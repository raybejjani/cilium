// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"net"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/google/gopacket/layers"
	"github.com/pborman/uuid"
)

var DefaultDNSCache = NewDNSCache()

type dnsResponses map[string]*DNSCacheEntry

type DNSCacheEntry struct {
	uuid string

	Scope          string // what did the lookup? endpointID, agent, ?
	LookupTime     time.Time
	ExpirationTime time.Time
	DNSResponse    *layers.DNS // FIXME: use layers.DNSResourceRecord? allows mixing IP4/6
}

type DNSCache struct {
	lock.RWMutex

	forward map[string]dnsResponses
	back    map[string]dnsResponses

	cacheFilter func(*DNSCacheEntry) bool
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		forward:     make(map[string]dnsResponses),
		back:        make(map[string]dnsResponses),
		cacheFilter: func(*DNSCacheEntry) bool { return true },
	}
}

func (c *DNSCache) Update(scope string, response *layers.DNS) (entry *DNSCacheEntry, replaced bool) {
	now := time.Now()
	entry = &DNSCacheEntry{
		uuid:           uuid.NewUUID().String(),
		Scope:          scope,
		LookupTime:     now,
		ExpirationTime: getExpirationTime(response, now),
		DNSResponse:    response,
	}

	c.Lock()
	defer c.Unlock()
	return entry, c.updateForward(entry) || c.updateBack(entry)
}

func (c *DNSCache) LookupIP(ip net.IP) (names []string, entries []*DNSCacheEntry) {
	// find ip entry in back
	// return name & entries that match cache filter

	ipKey := ip.String()

	c.RLock()
	defer c.RUnlock()

	cacheEntries, found := c.back[ipKey]
	if !found {
		return nil, nil
	}

	nameSet := make(map[string]struct{})
	for _, entry := range cacheEntries {
		if !c.cacheFilter(entry) {
			continue
		}
		nameSet[getDNSQName(entry.DNSResponse)] = struct{}{}
		entries = append(entries, entry)
	}

	for name := range nameSet {
		names = append(names, name)
	}

	return names, entries
}

func (c *DNSCache) LookupName(name string) (ips []net.IP, entries []*DNSCacheEntry) {
	// find name in forward
	// return all IPs and entries that match cache filter
	c.RLock()
	defer c.RUnlock()

	cacheEntries, found := c.forward[name]
	if !found {
		return nil, nil
	}
	ipSet := map[string]net.IP{}
	for _, entry := range cacheEntries {
		if !c.cacheFilter(entry) {
			continue
		}
		for i := range entry.DNSResponse.Answers {
			rr := &entry.DNSResponse.Answers[i]
			ipSet[rr.IP.String()] = rr.IP
		}
		entries = append(entries, entry)
	}

	for _, ip := range ipSet {
		ips = append(ips, ip)
	}

	return ips, entries

}

func (c *DNSCache) GetNames() (names []string) {
	c.RLock()
	defer c.RUnlock()

perName:
	for name, cacheEntries := range c.forward {
		for _, entry := range cacheEntries {
			if !c.cacheFilter(entry) {
				continue perName
			}
			names = append(names, name)
		}
	}
	return names
}

func (c *DNSCache) GetIPs() (ips map[string][]net.IP) {
	c.RLock()
	defer c.RUnlock()

	ips = make(map[string][]net.IP, len(c.forward))
	for name, cacheEntries := range c.forward {
		ipSet := map[string]net.IP{}
		for _, entry := range cacheEntries {
			if !c.cacheFilter(entry) {
				continue
			}
			for i := range entry.DNSResponse.Answers {
				rr := &entry.DNSResponse.Answers[i]
				ipSet[rr.IP.String()] = rr.IP
			}
		}

		for _, ip := range ipSet {
			ips[name] = append(ips[name], ip)
		}
	}

	return ips
}

func (c *DNSCache) updateForward(entry *DNSCacheEntry) (replaced bool) {
	// find the response set by name
	// find the entry by uuid as replaced
	// replace the entry by uuid

	dnsName := getDNSQName(entry.DNSResponse)
	responseSet, found := c.forward[dnsName]
	if !found {
		responseSet = make(dnsResponses)
		c.forward[dnsName] = responseSet
	}

	_, replaced = responseSet[entry.uuid]
	responseSet[entry.uuid] = entry

	return replaced
}

func (c *DNSCache) updateBack(entry *DNSCacheEntry) (replaced bool) {
	// for each IP in the answer
	//   find the responseSet by IP
	//   add this response

	answers := entry.DNSResponse.Answers // this is a slice, so still by reference
	for i := range answers {
		if answers[i].Type != layers.DNSTypeA || answers[i].IP == nil {
			continue // TODO: handle CNAMEs and other things
		}

		ip := answers[i].IP.String()
		responseSet, found := c.back[ip]
		if !found {
			responseSet = make(dnsResponses)
			c.back[ip] = responseSet
		}

		_, exists := responseSet[entry.uuid]
		replaced = replaced || exists
		responseSet[entry.uuid] = entry
	}

	return replaced
}

func getDNSQName(response *layers.DNS) string {
	return string(response.Questions[0].Name)
}

func getExpirationTime(response *layers.DNS, now time.Time) (expire time.Time) {
	// Figure out error handling
	expire = now
	if len(response.Answers) != 0 {
		expire = now.Add(time.Duration(response.Answers[0].TTL) * time.Second)
	}

	return expire
}

// FIXME ACCOUNT FOR IPv6
func CreateDNSIPResponse(name string, ips []net.IP, TTL int) (response *layers.DNS) {
	response = &layers.DNS{
		QR:           true,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
		QDCount:      1,
		Questions: []layers.DNSQuestion{{
			Name:  []byte(name),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
		ANCount: uint16(len(ips)),
	}
	for _, ip := range ips {
		response.Answers = append(response.Answers,
			layers.DNSResourceRecord{
				Name:  []byte(name),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    ip,
			})
	}

	return response
}
