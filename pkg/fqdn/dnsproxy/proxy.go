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

package dnsproxy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/miekg/dns"
)

var (
	setupOnce    sync.Once
	log          = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdn/dnsproxy")
	allowed      = regexp.MustCompile("^")
	allowedNames = map[string]struct{}{}
	allowedLock  lock.Mutex

	DNSPoller *fqdn.DNSPoller
)

// StartDNSProxy starts the proxy used in DNS L7 redirects. Repeat calls are
// no-ops, and only the inital port value is used.
func StartDNSProxy(port uint16) error {
	if port == 0 {
		return errors.New("DNS proxy port not configured")
	}

	setupOnce.Do(func() {
		dns.HandleFunc(".", handleQuery)
		go serve("tcp", port)
		go serve("udp", port)
	})

	return nil
}

func AddAllowed(name string) {
	log.Infof("DNS Proxy: Adding %s to allowed", name)

	allowedLock.Lock()
	defer allowedLock.Unlock()

	allowedNames[name] = struct{}{}
	makeAllowedMatcher()
}

func RemoveAllowed(name string) {
	log.Infof("DNS Proxy: Removing %s from allowed", name)

	allowedLock.Lock()
	defer allowedLock.Unlock()

	delete(allowedNames, name)
	makeAllowedMatcher()
}

// allowedLock must be held
func makeAllowedMatcher() {
	var names []string
	for name := range allowedNames {
		names = append(names, name)
	}

	combined := strings.Join(names, "|")
	compiled, err := regexp.Compile(combined)
	if err != nil {
		log.WithError(err).Error("Error compiling regex %s", combined)
		return
	}
	allowed = compiled
}

func CheckAllowed(name string) bool {
	allowedLock.Lock()
	defer allowedLock.Unlock()

	return allowed.MatchString(name)
}

func handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	qname := dns.Fqdn(string(r.Question[0].Name))
	log.Infof("DNS Proxy: Handling query for %s from %s on %s", qname, w.RemoteAddr(), w.LocalAddr())

	now := time.Now()
	responses, errors := fqdn.DNSLookupDefaultResolver([]string{qname})
	for _, err := range errors {
		log.WithError(err).Errorf("cannot do lookup for %s", qname)
		return
	}
	for respName, response := range responses {
		if respName != qname {
			log.Warnf("Unexpected name in response %s, qname was %s", respName, qname)
			continue
		}
		for _, ip := range response.IPs {
			switch {
			case ip.To4() != nil && r.Question[0].Qtype == dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(response.TTL)},
					A:   ip,
				})
			case ip.To4() == nil && r.Question[0].Qtype == dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(response.TTL)},
					AAAA: ip,
				})
			}
		}

		log.Infof("DNS Proxy: Updating %s in cache from response to to query from %s", qname, w.RemoteAddr())
		fqdn.DefaultDNSCache.Update(now, respName, response.IPs, response.TTL)

		// This is racey, and should be fixed
		if DNSPoller != nil {
			DNSPoller.UpdateGenerateDNS(now, map[string]*fqdn.DNSIPRecords{
				respName: {TTL: response.TTL, IPs: response.IPs},
			})
		}
	}

	// This check is here, after the actual lookup, to allow populating the cache
	// with information even when it isn't used.
	if !CheckAllowed(qname) {
		log.Warnf("DNS Proxy: Rejecting query for %s from %s on %s (%v)", qname, w.RemoteAddr(), w.LocalAddr(), allowed)
		return
	}

	log.Infof("DNS Proxy: Responding to query for %s from %s on %s", qname, w.RemoteAddr(), w.LocalAddr())
	w.WriteMsg(m)
}

func serve(proto string, port uint16) {
	server := &dns.Server{Addr: fmt.Sprintf(":%d", port), Net: proto, TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.WithError(err).Errorf("Failed to setup the %s server on port %d", proto, port)
	}
}
