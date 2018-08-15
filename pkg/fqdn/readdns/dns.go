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
package readdns

import (
	"bytes"
	"encoding/gob"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ReadDNS(data []byte) {
	dissect, decoded, err := GetDissect(data)
	switch {
	case err != nil &&
		!strings.Contains(err.Error(), "No decoder for layer type") &&
		!strings.Contains(err.Error(), "slice bounds out of range") &&
		!strings.Contains(err.Error(), "index out of range"):
		//fmt.Printf("Error decoding DNS: %s\n", err.Error())
		fallthrough
	case err != nil:
		return
	case dissect == nil, dissect.DNS.QDCount == 0:
		//fmt.Printf("DNS no dissect %v\n", dissect)
		return
	}

	_ = decoded
	//fmt.Printf("DNS Dissect decoded %v\n", decoded)
	//fmt.Printf("DNS Dissect summary %v\n", GetDissectSummary(data))

	dns := &dissect.DNS
	ips := make([]net.IP, 0)
	ttl := 0
	for i := range dns.Answers {
		if dns.Answers[i].Type != layers.DNSTypeA || dns.Answers[i].Type != layers.DNSTypeAAAA {
			ips = append(ips, dns.Answers[i].IP)
			ttl = int(dns.Answers[i].TTL)
		}
	}
	//fmt.Printf("Inserting %#v into DNS cache\n", dns)
	fqdn.DefaultDNSCache.Update(time.Now(), string(dns.Questions[0].Name), ips, ttl)
}

func ReplaceDNS(line string, ip net.IP) string {
	names := fqdn.DefaultDNSCache.LookupIP(ip)
	//fmt.Printf("DNS Found names for %s: %v\n", ip.String(), names)
	if len(names) > 0 {
		ipStr := ip.String()
		line = strings.Replace(line, ipStr, ipStr+"("+strings.Join(names, ",")+")", 1)
	}

	return line
}

// Dissect bundles decoded layers into objects
type Dissection struct {
	Ethernet layers.Ethernet `json:"ethernet,omitempty"`
	IPv4     layers.IPv4     `json:"ipv4,omitempty"`
	IPv6     layers.IPv6     `json:"ipv6,omitempty"`
	UDP      layers.UDP      `json:"udp,omitempty"`
	DNS      layers.DNS      `json:"dns,omitempty"`
}

// GetDissect returns DissectSummary created from data
func GetDissect(data []byte) (out *Dissection, decoded []gopacket.LayerType, err error) {
	decoded = []gopacket.LayerType{}
	dis := &Dissection{}

	fullParser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&dis.Ethernet,
		&dis.IPv4, &dis.IPv6,
		&dis.UDP,
		&dis.DNS)

	if err := fullParser.DecodeLayers(data, &decoded); err != nil {
		return nil, nil, err
	}

	return dis.Copy(), decoded, nil
}

// Copy is needed because layers manages to reuse the backing data, corrupting
// our packet
func (d *Dissection) Copy() *Dissection {
	buf := bytes.Buffer{}
	enc := gob.NewEncoder(&buf)
	enc.Encode(d)

	var ret *Dissection
	dec := gob.NewDecoder(&buf)
	dec.Decode(&ret)

	return ret
}
