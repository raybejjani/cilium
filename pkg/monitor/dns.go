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
package monitor

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/fqdn/cache"
)

func ReadDNS(data []byte) {
	dissect, decoded, err := GetDissect(data)
	switch {
	case err != nil && !strings.Contains(err.Error(), "No decoder for layer type"):
		fmt.Printf("Error decoding DNS: %s\n", err.Error())
		return
	case dissect == nil, dissect.DNS.QDCount == 0:
		//fmt.Printf("DNS no dissect %v\n", dissect)
		return
	}

	_ = decoded
	//fmt.Printf("DNS Dissect decoded %v\n", decoded)
	//fmt.Printf("DNS Dissect summary %v\n", GetDissectSummary(data))

	dns := &dissect.DNS
	//fmt.Printf("Inserting %#v into DNS cache\n", dns)
	cache.DefaultDNSCache.Update("monitor-cli", dns)
}

func ReplaceDNS(line string, ip net.IP) string {
	names, _ := cache.DefaultDNSCache.LookupIP(ip)
	//fmt.Printf("DNS Found names for %s: %v\n", ip.String(), names)
	if len(names) > 0 {
		ipStr := ip.String()
		line = strings.Replace(line, ipStr, ipStr+"("+strings.Join(names, ",")+")", 1)
	}

	return line
}
