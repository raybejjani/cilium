// Copyright 2019 Authors of Cilium
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

package cmd

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	toFQDNsPreCachePathOption = "tofqdns-pre-cache"
	toFQDNsPreCacheTTLOption  = "tofqdns-pre-cache-ttl"
)

var (
	toFQDNsPreCachePath string
	toFQDNsPreCacheTTL  int
)

// preflightCmd is the command used to manage preflight tasks for upgrades
var preflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "cilium upgrade helper",
	Long:  `CLI to help upgrade cilium`,
}

// pollerC, is the command used to upgrade a fqdn poller
var pollerCmd = &cobra.Command{
	Use:   "fqdn-poller",
	Short: "Prepare for upgrades to cilium 1.4",
	Long:  "Prepare for upgrades to cilium 1.4",
	Run: func(cmd *cobra.Command, args []string) {
		preflightPoller()
	},
}

func init() {
	pollerCmd.Flags().StringVar(&toFQDNsPreCachePath, toFQDNsPreCachePathOption, "", "The path to write serialized ToFQDNs pre-cache information. stdout is the default")
	pollerCmd.Flags().IntVar(&toFQDNsPreCacheTTL, toFQDNsPreCacheTTLOption, 604800, "TTL, in seconds, to set on generated ToFQDNs pre-cache information")
	preflightCmd.AddCommand(pollerCmd)
	rootCmd.AddCommand(preflightCmd)
}

func preflightPoller() {
	lookupTime := time.Now()

	// Get data from the local cilium-agent
	DNSData, err := getDNSMappings()
	if err != nil {
		Fatalf("Cannot extract DNS data from local cilium-agent: %s", err)
	}
	logrus.WithError(err).WithField("DNSData", DNSData).Debug("")

	// Build a cache from this data to be serialized
	cache := fqdn.NewDNSCache()
	for name, IPs := range DNSData {
		cache.Update(lookupTime, name, IPs, toFQDNsPreCacheTTL)
	}
	logrus.WithError(err).WithField("cache", cache).Debug("")

	// Marshal into a writeable format
	serialized, err := json.Marshal(cache)
	if err != nil {
		Fatalf("Cannot create DNS pre-cache data from policy DNS data: %s", err)
	}

	var outWriter io.WriteCloser = os.Stdout
	if toFQDNsPreCachePath != "" {
		outWriter, err = os.OpenFile(toFQDNsPreCachePath, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			Fatalf("Cannot open target destination for DNS pre-cache data: %s", err)
		}
	}
	defer outWriter.Close()
	if _, err = outWriter.Write(serialized); err != nil {
		Fatalf("Error writing data: %s", err)
	}
}

func getDNSMappings() (DNSData map[string][]net.IP, err error) {
	policy, err := client.PolicyGet(nil)
	if err != nil {
		return nil, err
	}

	var rules policyAPI.Rules
	if err := json.Unmarshal([]byte(policy.Policy), &rules); err != nil {
		return nil, err
	}

	// for each egressrule, when ToFQDNs.matchName is filled in, use the IPs we
	// inserted into that rule as IPs for that DNS name (this may be shared by many
	// DNS names). We ensure that we only read /32 CIDRs, since we only ever insert
	// those.
	DNSData = make(map[string][]net.IP)
	for _, rule := range rules {
		for _, egressRule := range rule.Egress {
			for _, ToFQDN := range egressRule.ToFQDNs {
				for _, cidr := range egressRule.ToCIDRSet {
					if ToFQDN.MatchName != "" && cidr.Cidr != "" {
						ip, ipnet, err := net.ParseCIDR(string(cidr.Cidr))
						if err != nil {
							return nil, err
						}
						if ones, _ := ipnet.Mask.Size(); ones == 32 {
							name := matchpattern.Sanitize(ToFQDN.MatchName)
							DNSData[name] = append(name, ip)
						}
					}
				}
			}
		}
	}

	return DNSData, nil
}
