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

package api

import (
	"fmt"
	"regexp"

	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
)

var (
	// allowedMatchNameChars tests that MatchName contains only valid DNS characters
	allowedMatchNameChars = regexp.MustCompile("^[-a-zA-Z0-9.]+$")

	// allowedPatternChars tests that the MatchPattern field contains only the
	// characters we want in our wilcard scheme.
	allowedPatternChars = regexp.MustCompile("^[-a-zA-Z0-9.*]+$") // the * inside the [] is a literal *
)

type FQDNSelector struct {
	// MatchName matches literal DNS names. A trailing "." is automatically added
	// when missing.
	MatchName string `json:"matchName,omitempty"`

	// MatchPattern allows using wildcards to match DNS names. All wildcards are
	// case insensitive. The wildcards are:
	// - "*" matches 0 or more DNS valid characters, and may occur anywhere in
	// the pattern. As a special case a "*" as the leftmost character, without a
	// following "." matches all subdomains as well as the name to the right.
	// A trailing "." is automatically added when missing
	//
	// Examples:
	// *.cilium.io matches subomains of cilium at that level
	// *cilium.io matches cilium.io and all subdomains 1 level below
	// sub*.cilium.io matches subdomains of cilium where the subdomain component
	// begins with "sub"
	MatchPattern string `json:"matchPattern,omitempty"`
}

// sanitize for FQDNSelector is a little wonky. While we do more processing
// when using MatchName the basic requirement is that is a valid regexp. We
// test that it can compile here.
func (s *FQDNSelector) sanitize() error {
	if len(s.MatchName) > 0 && !allowedMatchNameChars.MatchString(s.MatchName) {
		return fmt.Errorf("Invalid characters in MatchName: \"%s\". Only 0-9, a-z, A-Z and . and - characters are allowed", s.MatchName)
	}

	if len(s.MatchPattern) > 0 && !allowedPatternChars.MatchString(s.MatchPattern) {
		return fmt.Errorf("Invalid characters in MatchPattern: \"%s\". Only 0-9, a-z, A-Z and ., - and * characters are allowed", s.MatchPattern)
	}
	return matchpattern.Validate(s.MatchPattern)
}

// PortRuleDNS is a list of allowed DNS lookups.
type PortRuleDNS FQDNSelector

// Sanitize checks that the matchName in the portRule can be compiled as a
// regex. It does not check that a DNS name is a valid DNS name.
func (kr *PortRuleDNS) Sanitize() error {
	return nil
}
