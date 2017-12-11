// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	"fmt"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
)

// JoinPath returns a joined path from a and b.
func JoinPath(a, b string) string {
	return a + common.PathDelimiter + b
}

// extractPolicyNames returns a slice of policy names for the rule objects
// passed in. It will use the k8s name if available, the description, and then
// generate "policy#" if no other name is found
func extractPolicyNames(sourcePolicies []*rule) []string {
	k8sPolicyNameKey := "io.cilium.k8s-policy-name"
	sourceNames := make([]string, 0, len(sourcePolicies))
	for i, v := range sourcePolicies {
		srcName := v.Rule.Labels.Get(labels.GetExtendedKeyFrom(k8sPolicyNameKey))
		if srcName == "" {
			srcName = v.Description
		}
		if srcName == "" {
			srcName = fmt.Sprintf("policy%d", i)
		}
		sourceNames = append(sourceNames, srcName)
	}

	return sourceNames
}
