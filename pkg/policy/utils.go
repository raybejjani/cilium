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
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// JoinPath returns a joined path from a and b.
func JoinPath(a, b string) string {
	return a + common.PathDelimiter + b
}

// extractPolicyName returns the policy names for the rule object passed in.
// It will use the k8s name if available, the description, and then the fallback
// if no other name is found
func extractPolicyName(rule api.Rule, fallback string) string {
	k8sPolicyNameKey := "io.cilium.k8s-policy-name"
	srcName := rule.Labels.Get(labels.GetExtendedKeyFrom(k8sPolicyNameKey))
	if srcName == "" {
		srcName = rule.Description
	}
	if srcName == "" {
		srcName = fallback
	}
	return srcName
}
