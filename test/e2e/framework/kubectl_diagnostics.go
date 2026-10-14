// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package framework

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// kubectlTimeout caps each diagnostic kubectl call so it can never hang a spec.
const kubectlTimeout = 30 * time.Second

// Kubectl runs kubectl and returns its output. It never fails the spec: if
// kubectl is missing or the call fails, the returned text says so.
func Kubectl(args ...string) string {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return "kubectl not on PATH; cluster state not captured"
	}
	ctx, cancel := context.WithTimeout(context.Background(), kubectlTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "kubectl", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		text += fmt.Sprintf("\n(kubectl %s: %v)", strings.Join(args, " "), err)
	}
	return text
}

// AttachNamespaceStateOnFailure adds pods, jobs, Warning events and the
// describe output of non-Running pods to the Ginkgo report, only if the spec
// fails, for every namespace that starts with prefix and contains all of the
// given substrings. The test cannot name these namespaces exactly (e.g.
// "dp-<org>-<project>-<env>-<hash>", "workflows-<env>"), hence the matching.
func AttachNamespaceStateOnFailure(label, prefix string, contains ...string) {
	AttachOnFailure(label, func() string {
		return NamespaceState(prefix, contains...)
	})
}

// NamespaceState builds the text AttachNamespaceStateOnFailure attaches.
// Output is capped so a large cluster cannot flood the report.
func NamespaceState(prefix string, contains ...string) string {
	const (
		maxNamespaces = 6
		describeLimit = 80
		eventLimit    = 30
	)

	var namespaces []string
	for _, line := range strings.Split(Kubectl("get", "ns", "-o", "name"), "\n") {
		ns := strings.TrimPrefix(strings.TrimSpace(line), "namespace/")
		if ns == "" || !strings.HasPrefix(ns, prefix) {
			continue
		}
		matched := true
		for _, want := range contains {
			if !strings.Contains(ns, want) {
				matched = false
				break
			}
		}
		if matched {
			namespaces = append(namespaces, ns)
		}
	}
	if len(namespaces) == 0 {
		return fmt.Sprintf("no namespace matched prefix %q containing %v", prefix, contains)
	}
	if len(namespaces) > maxNamespaces {
		namespaces = namespaces[:maxNamespaces]
	}

	var b strings.Builder
	for _, ns := range namespaces {
		fmt.Fprintf(&b, "===== namespace %s =====\n", ns)
		fmt.Fprintf(&b, "--- pods\n%s\n", Kubectl("get", "pods", "-n", ns, "-o", "wide"))
		fmt.Fprintf(&b, "--- jobs\n%s\n", Kubectl("get", "jobs", "-n", ns))
		events := strings.Split(Kubectl("get", "events", "-n", ns, "--field-selector", "type=Warning", "--sort-by=.lastTimestamp"), "\n")
		if len(events) > eventLimit {
			events = events[len(events)-eventLimit:]
		}
		fmt.Fprintf(&b, "--- warning events (last %d)\n%s\n", eventLimit, strings.Join(events, "\n"))

		for _, line := range strings.Split(Kubectl("get", "pods", "-n", ns, "--no-headers"), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[2] == "Running" || fields[2] == "Completed" {
				continue
			}
			describe := Kubectl("describe", "pod", fields[0], "-n", ns)
			if idx := strings.Index(describe, "Conditions:"); idx >= 0 {
				describe = describe[idx:]
			}
			lines := strings.Split(describe, "\n")
			if len(lines) > describeLimit {
				lines = lines[:describeLimit]
			}
			fmt.Fprintf(&b, "--- describe pod/%s (status %s)\n%s\n", fields[0], fields[2], strings.Join(lines, "\n"))
		}
	}
	return b.String()
}
