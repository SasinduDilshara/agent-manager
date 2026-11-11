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

package bedrock

// A fake AWS endpoint that speaks the wire protocol each vendored SDK client
// uses (see evidence/impl_notes_bedrock.md):
//
//   - restJson1 (bedrock-agentcore-control, agent-registry-control,
//     bedrock-agent, bedrock): REST paths, JSON bodies, error code in the
//     X-Amzn-Errortype header.
//   - awsJson1_1 (logs, cloudtrail): POST /, X-Amz-Target, JSON bodies,
//     error code in __type.
//   - smithy-rpc-v2-cbor (cloudwatch): POST /service/<svc>/operation/<op>,
//     CBOR bodies, Smithy-Protocol: rpc-v2-cbor.
//   - awsQuery (sts): POST / form, XML response.
//
// Fixtures (testdata/), named <Operation>[_<id>][_page2].json, follow the
// official shapes in evidence/bedrock.md:
//
//   - ListAgentRuntimes*, GetAgentRuntime_*: §2.1 / §2.2 examples (API ref
//     Response Syntax, M:agentcore AgentRuntime / GetAgentRuntimeResponse).
//   - ListGateways*, GetGateway_*: §2.3 (GatewaySummary, GetGateway output).
//   - ListGatewayTargets_*: §2.4 (TargetSummary).
//   - ListRegistries*, ListRegistryRecords_*: §2.5 (agent-registry-control
//     RegistrySummary / RegistryRecordSummary; the record example).
//   - ListAgents*, GetAgent_*, ListAgentActionGroups_*: §2.6 / §2.7.
//   - GetModelInvocationLoggingConfiguration*: §2.8 (LoggingConfig).
//   - FilterLogEvents*: §2.9 official response, each message an official
//     "Log entry format" record with Converse / Anthropic Messages bodies.
//   - ListMetrics*, GetMetricData*: §2.10 official GetMetricData response
//     (JSON shape, converted to CBOR by cborFromJSON).
//   - LookupEvents*: §2.11 example; CloudTrailEvent follows the official
//     InvokeModel event.
//   - AssumeRole.xml: §4 official AssumeRole sample response.
//   - eu-west-1/*: the second region of the multi-region test.
//
// Fixtures carry retention markers (SECRET-PROMPT-MARKER, a fake key) in
// descriptions, instructions, environment variables, tool inputs, log
// bodies and URLs.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go/encoding/cbor"
)

const (
	markerPrompt = "SECRET-PROMPT-MARKER"
	markerKey    = "sk-test-SECRETSECRETSECRET"
	testSecret   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
	testKeyID    = "AKIDEXAMPLE"
)

type capturedReq struct {
	op      string
	region  string
	service string
	method  string
	path    string
	query   url.Values
	header  http.Header
	body    []byte
	at      time.Time
}

type fakeErr struct {
	status     int
	code       string
	retryAfter string
	// raw, when set, is sent as a 200 body as-is (malformed responses).
	raw string
}

type fakeAWS struct {
	t   *testing.T
	srv *httptest.Server

	mu   sync.Mutex
	reqs []capturedReq
	// errs are served (in order, one per request) before the fixtures.
	errs map[string][]fakeErr
	// variant selects an alternative fixture: <Op>_<variant>.json.
	variant map[string]string
	// forbidden ops fail the test when called.
	forbidden map[string]bool
}

func newFakeAWS(t *testing.T) *fakeAWS {
	t.Helper()
	f := &fakeAWS{t: t, errs: map[string][]fakeErr{}, variant: map[string]string{}, forbidden: map[string]bool{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAWS) failWith(op string, errs ...fakeErr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[op] = append(f.errs[op], errs...)
}

func (f *fakeAWS) requests(op string) []capturedReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []capturedReq
	for _, r := range f.reqs {
		if r.op == op {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeAWS) allOps() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.reqs {
		out = append(out, r.op)
	}
	return out
}

var (
	credRE    = regexp.MustCompile(`Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request`)
	runtimeRE = regexp.MustCompile(`^/runtimes/([^/]+)/$`)
	gwRE      = regexp.MustCompile(`^/gateways/([^/]+)/$`)
	targetsRE = regexp.MustCompile(`^/gateways/([^/]+)/targets/$`)
	recordsRE = regexp.MustCompile(`^/registries/([^/]+)/records-list$`)
	agentRE   = regexp.MustCompile(`^/agents/([^/]+)/$`)
	groupsRE  = regexp.MustCompile(`^/agents/([^/]+)/agentversions/([^/]+)/actiongroups/$`)
	cborOpRE  = regexp.MustCompile(`^/service/GraniteServiceVersion20100801/operation/([A-Za-z]+)$`)
)

// opService is the SigV4 signing name each operation must be signed with
// (evidence §2.0).
var opService = map[string]string{
	"ListAgentRuntimes": "bedrock-agentcore", "GetAgentRuntime": "bedrock-agentcore",
	"ListGateways": "bedrock-agentcore", "GetGateway": "bedrock-agentcore", "ListGatewayTargets": "bedrock-agentcore",
	"ListRegistries": "agent-registry", "ListRegistryRecords": "agent-registry",
	"ListAgents": "bedrock", "GetAgent": "bedrock", "ListAgentActionGroups": "bedrock",
	"GetModelInvocationLoggingConfiguration": "bedrock",
	"FilterLogEvents":                        "logs",
	"ListMetrics":                            "monitoring", "GetMetricData": "monitoring",
	"LookupEvents": "cloudtrail",
	"AssumeRole":   "sts",
}

// route identifies the operation (and the resource ID in its path).
func route(r *http.Request, body []byte) (op, id string) {
	p := r.URL.Path
	switch tgt := r.Header.Get("X-Amz-Target"); tgt {
	case "CloudTrail_20131101.LookupEvents", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents":
		return "LookupEvents", ""
	case "Logs_20140328.FilterLogEvents":
		return "FilterLogEvents", ""
	}
	if m := cborOpRE.FindStringSubmatch(p); m != nil {
		return m[1], ""
	}
	switch {
	case r.Method == http.MethodPost && p == "/" && strings.Contains(string(body), "Action=AssumeRole"):
		return "AssumeRole", ""
	case r.Method == http.MethodPost && p == "/runtimes/":
		return "ListAgentRuntimes", ""
	case r.Method == http.MethodGet && runtimeRE.MatchString(p):
		return "GetAgentRuntime", runtimeRE.FindStringSubmatch(p)[1]
	case r.Method == http.MethodGet && p == "/gateways/":
		return "ListGateways", ""
	case r.Method == http.MethodGet && targetsRE.MatchString(p):
		return "ListGatewayTargets", targetsRE.FindStringSubmatch(p)[1]
	case r.Method == http.MethodGet && gwRE.MatchString(p):
		return "GetGateway", gwRE.FindStringSubmatch(p)[1]
	case r.Method == http.MethodPost && p == "/registries-list":
		return "ListRegistries", ""
	case r.Method == http.MethodPost && recordsRE.MatchString(p):
		return "ListRegistryRecords", recordsRE.FindStringSubmatch(p)[1]
	case r.Method == http.MethodPost && p == "/agents/":
		return "ListAgents", ""
	case r.Method == http.MethodGet && agentRE.MatchString(p):
		return "GetAgent", agentRE.FindStringSubmatch(p)[1]
	case r.Method == http.MethodPost && groupsRE.MatchString(p):
		return "ListAgentActionGroups", groupsRE.FindStringSubmatch(p)[1]
	case r.Method == http.MethodGet && p == "/logging/modelinvocations":
		return "GetModelInvocationLoggingConfiguration", ""
	}
	return "", ""
}

type protocol int

const (
	protoRestJSON protocol = iota
	protoAWSJSON
	protoCBOR
	protoQuery
)

func protocolOf(op string) protocol {
	switch op {
	case "LookupEvents", "FilterLogEvents":
		return protoAWSJSON
	case "ListMetrics", "GetMetricData":
		return protoCBOR
	case "AssumeRole":
		return protoQuery
	}
	return protoRestJSON
}

// emptyList is the response of a list operation without a fixture.
var emptyList = map[string]string{
	"ListAgentRuntimes": `{"agentRuntimes":[]}`, "ListGateways": `{"items":[]}`, "ListGatewayTargets": `{"items":[]}`,
	"ListRegistries": `{"registries":[]}`, "ListRegistryRecords": `{"registryRecords":[]}`,
	"ListAgents": `{"agentSummaries":[]}`, "ListAgentActionGroups": `{"actionGroupSummaries":[]}`,
	"GetModelInvocationLoggingConfiguration": `{}`, "FilterLogEvents": `{"events":[]}`,
	"LookupEvents": `{"Events":[]}`, "ListMetrics": `{"Metrics":[]}`, "GetMetricData": `{"MetricDataResults":[]}`,
}

func (f *fakeAWS) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	op, id := route(r, body)
	region, service := "", ""
	if m := credRE.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		region, service = m[3], m[4]
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, capturedReq{
		op: op, region: region, service: service, method: r.Method, path: r.URL.Path, query: r.URL.Query(),
		header: r.Header.Clone(), body: body, at: time.Now(),
	})
	var injected *fakeErr
	if q := f.errs[op]; len(q) > 0 {
		injected = &q[0]
		f.errs[op] = q[1:]
	}
	forbidden := f.forbidden[op]
	variant := f.variant[op]
	f.mu.Unlock()

	if op == "" {
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.Error(w, "unknown operation", http.StatusNotFound)
		return
	}
	if forbidden {
		f.t.Errorf("%s must not be called", op)
	}
	if want := opService[op]; service != want {
		f.t.Errorf("%s signed for service %q, want %q", op, service, want)
	}
	proto := protocolOf(op)
	if injected != nil {
		if injected.raw != "" {
			writeBody(w, proto, []byte(injected.raw), false)
			return
		}
		writeError(w, proto, *injected)
		return
	}
	if op == "AssumeRole" {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(mustRead(f.t, "AssumeRole.xml"))
		return
	}
	page2 := hasNextToken(proto, r, body)
	name := op
	if id != "" {
		name += "_" + id
	}
	if variant != "" {
		name += "_" + variant
	}
	if page2 {
		name += "_page2"
	}
	data := fixture(region, name+".json")
	if data == nil {
		if e, ok := emptyList[op]; ok {
			data = []byte(e)
		} else {
			writeError(w, proto, fakeErr{status: http.StatusNotFound, code: "ResourceNotFoundException"})
			return
		}
	}
	writeBody(w, proto, data, true)
}

func fixture(region, name string) []byte {
	dir := "testdata"
	if region != "" && region != "us-east-1" {
		dir = filepath.Join(dir, region)
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil
	}
	return b
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

func hasNextToken(proto protocol, r *http.Request, body []byte) bool {
	if r.URL.Query().Get("nextToken") != "" {
		return true
	}
	switch proto {
	case protoCBOR:
		v, err := cbor.Decode(body)
		if err != nil {
			return false
		}
		m, _ := v.(cbor.Map)
		_, ok := m["NextToken"]
		return ok
	case protoRestJSON, protoAWSJSON:
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return false
		}
		return m["nextToken"] != nil || m["NextToken"] != nil
	}
	return false
}

func writeBody(w http.ResponseWriter, proto protocol, data []byte, convert bool) {
	switch proto {
	case protoAWSJSON:
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	case protoCBOR:
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Smithy-Protocol", "rpc-v2-cbor")
		if convert {
			data = cborFromJSON(data)
		}
	default:
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("X-Amzn-Requestid", "11111111-2222-3333-4444-555555555555")
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, proto protocol, e fakeErr) {
	if e.retryAfter != "" {
		w.Header().Set("Retry-After", e.retryAfter)
	}
	msg := "simulated " + e.code
	switch proto {
	case protoRestJSON:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Errortype", e.code)
		w.WriteHeader(e.status)
		_, _ = fmt.Fprintf(w, `{"message":%q}`, msg)
	case protoAWSJSON:
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(e.status)
		_, _ = fmt.Fprintf(w, `{"__type":%q,"message":%q}`, e.code, msg)
	case protoCBOR:
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Smithy-Protocol", "rpc-v2-cbor")
		w.Header().Set("X-Amzn-Query-Error", e.code+";Sender")
		w.WriteHeader(e.status)
		_, _ = w.Write(cbor.Encode(cbor.Map{"__type": cbor.String(e.code), "message": cbor.String(msg)}))
	case protoQuery:
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(e.status)
		_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error><RequestId>r1</RequestId></ErrorResponse>`, e.code, msg)
	}
}

// cborFromJSON converts a JSON fixture to the CBOR the rpcv2Cbor protocol
// sends: timestamps (members named Timestamps) as tag 1 epoch seconds,
// doubles (members named Values) as float64.
func cborFromJSON(data []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		panic(err)
	}
	return cbor.Encode(toCBOR(v, ""))
}

func toCBOR(v any, key string) cbor.Value {
	switch x := v.(type) {
	case map[string]any:
		m := cbor.Map{}
		for k, e := range x {
			m[k] = toCBOR(e, k)
		}
		return m
	case []any:
		l := cbor.List{}
		for _, e := range x {
			l = append(l, toCBOR(e, key))
		}
		return l
	case string:
		return cbor.String(x)
	case bool:
		return cbor.Bool(x)
	case json.Number:
		switch key {
		case "Timestamps":
			n, _ := x.Int64()
			return &cbor.Tag{ID: 1, Value: cbor.Uint(uint64(n))}
		case "Values":
			fl, _ := x.Float64()
			return cbor.Float64(fl)
		}
		if n, err := x.Int64(); err == nil {
			if n < 0 {
				return cbor.NegInt(uint64(-n - 1))
			}
			return cbor.Uint(uint64(n))
		}
		fl, _ := x.Float64()
		return cbor.Float64(fl)
	case nil:
		return &cbor.Nil{}
	}
	panic(fmt.Sprintf("unsupported JSON value %T", v))
}
