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

package services

import (
	"bufio"
	"encoding/json"
	"strings"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
)

// The traffic log has no LLM or MCP fields of its own: model, token usage and
// the MCP method and tool are read from the request and response bodies, when
// the gateway captured them. Only the fields below are read; nothing else in a
// body reaches the trail (the opt-in excerpts are separate).

// trafficBodyFields is what was read from one request's bodies.
type trafficBodyFields struct {
	requestModel, responseModel            string
	inputTokens, outputTokens, totalTokens int64
	hasInput, hasOutput, hasTotal          bool
	hasUsage                               bool

	mcpMethod, toolName, promptName, resourceURI string
	mcpError                                     bool

	derived bool
}

func (f trafficBodyFields) options() []audit.Option {
	var opts []audit.Option
	str := func(key, v string) {
		if v != "" {
			opts = append(opts, audit.Detail(key, v))
		}
	}
	str("requestModel", f.requestModel)
	str("responseModel", f.responseModel)
	if f.hasUsage {
		opts = append(opts,
			audit.Detail("inputTokens", f.inputTokens),
			audit.Detail("outputTokens", f.outputTokens),
			audit.Detail("totalTokens", f.totalTokens),
		)
	}
	str("mcpMethod", f.mcpMethod)
	str("toolName", f.toolName)
	str("promptName", f.promptName)
	str("resourceUri", f.resourceURI)
	if f.mcpError {
		opts = append(opts, audit.Detail("mcpError", true))
	}
	if f.derived {
		opts = append(opts, audit.Detail("derivedFromBody", true))
	}
	return opts
}

// extractTrafficBodyFields reads the LLM fields of an LLM API's bodies, or the
// JSON-RPC fields of an MCP API's. A body that is absent, truncated or not the
// expected shape yields nothing, never an error: the record is kept without it.
func extractTrafficBodyFields(apiKind, requestBody, responseBody string) trafficBodyFields {
	var f trafficBodyFields
	switch strings.ToLower(apiKind) {
	case "llmproxy", "llmprovider":
		readLLMRequest(&f, requestBody)
		for _, msg := range jsonMessages(responseBody) {
			readLLMResponse(&f, msg)
		}
		f.finishLLMUsage()
	case "mcp":
		readMCPRequest(&f, requestBody)
		for _, msg := range jsonMessages(responseBody) {
			for _, reply := range jsonRPCReplies(msg) {
				readMCPResponse(&f, reply)
			}
		}
	}
	f.derived = f.requestModel != "" || f.responseModel != "" || f.hasUsage || f.mcpMethod != ""
	return f
}

// jsonMessages returns the JSON objects of a body: the body itself, or, for a
// server-sent-events stream (a streamed completion, an MCP Streamable HTTP
// reply), the payload of each "data:" line.
func jsonMessages(body string) []json.RawMessage {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if json.Valid([]byte(trimmed)) {
			return []json.RawMessage{json.RawMessage(trimmed)}
		}
		return nil
	}
	// Server-sent events: an event's data is its "data:" lines joined by
	// newlines, and a blank line ends the event.
	var out []json.RawMessage
	var data []string
	flush := func() {
		payload := strings.TrimSpace(strings.Join(data, "\n"))
		data = data[:0]
		if payload == "" || payload == "[DONE]" || !json.Valid([]byte(payload)) {
			return
		}
		out = append(out, json.RawMessage(payload))
	}
	sc := bufio.NewScanner(strings.NewReader(trimmed))
	sc.Buffer(make([]byte, 0, 64*1024), len(trimmed)+1)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			flush()
			continue
		}
		if value, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(value, " "))
		}
	}
	flush()
	return out
}

func readLLMRequest(f *trafficBodyFields, body string) {
	var req struct {
		Model string `json:"model"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &req) == nil {
		f.requestModel = req.Model
	}
}

// llmUsage is a usage object in any of the shapes providers send: OpenAI chat
// (prompt_tokens, completion_tokens), Anthropic and the OpenAI Responses API
// (input_tokens, output_tokens).
type llmUsage struct {
	PromptTokens     *int64 `json:"prompt_tokens"`
	CompletionTokens *int64 `json:"completion_tokens"`
	TotalTokens      *int64 `json:"total_tokens"`
	InputTokens      *int64 `json:"input_tokens"`
	OutputTokens     *int64 `json:"output_tokens"`
}

// llmMessage is one response body or stream event. Besides the plain shape,
// usage and model can sit one level down: in Anthropic's message_start event
// ("message") and in the OpenAI Responses API's response.completed ("response").
type llmMessage struct {
	Model    string    `json:"model"`
	Usage    *llmUsage `json:"usage"`
	Message  *llmInner `json:"message"`
	Response *llmInner `json:"response"`
}

type llmInner struct {
	Model string    `json:"model"`
	Usage *llmUsage `json:"usage"`
}

// readLLMResponse reads one response message. A stream spreads the usage over
// several events — Anthropic sends input tokens at the start and output tokens
// at the end — so each value is kept once seen and only replaced by a later
// event that carries it. The total is settled by finishLLMUsage.
func readLLMResponse(f *trafficBodyFields, msg json.RawMessage) {
	var resp llmMessage
	if json.Unmarshal(msg, &resp) != nil {
		return
	}
	for _, inner := range []*llmInner{resp.Message, resp.Response} {
		if inner == nil {
			continue
		}
		if inner.Model != "" {
			f.responseModel = inner.Model
		}
		f.addUsage(inner.Usage)
	}
	if resp.Model != "" {
		f.responseModel = resp.Model
	}
	f.addUsage(resp.Usage)
}

func (f *trafficBodyFields) addUsage(u *llmUsage) {
	if u == nil {
		return
	}
	if in := first(u.PromptTokens, u.InputTokens); in != nil {
		f.inputTokens, f.hasInput = *in, true
	}
	if out := first(u.CompletionTokens, u.OutputTokens); out != nil {
		f.outputTokens, f.hasOutput = *out, true
	}
	if u.TotalTokens != nil {
		f.totalTokens, f.hasTotal = *u.TotalTokens, true
	}
}

// finishLLMUsage settles the usage once every message is read: a provider that
// reports no total gets the sum of what it did report.
func (f *trafficBodyFields) finishLLMUsage() {
	f.hasUsage = f.hasInput || f.hasOutput || f.hasTotal
	if f.hasUsage && !f.hasTotal {
		f.totalTokens = f.inputTokens + f.outputTokens
	}
}

func first(values ...*int64) *int64 {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

// jsonRPCRequest is an MCP request; a batch is read by its first call.
type jsonRPCRequest struct {
	Method string `json:"method"`
	Params *struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	} `json:"params"`
}

func readMCPRequest(f *trafficBodyFields, body string) {
	trimmed := strings.TrimSpace(body)
	var req jsonRPCRequest
	if strings.HasPrefix(trimmed, "[") {
		var batch []jsonRPCRequest
		if json.Unmarshal([]byte(trimmed), &batch) != nil || len(batch) == 0 {
			return
		}
		req = batch[0]
	} else if json.Unmarshal([]byte(trimmed), &req) != nil {
		return
	}
	f.mcpMethod = req.Method
	if req.Params == nil {
		return
	}
	switch req.Method {
	case "tools/call":
		f.toolName = req.Params.Name
	case "prompts/get":
		f.promptName = req.Params.Name
	case "resources/read":
		f.resourceURI = req.Params.URI
	}
}

// jsonRPCReplies splits a JSON-RPC batch reply (an array) into its replies.
func jsonRPCReplies(msg json.RawMessage) []json.RawMessage {
	trimmed := strings.TrimSpace(string(msg))
	if !strings.HasPrefix(trimmed, "[") {
		return []json.RawMessage{msg}
	}
	var batch []json.RawMessage
	if json.Unmarshal(msg, &batch) != nil {
		return nil
	}
	return batch
}

// readMCPResponse marks a JSON-RPC error, or a tool result the server flagged
// as an error (result.isError), which an HTTP 200 does not show.
func readMCPResponse(f *trafficBodyFields, msg json.RawMessage) {
	var resp struct {
		Error  json.RawMessage `json:"error"`
		Result *struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if json.Unmarshal(msg, &resp) != nil {
		return
	}
	if (len(resp.Error) > 0 && string(resp.Error) != "null") || (resp.Result != nil && resp.Result.IsError) {
		f.mcpError = true
	}
}
