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

package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Batch endpoints whose files carry chat or Responses API bodies.
const (
	endpointChat      = "/v1/chat/completions"
	endpointResponses = "/v1/responses"
)

// toolCallOutputTypes are the Responses API output item types that are a
// tool call (OAS OutputItem; batch rule in the evidence).
var toolCallOutputTypes = map[string]bool{
	"function_call":         true,
	"web_search_call":       true,
	"file_search_call":      true,
	"computer_call":         true,
	"mcp_call":              true,
	"code_interpreter_call": true,
	"custom_tool_call":      true,
	"shell_call":            true,
	"local_shell_call":      true,
	"apply_patch_call":      true,
	"image_generation_call": true,
}

// deepInspect reads, per project key and only with deep inspection on,
// stored chat completions and batch files, in memory and bounded, keeping
// only counts.
func (s *scan) deepInspect(ctx context.Context) {
	if !s.conn.Config.DeepInspection {
		for _, c := range []string{callChatCompletions, callBatches, callFileContent} {
			s.calls.Skip(c, reasonDeepOff)
		}
		return
	}
	ids := s.scopedProjects()
	if len(ids) == 0 {
		for _, c := range []string{callChatCompletions, callBatches, callFileContent} {
			s.calls.Skip(c, reasonNoProjectKey)
		}
		return
	}
	filesRead := false
	for _, pid := range ids {
		if ctx.Err() != nil {
			break
		}
		api := s.projectAPI(pid)
		s.inspectCompletions(ctx, api, pid)
		if s.inspectBatches(ctx, api, pid) {
			filesRead = true
		}
	}
	if !filesRead {
		s.calls.Skip(callFileContent, "no chat or responses batch with files in the window")
	}
}

// inspectCompletions reads up to maxStoredCompletions stored chat
// completions of the window, newest first.
func (s *scan) inspectCompletions(ctx context.Context, api *sa.API, projectID string) {
	inspected, withTools := int64(0), int64(0)
	start := s.w.Start.Unix()
	_, err := listAll(ctx, api, s.base+"/chat/completions", url.Values{"order": []string{"desc"}}, nil,
		listPageSize, maxStoredCompletions/listPageSize+1, func(c storedCompletion) bool {
			if c.Created > 0 && c.Created < start {
				return false
			}
			inspected++
			if completionHasToolCall(c.Choices) {
				withTools++
			}
			return inspected < maxStoredCompletions
		})
	s.calls.Record(callChatCompletions, int(inspected), err)
	if withTools > 0 {
		s.attributeProject(projectID, sa.Signal{
			Code: sa.SigOpenAIToolCallCompletion, Source: callChatCompletions,
			Observed: map[string]any{"completionsWithToolCalls": withTools, "completionsInspected": inspected},
		})
	}
}

// completionHasToolCall is the stored-completion rule: a choice whose
// message has tool_calls, or the deprecated function_call, or whose
// finish_reason is tool_calls or function_call.
func completionHasToolCall(choices []chatChoice) bool {
	for _, ch := range choices {
		if ch.FinishReason == "tool_calls" || ch.FinishReason == "function_call" {
			return true
		}
		if ch.Message != nil && (len(ch.Message.ToolCalls) > 0 || ch.Message.FunctionCall != nil) {
			return true
		}
	}
	return false
}

// inspectBatches reads up to maxBatchesPerProject chat or responses batches
// created in the window and scans their output and input files. It reports
// whether any file was read.
func (s *scan) inspectBatches(ctx context.Context, api *sa.API, projectID string) bool {
	var picked []batch
	listed := 0
	start := s.w.Start.Unix()
	_, err := listAll(ctx, api, s.base+"/batches", nil, nil, listPageSize, maxBatchListPages, func(b batch) bool {
		listed++
		if b.CreatedAt < start || (b.Endpoint != endpointChat && b.Endpoint != endpointResponses) {
			return true
		}
		picked = append(picked, b)
		return len(picked) < maxBatchesPerProject
	})
	s.calls.Record(callBatches, listed, err)

	var callBatchesN, callLines, resultBatchesN, resultLines int64
	filesRead := false
	for _, b := range picked {
		if ctx.Err() != nil {
			break
		}
		if b.OutputFileID != "" {
			n := s.scanFile(ctx, api, b.OutputFileID, outputLineHasToolCall)
			filesRead = true
			if n > 0 {
				callBatchesN++
				callLines += n
			}
		}
		if b.InputFileID != "" {
			n := s.scanFile(ctx, api, b.InputFileID, inputLineHasToolResult)
			filesRead = true
			if n > 0 {
				resultBatchesN++
				resultLines += n
			}
		}
	}
	if callBatchesN > 0 {
		s.attributeProject(projectID, sa.Signal{
			Code: sa.SigOpenAIToolCallBatch, Source: callFileContent,
			Observed: map[string]any{"batches": callBatchesN, "linesWithToolCalls": callLines},
		})
	}
	if resultBatchesN > 0 {
		s.attributeProject(projectID, sa.Signal{
			Code: sa.SigOpenAIToolResultBatch, Source: callFileContent,
			Observed: map[string]any{"batches": resultBatchesN, "linesWithToolResults": resultLines},
		})
	}
	return filesRead
}

// scanFile reads a JSONL file in memory (bounded by maxFileBytes) and
// returns how many lines match.
func (s *scan) scanFile(ctx context.Context, api *sa.API, fileID string, match func([]byte) bool) int64 {
	var lines, hits int64
	err := api.EachLine(ctx, sa.Request{Method: http.MethodGet, URL: s.base + "/files/" + url.PathEscape(fileID) + "/content"},
		maxFileBytes, func(line []byte) bool {
			lines++
			if match(line) {
				hits++
			}
			return true
		})
	s.calls.Record(callFileContent, int(lines), err)
	return hits
}

// outputLineHasToolCall applies the tool-call rule to one output line:
// a chat body as for stored completions, or a Responses body with an output
// item of a tool call type.
func outputLineHasToolCall(line []byte) bool {
	var l batchOutputLine
	if json.Unmarshal(line, &l) != nil || l.Response == nil || l.Response.Body == nil {
		return false
	}
	if completionHasToolCall(l.Response.Body.Choices) {
		return true
	}
	for _, o := range l.Response.Body.Output {
		if toolCallOutputTypes[o.Type] {
			return true
		}
	}
	return false
}

// inputLineHasToolResult applies the tool-result rule to one input line: a
// Responses input item of type function_call_output, or a chat message with
// role tool (or the deprecated function).
func inputLineHasToolResult(line []byte) bool {
	var l batchInputLine
	if json.Unmarshal(line, &l) != nil || l.Body == nil {
		return false
	}
	for _, m := range l.Body.Messages {
		if m.Role == "tool" || m.Role == "function" {
			return true
		}
	}
	var items []inputItem
	if len(l.Body.Input) > 0 && json.Unmarshal(l.Body.Input, &items) == nil {
		for _, it := range items {
			if it.Type == "function_call_output" {
				return true
			}
		}
	}
	return false
}
