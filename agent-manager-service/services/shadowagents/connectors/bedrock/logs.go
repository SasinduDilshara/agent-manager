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

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsbedrock "github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// scanInvocationLogs reads the region's model invocation logging
// configuration (evidence §2.8) and, with deep inspection on and a
// CloudWatch Logs destination, reads the invocation log records in memory
// (§2.9) to derive tool-use flags. Nothing of a record is kept but the
// principal, the model and two booleans.
func (s *scan) scanInvocationLogs(ctx context.Context, rc *regionClients) {
	out, err := rc.bedrock.GetModelInvocationLoggingConfiguration(ctx, &awsbedrock.GetModelInvocationLoggingConfigurationInput{})
	if err != nil {
		s.calls.Record(callLoggingConfig, 0, awsError(err))
		s.skipLater(callFilterLogs, "the model invocation logging configuration could not be read")
		return
	}
	lc := out.LoggingConfig
	logGroup := ""
	toS3 := false
	if lc != nil {
		if lc.CloudWatchConfig != nil {
			logGroup = str(lc.CloudWatchConfig.LogGroupName)
		}
		toS3 = lc.S3Config != nil && str(lc.S3Config.BucketName) != ""
	}
	items := 0
	if logGroup != "" || toS3 {
		items = 1
	}
	s.calls.Record(callLoggingConfig, items, nil)
	for _, f := range s.regionRuntimes[rc.region] {
		f.Attributes["invocationLogging"] = logGroup != "" || toS3
	}
	switch {
	case logGroup == "" && !toS3:
		// No logging config: the GetModelInvocationLoggingConfiguration
		// response has no loggingConfig (evidence §2.8, UNVERIFIED exact body).
		s.logsOff[rc.region] = true
		s.skipLater(callFilterLogs, "model invocation logging is off")
	case logGroup == "":
		s.skipLater(callFilterLogs, "invocation logs are delivered to S3 only")
	case !s.conn.Config.DeepInspection:
		s.skipLater(callFilterLogs, "deep inspection is off")
	default:
		s.readInvocationLogs(ctx, rc, logGroup)
	}
}

type logFlags struct{ toolUse, toolResult int64 }

// readInvocationLogs reads at most maxLogEvents records (and maxLogBytes of
// them) of the window from the log group.
func (s *scan) readInvocationLogs(ctx context.Context, rc *regionClients, logGroup string) {
	p := cloudwatchlogs.NewFilterLogEventsPaginator(rc.logs, &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroup),
		StartTime:    aws.Int64(s.w.Start.UnixMilli()),
		EndTime:      aws.Int64(s.w.End.UnixMilli()),
		Limit:        aws.Int32(logPageSize),
		// Every other field is left unset; unmask stays false (it needs
		// logs:Unmask and would reveal masked data).
		FilterPattern: nil, LogGroupIdentifier: nil, LogStreamNamePrefix: nil,
		LogStreamNames: nil, NextToken: nil, StartFromHead: nil, Unmask: false,
	})
	events, size, bad := 0, 0, 0
	full := false
	flags := map[*sa.Finding]*logFlags{}
	n, err := paginate(ctx, maxPages, func() bool { return !full && p.HasMorePages() }, func(ctx context.Context) (int, error) {
		out, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, e := range out.Events {
			if events >= maxLogEvents || size >= maxLogBytes {
				full = true
				break
			}
			msg := str(e.Message)
			events++
			size += len(msg)
			rec, ok := parseInvocationRecord(msg)
			if !ok {
				bad++
				continue
			}
			if rec.identity == "" || (!rec.toolUse && !rec.toolResult) {
				continue
			}
			f := s.trafficTarget(rc.region, rec.identity, "")
			fl := flags[f]
			if fl == nil {
				fl = &logFlags{}
				flags[f] = fl
			}
			if rec.toolUse {
				fl.toolUse++
			}
			if rec.toolResult {
				fl.toolResult++
			}
			addModel(f, rec.model)
			if !rec.at.IsZero() {
				f.ObserveUse(rec.at)
			}
		}
		return len(out.Events), nil
	})
	if full && err == nil {
		err = &sa.CallError{Outcome: models.ShadowCallOK, Message: "stopped at the read bound; results are partial"}
	}
	s.calls.Record(callFilterLogs, n, err)
	for f, fl := range flags {
		f.Attributes["deepInspection"] = true
		if fl.toolUse > 0 {
			f.AddSignal(sa.Signal{Code: sa.SigBedrockToolCallLog, Source: callFilterLogs, Observed: map[string]any{"records": fl.toolUse}})
		}
		if fl.toolResult > 0 {
			f.AddSignal(sa.Signal{Code: sa.SigBedrockToolResultLog, Source: callFilterLogs, Observed: map[string]any{"records": fl.toolResult}})
		}
	}
	s.log.Debug("Shadow agent discovery Bedrock invocation logs read", "region", rc.region, "records", events, "unparsed", bad, "findings", len(flags))
}

// invocationRecord is what is kept of one invocation log record.
type invocationRecord struct {
	identity   string
	model      string
	at         time.Time
	toolUse    bool
	toolResult bool
}

// parseInvocationRecord derives the flags of one record (the official
// "Log entry format", evidence §2.9). The bodies are decoded into flag-only
// shapes: no text, tool input or tool output is retained.
func parseInvocationRecord(msg string) (invocationRecord, bool) {
	var raw struct {
		Timestamp string `json:"timestamp"`
		ModelID   string `json:"modelId"`
		Identity  struct {
			ARN string `json:"arn"`
		} `json:"identity"`
		Input struct {
			Body bodyFlags `json:"inputBodyJson"`
		} `json:"input"`
		Output struct {
			Body bodyFlags `json:"outputBodyJson"`
		} `json:"output"`
	}
	if err := json.Unmarshal([]byte(msg), &raw); err != nil {
		return invocationRecord{}, false
	}
	rec := invocationRecord{
		identity:   raw.Identity.ARN,
		model:      modelName(raw.ModelID),
		toolUse:    raw.Output.Body.toolUse,
		toolResult: raw.Input.Body.toolResult,
	}
	if t, err := time.Parse(time.RFC3339, raw.Timestamp); err == nil {
		rec.at = t.UTC()
	}
	return rec, true
}

// present records whether a JSON member is there (and not null) without
// keeping its value.
type present bool

func (p *present) UnmarshalJSON(b []byte) error {
	*p = present(!bytes.Equal(bytes.TrimSpace(b), []byte("null")))
	return nil
}

// block is a content block: Converse blocks are keyed by their kind
// (toolUse, toolResult), Anthropic blocks carry a type.
type block struct {
	Type       string  `json:"type"`
	ToolUse    present `json:"toolUse"`
	ToolResult present `json:"toolResult"`
}

// blocks is a content list; a string content (plain text) decodes to none.
type blocks []block

func (bs *blocks) UnmarshalJSON(b []byte) error {
	var list []block
	if json.Unmarshal(b, &list) == nil {
		*bs = list
	}
	return nil
}

type message struct {
	Content blocks `json:"content"`
}

// bodyShape covers the request and response bodies of Converse and of
// InvokeModel with Anthropic models, and (leniently, UNVERIFIED for
// invocation logs) the stream events of ConverseStream and
// InvokeModelWithResponseStream when a body is an array of them.
type bodyShape struct {
	StopReason      string    `json:"stopReason"`  // Converse response
	StopReasonSnake string    `json:"stop_reason"` // Anthropic response
	Content         blocks    `json:"content"`     // Anthropic response
	Messages        []message `json:"messages"`    // request (both)
	Output          *struct {
		Message *message `json:"message"`
	} `json:"output"` // Converse response
	ContentBlock *block `json:"content_block"` // Anthropic content_block_start
	Delta        *struct {
		StopReason string `json:"stop_reason"`
	} `json:"delta"` // Anthropic message_delta
	ContentBlockStart *struct {
		Start *block `json:"start"`
	} `json:"contentBlockStart"` // ConverseStream
	MessageStop *struct {
		StopReason string `json:"stopReason"`
	} `json:"messageStop"` // ConverseStream
}

func (b bodyShape) flags() (toolUse, toolResult bool) {
	isUse := func(x block) bool { return bool(x.ToolUse) || x.Type == "tool_use" }
	isResult := func(x block) bool { return bool(x.ToolResult) || x.Type == "tool_result" }
	if b.StopReason == "tool_use" || b.StopReasonSnake == "tool_use" {
		toolUse = true
	}
	for _, c := range b.Content {
		toolUse = toolUse || isUse(c)
	}
	if b.Output != nil && b.Output.Message != nil {
		for _, c := range b.Output.Message.Content {
			toolUse = toolUse || isUse(c)
		}
	}
	if b.ContentBlock != nil && isUse(*b.ContentBlock) {
		toolUse = true
	}
	if b.Delta != nil && b.Delta.StopReason == "tool_use" {
		toolUse = true
	}
	if b.ContentBlockStart != nil && b.ContentBlockStart.Start != nil && isUse(*b.ContentBlockStart.Start) {
		toolUse = true
	}
	if b.MessageStop != nil && b.MessageStop.StopReason == "tool_use" {
		toolUse = true
	}
	for _, m := range b.Messages {
		for _, c := range m.Content {
			toolResult = toolResult || isResult(c)
		}
	}
	return toolUse, toolResult
}

// bodyFlags decodes a body (an object, or an array of stream events) into
// its two flags.
type bodyFlags struct{ toolUse, toolResult bool }

func (f *bodyFlags) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	var shapes []bodyShape
	switch b[0] {
	case '{':
		var one bodyShape
		if json.Unmarshal(b, &one) == nil {
			shapes = append(shapes, one)
		}
	case '[':
		_ = json.Unmarshal(b, &shapes)
	}
	for _, sh := range shapes {
		u, r := sh.flags()
		f.toolUse = f.toolUse || u
		f.toolResult = f.toolResult || r
	}
	return nil
}
