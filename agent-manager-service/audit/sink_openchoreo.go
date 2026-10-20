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

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// maxOpenChoreoLineBytes bounds one written record. Redaction already caps
// every field, but a record may carry many capped detail values; above this
// size the details are left out (and the omission recorded) rather than
// writing a line the log collector might split or skip.
const maxOpenChoreoLineBytes = 64 * 1024

// openChoreoSink writes OpenChoreo audit records, one JSON line each, to
// standard output — where the kubelet captures them into the container log
// that OpenChoreo's log collector reads.
//
// That collector accepts a record only from a container on its trusted-producer
// allowlist (matched on the log file name the kubelet writes, which a pod
// cannot choose), so this sink's output reaches the audit index only when this
// service is listed there. See docs/audit-logging.md.
type openChoreoSink struct {
	w io.Writer
	// mu makes each record a single Write. os.File already serialises writes
	// per call, so one Write per line cannot interleave with the application
	// logger writing to the same descriptor.
	mu  sync.Mutex
	now func() time.Time
}

// NewOpenChoreoSink returns a sink writing OpenChoreo audit records to stdout.
func NewOpenChoreoSink() Sink {
	return newOpenChoreoSink(os.Stdout)
}

func newOpenChoreoSink(w io.Writer) *openChoreoSink {
	return &openChoreoSink{w: w, now: time.Now}
}

func (s *openChoreoSink) Name() string { return "openchoreo" }

// ocLine is one written record: the envelope OpenChoreo's own audit logger
// emits (time, level, message) followed by the record's fields.
type ocLine struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
	ocRecord
}

func (s *openChoreoSink) Write(ctx context.Context, events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range events {
		// Checked between records: a write to a file descriptor cannot itself
		// be cancelled, so the deadline bounds how many more records are tried.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("audit openchoreo sink: %d of %d records written: %w", i, len(events), err)
		}
		line, err := renderOpenChoreoLine(&events[i], s.now())
		if err != nil {
			return fmt.Errorf("audit openchoreo sink: render event %s: %w", events[i].EventID, err)
		}
		if _, err := s.w.Write(line); err != nil {
			return fmt.Errorf("audit openchoreo sink: %d of %d records written: %w", i, len(events), err)
		}
	}
	return nil
}

// renderOpenChoreoLine returns the newline-terminated line for one event.
func renderOpenChoreoLine(e *Event, now time.Time) ([]byte, error) {
	line := ocLine{
		Time:     now.UTC(),
		Level:    "INFO",
		Msg:      OpenChoreoRoutingKey,
		ocRecord: toOpenChoreoRecord(e),
	}
	b, err := json.Marshal(line)
	if err != nil {
		return nil, err
	}
	if len(b) > maxOpenChoreoLineBytes {
		amp, _ := line.Metadata[ampMetadataKey].(map[string]any)
		delete(amp, "details")
		amp["detailsOmitted"] = true
		amp["originalBytes"] = len(b)
		if b, err = json.Marshal(line); err != nil {
			return nil, err
		}
	}
	return append(b, '\n'), nil
}
