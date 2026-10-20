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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Sink persists audit events. Implementations must be safe for concurrent use
// and must not retain the slice after Write returns.
//
// The interface exists so that a durable store or a direct SIEM feed can be
// added later without touching a single emit site: only the sink list changes.
type Sink interface {
	Write(ctx context.Context, events []Event) error
	Name() string
}

// multiSink fans out to every configured sink. One failing sink never prevents
// the others from writing, and the joined error tells the caller which failed.
type multiSink []Sink

func (m multiSink) Name() string { return "multi" }

func (m multiSink) Write(ctx context.Context, events []Event) error {
	var errs []error
	for _, s := range m {
		if err := s.Write(ctx, events); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// NewMultiSink combines sinks. It returns the single sink unwrapped when there
// is only one, and a sink that discards when there are none.
func NewMultiSink(sinks ...Sink) Sink {
	switch len(sinks) {
	case 0:
		return discardSink{}
	case 1:
		return sinks[0]
	default:
		return multiSink(sinks)
	}
}

// sinkNames lists the sinks behind s, unwrapping a multi-sink.
func sinkNames(s Sink) []string {
	if m, ok := s.(multiSink); ok {
		out := make([]string, 0, len(m))
		for _, inner := range m {
			out = append(out, inner.Name())
		}
		return out
	}
	return []string{s.Name()}
}

// SinkNames reports where a recorder writes, for the startup posture record.
// Nil for a recorder that writes nowhere (disabled or not installed).
func SinkNames(r Recorder) []string {
	if br, ok := r.(*bufferedRecorder); ok {
		return sinkNames(br.sink)
	}
	return nil
}

type discardSink struct{}

func (discardSink) Name() string                         { return "discard" }
func (discardSink) Write(context.Context, []Event) error { return nil }

// stdoutSink writes one JSON object per event to stdout.
//
// The service already emits structured JSON logs there and the platform's log
// pipeline collects container stdout, so this makes audit events searchable
// without any new infrastructure. It also gives the trail a copy the service
// cannot rewrite: there is no write path from here back into the log store,
// which is what makes it usable as a tamper-evidence witness.
//
// Retention is the operator's responsibility — see docs/audit-logging.md.
type stdoutSink struct {
	logger *slog.Logger
	// mu serialises writes so that a record is never interleaved with another.
	// slog's handler locks internally, but Write must also be atomic across the
	// batch for the flush-on-shutdown ordering to be meaningful.
	mu sync.Mutex
}

// NewStdoutSink returns a sink writing newline-delimited JSON audit records.
//
// It uses its own handler rather than the default logger so that audit records
// are emitted at a fixed level and cannot be filtered out by raising LOG_LEVEL.
func NewStdoutSink() Sink {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	return &stdoutSink{logger: slog.New(handler)}
}

func (s *stdoutSink) Name() string { return "stdout" }

func (s *stdoutSink) Write(ctx context.Context, events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range events {
		// Checked per record rather than per batch. A write to os.Stdout is
		// synchronous and cannot itself be cancelled, so the deadline bounds how
		// many more records this call will attempt — not the one already in
		// flight. That still matters: a blocked log pipe would otherwise hold a
		// request goroutine through a whole batch on the fail-closed path.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("audit stdout sink: %d of %d records written: %w", i, len(events), err)
		}
		s.logger.LogAttrs(
			ctx, slog.LevelInfo, "audit",
			// A single fixed key lets the log pipeline select audit records
			// with one term query and route them to their own index.
			slog.String("log_type", "audit"),
			slog.Any("event", &events[i]),
		)
	}
	return nil
}

// writeTimeout bounds a sink write. Sinks are expected to honour the deadline;
// stdoutSink checks it between records, which is the finest granularity a
// synchronous write to a file descriptor allows.
const writeTimeout = 5 * time.Second
