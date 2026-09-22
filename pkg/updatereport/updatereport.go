// Copyright Drydock Contributors.
// Portions derived from containrrr/watchtower (Apache-2.0).
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

// Package updatereport renders and delivers per-cycle update reports for
// Drydock: a deterministic human summary (Go text/template) and a stable
// machine-readable JSON form, on top of a minimal Sender abstraction.
//
// Module: github.com/drydock-updater/drydock. This package implements the
// safeflow.Reporter contract (pkg/safeflow/report.go) and follows the
// zero-conflict rule: it imports pkg/safeflow, the standard library,
// sirupsen/logrus and - in shoutrrr.go only - containrrr/shoutrrr v0.8.0
// (go.mod:6).
//
// Silence rule (upstream pain watchtower#1962/#1313 - quiet cycles must not
// spam notification channels): Report invokes the Sender only when the cycle
// contains at least one StatusUpdated, StatusFailed or StatusRolledBack
// container. All-fresh / all-skipped cycles produce console output only.
// The console summary is written on every cycle unconditionally.
//
// v0.1 non-goals: no persisted notification state, no prometheus metrics,
// no user-supplied template flag.
package updatereport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/drydock-updater/drydock/pkg/safeflow"
	"github.com/sirupsen/logrus"
)

// Sender is the minimal notification abstraction this package depends on.
// Production use wraps a containrrr/shoutrrr router (see shoutrrr.go); the
// router itself is constructed by the cmd layer from --notification-url and
// injected, so this package never parses URLs or dials anything. A nil
// Sender passed to New selects pure console mode.
type Sender interface {
	Send(ctx context.Context, subject, body string) error
}

// Options tunes Reporter construction. The zero value is valid.
type Options struct {
	// Console receives the per-cycle human summary on every cycle. When nil,
	// os.Stdout is used.
	Console io.Writer
}

// Reporter implements safeflow.Reporter. It is safe for sequential use by
// one goroutine (one Report call per cycle, as driven by the cmd layer).
type Reporter struct {
	log     *logrus.Entry
	sender  Sender
	console io.Writer
	tpl     *template.Template
}

// Compile-time proof that Reporter satisfies the shared contract.
var _ safeflow.Reporter = (*Reporter)(nil)

// New builds a Reporter. A nil log falls back to the logrus standard
// logger; a nil sender selects console-only mode (no notification is ever
// attempted). The default template is parsed here - a broken default
// template is a programmer error and panics eagerly, mirroring the
// template.Must idiom used by upstream (pkg/notifications/shoutrrr.go:234).
func New(log *logrus.Entry, sender Sender, opts Options) *Reporter {
	if log == nil {
		log = logrus.NewEntry(logrus.StandardLogger())
	}
	console := opts.Console
	if console == nil {
		console = os.Stdout
	}
	return &Reporter{
		log:     log.WithField("component", "updatereport"),
		sender:  sender,
		console: console,
		tpl:     template.Must(template.New("cycle").Parse(defaultTemplate)),
	}
}

// Report renders the cycle, writes the console summary (always), and
// delivers a notification when the silence rule allows it. Delivery
// failures are logged and swallowed - the returned error is reserved for
// rendering/template programmer errors only.
func (r *Reporter) Report(ctx context.Context, cycle safeflow.CycleReport) error {
	subject := subjectLine(cycle)
	body, err := r.render(cycle, subject)
	if err != nil {
		return fmt.Errorf("updatereport: render cycle report: %w", err)
	}

	// The console summary is unconditional - one output per cycle.
	if _, err := io.WriteString(r.console, body); err != nil {
		r.log.WithError(err).Warn("failed to write console summary")
	}
	r.log.WithField("subject", subject).Info("cycle summary written to console")

	if r.sender == nil {
		r.log.Debug("no sender configured; console-only mode")
		return nil
	}
	if !notifiable(cycle) {
		r.log.WithField("subject", subject).
			Debug("cycle had no updated/failed/rolled-back containers; notification silenced")
		return nil
	}
	if err := r.sender.Send(ctx, subject, body); err != nil {
		// Delivery failure is operational, not a report defect: log only.
		r.log.WithError(err).Warn("failed to deliver cycle report")
		return nil
	}
	r.log.WithField("subject", subject).Info("cycle report delivered")
	return nil
}

// ReportJSON renders the cycle as deterministic, diff-friendly JSON. It
// marshals the safeflow.CycleReport struct tree directly (field order is
// the struct declaration order; the contract types are map-free), never
// injects wall-clock or reporter state, and appends a trailing newline.
// Two calls with the same input produce byte-identical output.
func (r *Reporter) ReportJSON(cycle safeflow.CycleReport) ([]byte, error) {
	out, err := json.MarshalIndent(cycle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("updatereport: marshal cycle report: %w", err)
	}
	return append(out, '\n'), nil
}
