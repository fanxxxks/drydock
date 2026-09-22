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

package updatereport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/drydock-updater/drydock/pkg/safeflow"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSender is the capturing fake Sender; it never touches the network.
type fakeSender struct {
	calls  []fakeSend
	retErr error
}

type fakeSend struct {
	subject string
	body    string
}

var _ Sender = (*fakeSender)(nil)

func (f *fakeSender) Send(_ context.Context, subject, body string) error {
	f.calls = append(f.calls, fakeSend{subject: subject, body: body})
	return f.retErr
}

// newTestReporter wires a Reporter whose console output is captured and
// whose logger is silenced.
func newTestReporter(sender Sender) (*Reporter, *bytes.Buffer) {
	lg := logrus.New()
	lg.SetOutput(io.Discard)
	console := &bytes.Buffer{}
	return New(lg.WithField("test", true), sender, Options{Console: console}), console
}

var cycleStart = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func updatedCycle() safeflow.CycleReport {
	return safeflow.CycleReport{
		StartedAt: cycleStart,
		Updates: []safeflow.ContainerReport{
			{
				ContainerName: "web",
				Status:        safeflow.StatusUpdated,
				OldImageRef:   "docker.io/library/nginx:1.25.3",
				NewImageRef:   "docker.io/library/nginx:1.27.2",
				Precheck: &safeflow.PrecheckVerdict{
					Allow:      true,
					Reason:     safeflow.PrecheckAllowed,
					CurrentTag: "1.25.3",
					TargetTag:  "1.27.2",
					Semver:     true,
				},
				Health: &safeflow.HealthResult{
					Status:  safeflow.HealthHealthy,
					Checks:  3,
					Elapsed: 12 * time.Second,
				},
			},
			{
				ContainerName: "db",
				Status:        safeflow.StatusFresh,
				OldImageRef:   "docker.io/library/postgres:16.1",
			},
		},
	}
}

func rollbackCycle() safeflow.CycleReport {
	return safeflow.CycleReport{
		StartedAt: cycleStart,
		Updates: []safeflow.ContainerReport{
			{
				ContainerName: "api",
				Status:        safeflow.StatusRolledBack,
				OldImageRef:   "docker.io/library/api:2.3.1",
				NewImageRef:   "docker.io/library/api:2.4.0",
				Precheck: &safeflow.PrecheckVerdict{
					Allow:  true,
					Reason: safeflow.PrecheckAllowed,
				},
				Health: &safeflow.HealthResult{
					Status:  safeflow.HealthUnhealthy,
					Reason:  "healthcheck reported unhealthy",
					Checks:  13,
					Elapsed: 65 * time.Second,
				},
				Rollback: &safeflow.RollbackReport{
					SnapshotID:         "api-1726920000000000000",
					RestoredContainerID: "0f1e2d3c4b5a",
				},
				Error: "health gate: container is unhealthy",
			},
			{
				ContainerName: "worker",
				Status:        safeflow.StatusFailed,
				OldImageRef:   "docker.io/library/worker:1.0.0",
				NewImageRef:   "docker.io/library/worker:1.1.0",
				Error:         "recreate: no such image",
			},
			{
				ContainerName: "cache",
				Status:        safeflow.StatusSkipped,
				OldImageRef:   "docker.io/library/redis:7.2",
				NewImageRef:   "docker.io/library/redis:8.0",
				Precheck: &safeflow.PrecheckVerdict{
					Allow:  false,
					Reason: safeflow.PrecheckBlockedMajor,
					Detail: "major bump 7.x -> 8.x",
				},
			},
		},
	}
}

func quietCycle() safeflow.CycleReport {
	return safeflow.CycleReport{
		StartedAt: cycleStart,
		Updates: []safeflow.ContainerReport{
			{ContainerName: "web", Status: safeflow.StatusFresh, OldImageRef: "nginx:1.27.2"},
			{ContainerName: "cache", Status: safeflow.StatusSkipped, OldImageRef: "redis:7.2", NewImageRef: "redis:8.0"},
		},
	}
}

func TestSubjectLine(t *testing.T) {
	cases := []struct {
		name  string
		cycle safeflow.CycleReport
		want  string
	}{
		{"all fresh", quietCycle(), "drydock: no changes"},
		{"empty updates", safeflow.CycleReport{}, "drydock: no changes"},
		{"one updated", updatedCycle(), "drydock: 1 updated"},
		{"rolled back only", func() safeflow.CycleReport {
			c := rollbackCycle()
			c.Updates = c.Updates[:1]
			return c
		}(), "drydock: 1 rolled back"},
		{"failed and rolled back", rollbackCycle(), "drydock: 1 failed, 1 rolled back"},
		{"all three", func() safeflow.CycleReport {
			c := rollbackCycle()
			c.Updates = append(c.Updates, updatedCycle().Updates[0])
			return c
		}(), "drydock: 1 updated, 1 failed, 1 rolled back"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, subjectLine(tc.cycle))
		})
	}
}

func TestNotifiable(t *testing.T) {
	assert.False(t, notifiable(quietCycle()))
	assert.False(t, notifiable(safeflow.CycleReport{}))
	assert.True(t, notifiable(updatedCycle()))
	assert.True(t, notifiable(rollbackCycle()))
}

func TestReportSilencesQuietCycles(t *testing.T) {
	sender := &fakeSender{}
	r, console := newTestReporter(sender)

	require.NoError(t, r.Report(context.Background(), quietCycle()))

	// Silence rule: zero sender calls for an all-fresh/skipped cycle.
	assert.Len(t, sender.calls, 0)
	// Console summary is still written on every cycle.
	out := console.String()
	assert.Contains(t, out, "drydock: no changes")
	assert.Contains(t, out, "web")
	assert.Contains(t, out, "cache")
}

func TestReportNotifiesOnUpdated(t *testing.T) {
	sender := &fakeSender{}
	r, console := newTestReporter(sender)

	require.NoError(t, r.Report(context.Background(), updatedCycle()))

	require.Len(t, sender.calls, 1)
	assert.Equal(t, "drydock: 1 updated", sender.calls[0].subject)
	body := sender.calls[0].body
	assert.Contains(t, body, "web")
	assert.Contains(t, body, "updated")
	assert.Contains(t, body, "nginx:1.25.3 -> docker.io/library/nginx:1.27.2")
	assert.Contains(t, body, "allowed")
	assert.Contains(t, body, "healthy (12s)")
	// fresh sibling with nil Precheck/Health renders the placeholder
	assert.Contains(t, body, "—")
	// console gets the same summary every cycle
	assert.Contains(t, console.String(), "drydock: 1 updated")
}

func TestReportNotifiesOnFailedAndRolledBack(t *testing.T) {
	sender := &fakeSender{}
	r, console := newTestReporter(sender)

	require.NoError(t, r.Report(context.Background(), rollbackCycle()))

	require.Len(t, sender.calls, 1)
	assert.Equal(t, "drydock: 1 failed, 1 rolled back", sender.calls[0].subject)
	body := sender.calls[0].body
	assert.Contains(t, body, "api")
	assert.Contains(t, body, "rolled-back")
	assert.Contains(t, body, "api-1726920000000000000")
	assert.Contains(t, body, "restored from snapshot api-1726920000000000000")
	assert.Contains(t, body, "blocked-major")
	assert.Contains(t, body, "unhealthy (1m5s)")
	assert.Contains(t, body, "health gate: container is unhealthy")
	assert.Contains(t, console.String(), "rolled-back")
}

func TestReportNilSenderConsoleOnly(t *testing.T) {
	var r *Reporter
	var console *bytes.Buffer
	require.NotPanics(t, func() {
		r, console = newTestReporter(nil)
		r.Report(context.Background(), rollbackCycle())
	})
	out := console.String()
	assert.Contains(t, out, "rolled-back")
	assert.Contains(t, out, "api-1726920000000000000")
}

func TestReportNilSafety(t *testing.T) {
	sender := &fakeSender{}

	t.Run("zero cycle", func(t *testing.T) {
		r, console := newTestReporter(sender)
		var err error
		require.NotPanics(t, func() { err = r.Report(context.Background(), safeflow.CycleReport{}) })
		require.NoError(t, err)
		assert.Len(t, sender.calls, 0)
		assert.Contains(t, console.String(), "no containers were in scope this cycle")
	})

	t.Run("empty updates slice", func(t *testing.T) {
		r, console := newTestReporter(sender)
		var err error
		require.NotPanics(t, func() {
			err = r.Report(context.Background(), safeflow.CycleReport{Updates: []safeflow.ContainerReport{}})
		})
		require.NoError(t, err)
		assert.Contains(t, console.String(), "no containers were in scope this cycle")
		assert.Len(t, sender.calls, 0)
	})

	t.Run("all nil substructures", func(t *testing.T) {
		r, console := newTestReporter(sender)
		cycle := safeflow.CycleReport{
			Updates: []safeflow.ContainerReport{
				{ContainerName: "bare", Status: safeflow.StatusFresh},
			},
		}
		var err error
		require.NotPanics(t, func() { err = r.Report(context.Background(), cycle) })
		require.NoError(t, err)
		out := console.String()
		// image, precheck, health, rollback and error cells all render the
		// placeholder on the bare container's own line.
		var bareLine string
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "bare") {
				bareLine = l
			}
		}
		assert.Contains(t, bareLine, "bare")
		assert.Contains(t, bareLine, "fresh")
		assert.Equal(t, 5, strings.Count(bareLine, "—"))
	})

	t.Run("new with nil log", func(t *testing.T) {
		lg := logrus.New()
		lg.SetOutput(io.Discard)
		logrus.StandardLogger().SetOutput(io.Discard)
		var r *Reporter
		require.NotPanics(t, func() {
			r = New(nil, sender, Options{Console: io.Discard})
		})
		require.NoError(t, r.Report(context.Background(), updatedCycle()))
	})
}

func TestReportSendFailureOnlyLogged(t *testing.T) {
	sender := &fakeSender{retErr: errors.New("SMTP refused")}
	r, console := newTestReporter(sender)

	var err error
	require.NotPanics(t, func() { err = r.Report(context.Background(), updatedCycle()) })

	// Delivery failure must not surface as a Report error...
	require.NoError(t, err)
	// ...but the send was attempted and the console summary still written.
	require.Len(t, sender.calls, 1)
	assert.Contains(t, console.String(), "drydock: 1 updated")
}

func TestReportJSONByteStability(t *testing.T) {
	r, _ := newTestReporter(&fakeSender{})

	first, err := r.ReportJSON(updatedCycle())
	require.NoError(t, err)
	second, err := r.ReportJSON(updatedCycle())
	require.NoError(t, err)

	assert.True(t, bytes.Equal(first, second),
		"same input must marshal to identical bytes")
	assert.Equal(t, first, second)

	// A second reporter instance produces the same bytes: no hidden state.
	r2, _ := newTestReporter(nil)
	third, err := r2.ReportJSON(updatedCycle())
	require.NoError(t, err)
	assert.Equal(t, first, third)

	s := string(first)
	assert.True(t, strings.HasSuffix(s, "\n"), "diff-friendly trailing newline")
	// Struct-marshal field order is the declaration order (stable, diffable).
	assert.Less(t, strings.Index(s, "\"StartedAt\""), strings.Index(s, "\"Updates\""))
	assert.Less(t, strings.Index(s, "\"ContainerName\""), strings.Index(s, "\"Status\""))
	assert.Contains(t, s, "\"Status\": \"updated\"")
	assert.Contains(t, s, "\"Rollback\": null")

	// Different cycle, different bytes (sanity: the above is not trivially constant).
	other, err := r.ReportJSON(rollbackCycle())
	require.NoError(t, err)
	assert.NotEqual(t, first, other)
	assert.Contains(t, string(other), "\"SnapshotID\": \"api-1726920000000000000\"")
}

func TestReporterImplementsSafeflowContract(t *testing.T) {
	sender := &fakeSender{}
	var rep safeflow.Reporter // interface compliance, exercised end to end
	rep, _ = newTestReporter(sender)
	require.NoError(t, rep.Report(context.Background(), updatedCycle()))
	assert.Len(t, sender.calls, 1)
}
