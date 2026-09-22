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
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/drydock-updater/drydock/pkg/safeflow"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errConsole is an io.Writer that always fails, to prove console-write
// failures are logged and swallowed (never returned from Report).
type errConsole struct{}

func (errConsole) Write([]byte) (int, error) {
	return 0, errors.New("console broken")
}

// gateTimeoutCycle models a container whose health-gate window closed
// without a verdict (ErrHealthTimeout path, safeflow.go:68) and whose
// rollback therefore never ran.
func gateTimeoutCycle() safeflow.CycleReport {
	return safeflow.CycleReport{
		StartedAt: cycleStart,
		Updates: []safeflow.ContainerReport{
			{
				ContainerName: "web",
				Status:        safeflow.StatusFailed,
				OldImageRef:   "docker.io/library/nginx:1.27.1",
				NewImageRef:   "docker.io/library/nginx:1.27.2",
				Precheck: &safeflow.PrecheckVerdict{
					Allow:  true,
					Reason: safeflow.PrecheckAllowed,
				},
				Health: &safeflow.HealthResult{
					Status:  safeflow.HealthStarting,
					Reason:  "still starting when the window closed",
					Checks:  12,
					Elapsed: 60 * time.Second,
				},
				Error: "health gate: " + safeflow.ErrHealthTimeout.Error(),
			},
		},
	}
}

// corruptedSnapshotCycle models an update judged unhealthy whose rollback
// then failed on an unusable snapshot (ErrSnapshotInvalid, safeflow.go:76):
// the operator must see both facts in one row.
func corruptedSnapshotCycle() safeflow.CycleReport {
	return safeflow.CycleReport{
		StartedAt: cycleStart,
		Updates: []safeflow.ContainerReport{
			{
				ContainerName: "api",
				Status:        safeflow.StatusRolledBack,
				OldImageRef:   "docker.io/library/api:2.3.1",
				NewImageRef:   "docker.io/library/api:2.4.0",
				Health: &safeflow.HealthResult{
					Status:  safeflow.HealthUnhealthy,
					Reason:  "healthcheck reported unhealthy",
					Checks:  4,
					Elapsed: 9 * time.Second,
				},
				Rollback: &safeflow.RollbackReport{
					SnapshotID: "api-1726920000000000003",
					Error:      safeflow.ErrSnapshotInvalid.Error() + ": payload truncated on disk",
				},
				Error: "health gate: " + safeflow.ErrUnhealthy.Error(),
			},
		},
	}
}

// missingImageRollbackCycle models a rollback that could not run because an
// eager cleanup had already removed the pinned image (ErrRollbackImageMissing,
// safeflow.go:81).
func missingImageRollbackCycle() safeflow.CycleReport {
	c := corruptedSnapshotCycle()
	u := &c.Updates[0]
	u.Rollback = &safeflow.RollbackReport{
		SnapshotID: "api-1726920000000000004",
		Error:      safeflow.ErrRollbackImageMissing.Error(),
	}
	return c
}

// exitedDuringGateCycle models a replacement container that died inside the
// gate window (HealthExited with an exit code).
func exitedDuringGateCycle() safeflow.CycleReport {
	c := corruptedSnapshotCycle()
	u := &c.Updates[0]
	u.Health = &safeflow.HealthResult{
		Status:   safeflow.HealthExited,
		Reason:   "container exited during gate window",
		Checks:   2,
		ExitCode: 137,
		Elapsed:  3 * time.Second,
	}
	u.Error = "health gate: " + safeflow.ErrUnhealthy.Error()
	return c
}

// pullFailureCycle models a StatusFailed with no NewImageRef (the new image
// never materialised locally) plus an empty container name / zero start time
// to exercise placeholder rendering end to end.
func pullFailureCycle() safeflow.CycleReport {
	return safeflow.CycleReport{
		Updates: []safeflow.ContainerReport{
			{
				Status:      safeflow.StatusFailed,
				OldImageRef: "docker.io/library/worker:1.0.0",
				Error:       "pull: manifest unknown",
			},
		},
	}
}

func TestReportScenarioMatrix(t *testing.T) {
	cases := []struct {
		name            string
		cycle           func() safeflow.CycleReport
		wantNotify      bool
		wantSubject     string
		wantBodyParts   []string
		wantNoBodyParts []string
	}{
		{
			name:        "healthy update passes the full loop",
			cycle:       updatedCycle,
			wantNotify:  true,
			wantSubject: "drydock: 1 updated",
			wantBodyParts: []string{
				"web", "updated",
				"docker.io/library/nginx:1.25.3 -> docker.io/library/nginx:1.27.2",
				"allowed", "healthy (12s)",
			},
		},
		{
			name:        "health gate timeout reports starting state and sentinel",
			cycle:       gateTimeoutCycle,
			wantNotify:  true,
			wantSubject: "drydock: 1 failed",
			wantBodyParts: []string{
				"web", "failed", "starting (1m0s)",
				safeflow.ErrHealthTimeout.Error(),
			},
		},
		{
			name:        "unhealthy with successful rollback",
			cycle:       func() safeflow.CycleReport { c := rollbackCycle(); c.Updates = c.Updates[:1]; return c },
			wantNotify:  true,
			wantSubject: "drydock: 1 rolled back",
			wantBodyParts: []string{
				"api", "rolled-back", "unhealthy (1m5s)",
				"restored from snapshot api-1726920000000000000",
			},
		},
		{
			name:        "rollback against corrupted snapshot surfaces both failures",
			cycle:       corruptedSnapshotCycle,
			wantNotify:  true,
			wantSubject: "drydock: 1 rolled back",
			wantBodyParts: []string{
				"restore of snapshot api-1726920000000000003 failed: " +
					safeflow.ErrSnapshotInvalid.Error() + ": payload truncated on disk",
				safeflow.ErrUnhealthy.Error(),
			},
		},
		{
			name:        "rollback blocked by missing image surfaces sentinel",
			cycle:       missingImageRollbackCycle,
			wantNotify:  true,
			wantSubject: "drydock: 1 rolled back",
			wantBodyParts: []string{
				"restore of snapshot api-1726920000000000004 failed: " +
					safeflow.ErrRollbackImageMissing.Error(),
			},
		},
		{
			name:        "container exited during gate window",
			cycle:       exitedDuringGateCycle,
			wantNotify:  true,
			wantSubject: "drydock: 1 rolled back",
			wantBodyParts: []string{"exited (3s)"},
		},
		{
			name:        "pull failure with unknown new image ref",
			cycle:       pullFailureCycle,
			wantNotify:  true,
			wantSubject: "drydock: 1 failed",
			wantBodyParts: []string{
				"failed",
				"docker.io/library/worker:1.0.0 -> —",
				"pull: manifest unknown",
				"drydock cycle unknown", // zero StartedAt
			},
		},
		{
			name:           "all quiet cycle is silenced but still consoled",
			cycle:          quietCycle,
			wantNotify:     false,
			wantSubject:    "drydock: no changes",
			wantBodyParts:  []string{"web", "fresh"},
			wantNoBodyParts: []string{"updated"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakeSender{}
			r, console := newTestReporter(sender)

			var err error
			require.NotPanics(t, func() { err = r.Report(context.Background(), tc.cycle()) })
			require.NoError(t, err)

			body := console.String()
			for _, part := range tc.wantBodyParts {
				assert.Contains(t, body, part)
			}
			for _, part := range tc.wantNoBodyParts {
				assert.NotContains(t, body, part)
			}

			if !tc.wantNotify {
				assert.Empty(t, sender.calls, "silence rule: no notification for this cycle")
				return
			}
			require.Len(t, sender.calls, 1)
			assert.Equal(t, tc.wantSubject, sender.calls[0].subject)
			assert.Contains(t, sender.calls[0].body, tc.wantSubject)

			// No rendered line may carry trailing whitespace: only the last
			// column is unpadded and every other column pads exactly.
			for _, line := range strings.Split(sender.calls[0].body, "\n") {
				assert.False(t, strings.HasSuffix(line, " "),
					"line must not end in padding spaces: %q", line)
			}
		})
	}
}

// TestReportPrecheckBlockedVariants walks every veto reason in the contract:
// all are StatusSkipped, so the cycle is silenced and only the console shows
// why the update was refused.
func TestReportPrecheckBlockedVariants(t *testing.T) {
	cases := []struct {
		reason safeflow.PrecheckReason
		detail string
	}{
		{safeflow.PrecheckBlockedMajor, "major bump 7.x -> 8.x"},
		{safeflow.PrecheckBlockedPrerelease, "target is 8.0.0-rc.1"},
		{safeflow.PrecheckBlockedUnknownTag, "tag \"latest\" is not semver"},
		{safeflow.PrecheckBlockedNoHealthcheck, "target image defines no HEALTHCHECK"},
		{safeflow.PrecheckBypassed, "label com.drydock.updater.precheck=false"},
	}
	for _, tc := range cases {
		t.Run(string(tc.reason), func(t *testing.T) {
			sender := &fakeSender{}
			r, console := newTestReporter(sender)
			cycle := safeflow.CycleReport{
				StartedAt: cycleStart,
				Updates: []safeflow.ContainerReport{
					{
						ContainerName: "cache",
						Status:        safeflow.StatusSkipped,
						OldImageRef:   "redis:7.2",
						NewImageRef:   "redis:8.0",
						Precheck: &safeflow.PrecheckVerdict{
							Allow:  false,
							Reason: tc.reason,
							Detail: tc.detail,
						},
					},
				},
			}

			require.NoError(t, r.Report(context.Background(), cycle))

			assert.Empty(t, sender.calls, "skipped containers never notify")
			out := console.String()
			assert.Contains(t, out, string(tc.reason))
			assert.Contains(t, out, "skipped")
			assert.Contains(t, out, "drydock: no changes")
		})
	}
}

func TestReportConsoleWriteFailureOnlyLogged(t *testing.T) {
	// New(nil, ...) logs through the logrus standard logger; silence it so
	// the expected warnings do not pollute test output.
	logrus.StandardLogger().SetOutput(io.Discard)
	sender := &fakeSender{}
	r := New(nil, sender, Options{Console: errConsole{}})

	t.Run("notifiable cycle: write failure does not block delivery", func(t *testing.T) {
		var err error
		require.NotPanics(t, func() { err = r.Report(context.Background(), updatedCycle()) })
		require.NoError(t, err, "console failure is operational, logged only")
		require.Len(t, sender.calls, 1, "notification still delivered")
	})

	t.Run("quiet cycle with nil sender: write failure still not fatal", func(t *testing.T) {
		rq := New(nil, nil, Options{Console: errConsole{}})
		var err error
		require.NotPanics(t, func() { err = rq.Report(context.Background(), quietCycle()) })
		require.NoError(t, err)
	})
}

// TestReportRenderErrorPropagates proves the only error Report ever returns
// is a rendering defect: a template that fails at execute time (white-box:
// the field is package-private) surfaces wrapped, before any send.
func TestReportRenderErrorPropagates(t *testing.T) {
	sender := &fakeSender{}
	r, console := newTestReporter(sender)
	r.tpl = template.Must(template.New("cycle").Parse(`{{.Rows.MissingField}}`))

	err := r.Report(context.Background(), updatedCycle())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "updatereport: render cycle report")
	assert.Contains(t, err.Error(), "execute default template")
	assert.Empty(t, sender.calls, "nothing is sent when rendering fails")
	assert.Empty(t, console.String(), "nothing is written when rendering fails")
}

func TestReportOutputDeterministic(t *testing.T) {
	t.Run("two reporters, same cycle, identical bytes", func(t *testing.T) {
		r1, c1 := newTestReporter(nil)
		r2, c2 := newTestReporter(nil)
		require.NoError(t, r1.Report(context.Background(), rollbackCycle()))
		require.NoError(t, r2.Report(context.Background(), rollbackCycle()))
		assert.True(t, bytes.Equal([]byte(c1.String()), []byte(c2.String())))
	})

	t.Run("same reporter twice repeats the identical block", func(t *testing.T) {
		r, console := newTestReporter(nil)
		require.NoError(t, r.Report(context.Background(), rollbackCycle()))
		first := console.String()
		require.NoError(t, r.Report(context.Background(), rollbackCycle()))
		assert.Equal(t, first+first, console.String(), "no hidden per-call state")
	})
}

func TestNewDefaults(t *testing.T) {
	t.Run("zero options select stdout console", func(t *testing.T) {
		r := New(nil, nil, Options{})
		assert.Equal(t, os.Stdout, r.console)
		assert.NotNil(t, r.log, "nil log falls back to the standard logger")
		assert.NotNil(t, r.tpl, "default template parsed eagerly")
		assert.Nil(t, r.sender, "nil sender means console-only mode")
	})

	t.Run("explicit console is honoured", func(t *testing.T) {
		buf := &bytes.Buffer{}
		r := New(nil, nil, Options{Console: buf})
		assert.Equal(t, buf, r.console)
	})
}

func TestReportJSONScenarios(t *testing.T) {
	r, _ := newTestReporter(nil)

	cases := []struct {
		name          string
		cycle         safeflow.CycleReport
		wantContains  []string
	}{
		{
			name:  "zero cycle is stable and explicit",
			cycle: safeflow.CycleReport{},
			wantContains: []string{
				`"StartedAt": "0001-01-01T00:00:00Z"`,
				`"Updates": null`,
			},
		},
		{
			name: "health gate timeout keeps machine fields",
			cycle: gateTimeoutCycle(),
			wantContains: []string{
				`"Status": "starting"`,
				`"Elapsed": 60000000000`,
				`"Checks": 12`,
			},
		},
		{
			name: "exited container keeps its exit code",
			cycle: exitedDuringGateCycle(),
			wantContains: []string{
				`"Status": "exited"`,
				`"ExitCode": 137`,
			},
		},
		{
			name: "pre-update snapshot id travels on the container row",
			cycle: func() safeflow.CycleReport {
				c := updatedCycle()
				c.Updates[0].SnapshotID = "web-1726920000000000000"
				return c
			}(),
			wantContains: []string{`"SnapshotID": "web-1726920000000000000"`},
		},
		{
			name: "changelog notes surface verbatim (fetched upstream, injected here)",
			cycle: safeflow.CycleReport{Updates: []safeflow.ContainerReport{
				{
					ContainerName: "web",
					Status:        safeflow.StatusSkipped,
					Precheck: &safeflow.PrecheckVerdict{
						Allow: false,
						Reason: safeflow.PrecheckBlockedMajor,
						Notes: []string{
							"changelog: https://example.com/nginx/CHANGELOG#1.27",
							"BREAKING: default config syntax changed in 1.27",
						},
					},
				},
			}},
			wantContains: []string{
				"changelog: https://example.com/nginx/CHANGELOG#1.27",
				"BREAKING: default config syntax changed in 1.27",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := r.ReportJSON(tc.cycle)
			require.NoError(t, err)
			s := string(out)
			assert.True(t, strings.HasSuffix(s, "\n"), "trailing newline")
			for _, want := range tc.wantContains {
				assert.Contains(t, s, want)
			}
		})
	}
}

// TestReportJSONRoundTrip proves the JSON form is lossless enough for
// tooling to consume: field-wise comparison after unmarshalling.
func TestReportJSONRoundTrip(t *testing.T) {
	r, _ := newTestReporter(nil)
	original := rollbackCycle()

	out, err := r.ReportJSON(original)
	require.NoError(t, err)

	var back safeflow.CycleReport
	require.NoError(t, json.Unmarshal(out, &back))

	require.Len(t, back.Updates, len(original.Updates))
	u0, o0 := back.Updates[0], original.Updates[0]
	assert.True(t, back.StartedAt.Equal(original.StartedAt))
	assert.Equal(t, u0.ContainerName, o0.ContainerName)
	assert.Equal(t, u0.Status, o0.Status)
	assert.Equal(t, u0.OldImageRef, o0.OldImageRef)
	require.NotNil(t, u0.Precheck)
	assert.Equal(t, o0.Precheck.Allow, u0.Precheck.Allow)
	require.NotNil(t, u0.Health)
	assert.Equal(t, o0.Health.Status, u0.Health.Status)
	assert.Equal(t, o0.Health.Elapsed, u0.Health.Elapsed)
	require.NotNil(t, u0.Rollback)
	assert.Equal(t, o0.Rollback.SnapshotID, u0.Rollback.SnapshotID)
	assert.Equal(t, o0.Rollback.RestoredContainerID, u0.Rollback.RestoredContainerID)
}
