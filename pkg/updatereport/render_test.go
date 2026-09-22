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
	"strings"
	"testing"
	"time"

	"github.com/drydock-updater/drydock/pkg/safeflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file exercises the pure projection layer in render.go with
// table-driven tests: cell formatters (nil sub-structures, empty values,
// sentinel error texts from the safeflow contract), duration/zero-time
// formatting, column padding, subject counting and the notifiable switch.
// Everything here is in-memory: no docker daemon, no network.

func TestOrPlaceholder(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty string becomes placeholder", "", placeholder},
		{"non-empty passes through verbatim", "nginx:1.27", "nginx:1.27"},
		{"whitespace-only is not empty", " ", " "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, orPlaceholder(tc.in))
		})
	}
}

func TestImageCell(t *testing.T) {
	cases := []struct {
		name string
		u    safeflow.ContainerReport
		want string
	}{
		{
			name: "both refs unknown yields placeholder",
			u:    safeflow.ContainerReport{},
			want: placeholder,
		},
		{
			name: "old ref only pads the new side",
			u:    safeflow.ContainerReport{OldImageRef: "nginx:1.25.3"},
			want: "nginx:1.25.3 -> —",
		},
		{
			name: "new ref only pads the old side",
			u:    safeflow.ContainerReport{NewImageRef: "nginx:1.27.2"},
			want: "— -> nginx:1.27.2",
		},
		{
			name: "both refs render old -> new",
			u:    safeflow.ContainerReport{OldImageRef: "nginx:1.25.3", NewImageRef: "nginx:1.27.2"},
			want: "nginx:1.25.3 -> nginx:1.27.2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, imageCell(&tc.u))
		})
	}
}

func TestPrecheckCell(t *testing.T) {
	cases := []struct {
		name string
		v    *safeflow.PrecheckVerdict
		want string
	}{
		{"nil verdict yields placeholder", nil, placeholder},
		{"empty reason yields placeholder", &safeflow.PrecheckVerdict{}, placeholder},
		{
			name: "reason rendered verbatim",
			v:    &safeflow.PrecheckVerdict{Allow: false, Reason: safeflow.PrecheckBlockedMajor, Detail: "major bump"},
			want: "blocked-major",
		},
		{
			name: "label bypass reason rendered verbatim",
			v:    &safeflow.PrecheckVerdict{Allow: true, Reason: safeflow.PrecheckBypassed},
			want: "bypassed-by-label",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, precheckCell(tc.v))
		})
	}
}

func TestHealthCell(t *testing.T) {
	cases := []struct {
		name string
		h    *safeflow.HealthResult
		want string
	}{
		{"nil result yields placeholder", nil, placeholder},
		{
			name: "healthy with elapsed",
			h:    &safeflow.HealthResult{Status: safeflow.HealthHealthy, Checks: 3, Elapsed: 12 * time.Second},
			want: "healthy (12s)",
		},
		{
			name: "empty status still renders elapsed with placeholder",
			h:    &safeflow.HealthResult{Elapsed: 5 * time.Second},
			want: "— (5s)",
		},
		{
			name: "starting at gate timeout",
			h:    &safeflow.HealthResult{Status: safeflow.HealthStarting, Checks: 12, Elapsed: 60 * time.Second},
			want: "starting (1m0s)",
		},
		{
			name: "unhealthy carries over into rollback rows",
			h:    &safeflow.HealthResult{Status: safeflow.HealthUnhealthy, Checks: 13, Elapsed: 65 * time.Second},
			want: "unhealthy (1m5s)",
		},
		{
			name: "exited during the gate window",
			h:    &safeflow.HealthResult{Status: safeflow.HealthExited, ExitCode: 137, Elapsed: 3 * time.Second},
			want: "exited (3s)",
		},
		{
			name: "image without healthcheck judged by running state",
			h:    &safeflow.HealthResult{Status: safeflow.HealthUnknown, Elapsed: 2 * time.Second},
			want: "unknown (2s)",
		},
		{
			name: "zero elapsed renders 0s",
			h:    &safeflow.HealthResult{Status: safeflow.HealthHealthy},
			want: "healthy (0s)",
		},
		{
			name: "negative elapsed clamps to 0s",
			h:    &safeflow.HealthResult{Status: safeflow.HealthHealthy, Elapsed: -time.Second},
			want: "healthy (0s)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, healthCell(tc.h))
		})
	}
}

func TestRollbackCell(t *testing.T) {
	cases := []struct {
		name string
		rb   *safeflow.RollbackReport
		want string
	}{
		{"nil report yields placeholder", nil, placeholder},
		{
			name: "successful restore surfaces the snapshot id",
			rb:   &safeflow.RollbackReport{SnapshotID: "api-1726920000000000000", RestoredContainerID: "0f1e2d3c4b5a"},
			want: "restored from snapshot api-1726920000000000000",
		},
		{
			name: "successful restore with unknown snapshot id",
			rb:   &safeflow.RollbackReport{RestoredContainerID: "abc"},
			want: "restored from snapshot —",
		},
		{
			name: "corrupted snapshot: sentinel text from the contract preserved",
			rb: &safeflow.RollbackReport{
				SnapshotID: "api-1726920000000000001",
				Error:      safeflow.ErrSnapshotInvalid.Error() + ": payload truncated",
			},
			want: "restore of snapshot api-1726920000000000001 failed: safeflow: invalid container inspect for snapshot: payload truncated",
		},
		{
			name: "eager cleanup removed the snapshot image: sentinel preserved",
			rb: &safeflow.RollbackReport{
				SnapshotID: "api-1726920000000000002",
				Error:      safeflow.ErrRollbackImageMissing.Error(),
			},
			want: "restore of snapshot api-1726920000000000002 failed: safeflow: snapshot image missing on host",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, rollbackCell(tc.rb))
		})
	}
}

func TestStartedAtCell(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want string
	}{
		{"zero time renders unknown", time.Time{}, "unknown"},
		{
			name: "utc time renders rfc3339",
			in:   time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
			want: "2026-09-21T12:00:00Z",
		},
		{
			name: "non-utc zone is converted to utc",
			in:   time.Date(2026, 9, 21, 14, 0, 0, 0, time.FixedZone("CEST", 2*60*60)),
			want: "2026-09-21T12:00:00Z",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, startedAtCell(tc.in))
		})
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"zero", 0, "0s"},
		{"negative clamps to 0s", -90 * time.Second, "0s"},
		{"sub-second rounds down to 0s", 400 * time.Millisecond, "0s"},
		{"half-second rounds away from zero", 500 * time.Millisecond, "1s"},
		{"1.5s rounds up", 1500 * time.Millisecond, "2s"},
		{"whole seconds", 12 * time.Second, "12s"},
		{"minute-plus keeps seconds", 65 * time.Second, "1m5s"},
		{"exact minute", 60 * time.Second, "1m0s"},
		{"hour-plus", 90 * time.Minute, "1h30m0s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, formatDuration(tc.d))
		})
	}
}

func TestColumnWidths(t *testing.T) {
	header := []string{"NAME", "STATUS", "IMAGE", "PRECHECK", "HEALTH", "ROLLBACK", "ERROR"}

	t.Run("header only", func(t *testing.T) {
		w := columnWidths(header, nil)
		require.Len(t, w, 7)
		for i, h := range header {
			assert.Equal(t, len(h), w[i], "column %d", i)
		}
	})

	t.Run("longer data cell grows its column, shorter does not shrink it", func(t *testing.T) {
		rows := [][]string{
			{"very-long-container-name", "fresh", "img", "x", "y", "z", ""},
			{"a", "updated", "an-even-longer-image-reference:tag", "x", "y", "z", ""},
		}
		w := columnWidths(header, rows)
		assert.Equal(t, len("very-long-container-name"), w[0], "grows to the longest name")
		assert.Equal(t, len("an-even-longer-image-reference:tag"), w[2], "grows to the longest image ref")
		assert.Equal(t, len("updated"), w[1], "longer data cell wins over header width")
		assert.Equal(t, len("ERROR"), w[6], "empty cells never grow a column")
	})
}

func TestPaddedRow(t *testing.T) {
	t.Run("first six columns padded, last verbatim", func(t *testing.T) {
		cells := []string{"web", "updated", "img", "pc", "h", "rb", "boom"}
		widths := []int{6, 10, 4, 8, 6, 4, 2}
		rv := paddedRow(cells, widths)
		assert.Equal(t, "web   ", rv.Name, "padded to width 6")
		assert.Equal(t, "updated   ", rv.Status, "padded to width 10")
		assert.Equal(t, "img ", rv.Image, "padded to width 4")
		assert.Equal(t, "boom", rv.Error, "last column never padded (width 2 ignored)")
	})

	t.Run("cell already at width gets no padding", func(t *testing.T) {
		rv := paddedRow([]string{"webserver", "updated", "i", "p", "h", "r", "e"}, []int{9, 7, 1, 1, 1, 1, 1})
		assert.Equal(t, "webserver", rv.Name)
		assert.Equal(t, "updated", rv.Status)
	})

	t.Run("shorter row than widths is defensive, missing cells empty", func(t *testing.T) {
		rv := paddedRow([]string{"web", "updated"}, []int{6, 10, 4, 8, 6, 4, 2})
		assert.Equal(t, "web   ", rv.Name)
		assert.Equal(t, "updated", rv.Status, "last present cell verbatim")
		assert.Empty(t, rv.Image)
		assert.Empty(t, rv.Error)
	})

	t.Run("widths shorter than cells emit verbatim", func(t *testing.T) {
		rv := paddedRow([]string{"web", "updated", "img", "pc", "h", "rb", "boom"}, []int{3})
		assert.Equal(t, "web", rv.Name)
		assert.Equal(t, "updated", rv.Status)
		assert.Equal(t, "boom", rv.Error)
	})
}

// rowCells flattens a rowView for column-wise assertions.
func rowCells(rv rowView) []string {
	return []string{rv.Name, rv.Status, rv.Image, rv.Precheck, rv.Health, rv.Rollback, rv.Error}
}

func TestBuildCycleView(t *testing.T) {
	t.Run("empty cycle has no rows and count zero", func(t *testing.T) {
		v := buildCycleView(safeflow.CycleReport{}, "subj")
		assert.Empty(t, v.Rows)
		assert.Zero(t, v.Count)
		assert.Equal(t, "subj", v.Subject)
		assert.Equal(t, "unknown", v.StartedAt, "zero StartedAt")
	})

	t.Run("header shares padding with data rows and columns align", func(t *testing.T) {
		cycle := safeflow.CycleReport{
			StartedAt: cycleStart,
			Updates: []safeflow.ContainerReport{
				{
					ContainerName: "very-long-container-name",
					Status:        safeflow.StatusFailed,
					OldImageRef:   "a:1",
					NewImageRef:   "a:2",
					Error:         "boom",
				},
				{ContainerName: "db", Status: safeflow.StatusFresh},
			},
		}
		v := buildCycleView(cycle, "subj")
		require.Len(t, v.Rows, 3, "header + two data rows")
		assert.Equal(t, 2, v.Count, "Count counts containers, not view rows")
		assert.Equal(t, cycleStart.Format(time.RFC3339), v.StartedAt)

		// Column alignment: every padded column (0..5) has one fixed width
		// across ALL rows including the header; the last column is verbatim.
		for col := 0; col < 6; col++ {
			want := len(rowCells(v.Rows[0])[col])
			for _, rv := range v.Rows {
				assert.Len(t, rowCells(rv)[col], want, "column %d must align across rows", col)
			}
		}
		// The data value longer than the header defines the column width.
		assert.Len(t, rowCells(v.Rows[0])[0], len("very-long-container-name"))
		assert.LessOrEqual(t, len(rowCells(v.Rows[2])[6]), len("boom"), "last column unpadded")
	})

	t.Run("every optional sub-structure missing becomes placeholder", func(t *testing.T) {
		v := buildCycleView(safeflow.CycleReport{
			Updates: []safeflow.ContainerReport{{ContainerName: "bare", Status: safeflow.StatusFresh}},
		}, "subj")
		require.Len(t, v.Rows, 2)
		data := rowCells(v.Rows[1])
		// Padded cells carry trailing pad spaces; compare the trimmed value.
		// image, precheck, health, rollback and error are placeholders.
		assert.Equal(t, placeholder, strings.TrimSpace(data[2]))
		assert.Equal(t, placeholder, strings.TrimSpace(data[3]))
		assert.Equal(t, placeholder, strings.TrimSpace(data[4]))
		assert.Equal(t, placeholder, strings.TrimSpace(data[5]))
		assert.Equal(t, placeholder, strings.TrimSpace(data[6]))
		assert.Equal(t, "fresh", strings.TrimSpace(data[1]))
	})

	t.Run("empty name and empty status become placeholders", func(t *testing.T) {
		v := buildCycleView(safeflow.CycleReport{
			Updates: []safeflow.ContainerReport{{}},
		}, "subj")
		require.Len(t, v.Rows, 2)
		data := rowCells(v.Rows[1])
		assert.Equal(t, placeholder, strings.TrimSpace(data[0]), "empty container name")
		assert.Equal(t, placeholder, strings.TrimSpace(data[1]), "empty status")
	})
}

func TestSubjectLineCounts(t *testing.T) {
	mk := func(status safeflow.ContainerStatus, n int) []safeflow.ContainerReport {
		out := make([]safeflow.ContainerReport, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, safeflow.ContainerReport{Status: status})
		}
		return out
	}
	cases := []struct {
		name   string
		status safeflow.ContainerStatus
		count  int
		want   string
	}{
		{"multiple updated", safeflow.StatusUpdated, 2, "drydock: 2 updated"},
		{"multiple failed only", safeflow.StatusFailed, 3, "drydock: 3 failed"},
		{"multiple rolled back only", safeflow.StatusRolledBack, 4, "drydock: 4 rolled back"},
		{"fresh never appears in subject", safeflow.StatusFresh, 7, "drydock: no changes"},
		{"skipped never appears in subject", safeflow.StatusSkipped, 7, "drydock: no changes"},
		{"unknown status is counted nowhere", safeflow.ContainerStatus("bogus"), 5, "drydock: no changes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := safeflow.CycleReport{Updates: mk(tc.status, tc.count)}
			assert.Equal(t, tc.want, subjectLine(c))
		})
	}

	t.Run("all three terms in fixed order", func(t *testing.T) {
		c := safeflow.CycleReport{Updates: append(append(
			mk(safeflow.StatusRolledBack, 4),
			mk(safeflow.StatusFailed, 3)...),
			mk(safeflow.StatusUpdated, 2)...)}
		assert.Equal(t, "drydock: 2 updated, 3 failed, 4 rolled back", subjectLine(c))
	})
}

func TestNotifiablePerStatus(t *testing.T) {
	cases := []struct {
		status safeflow.ContainerStatus
		want   bool
	}{
		{safeflow.StatusFresh, false},
		{safeflow.StatusSkipped, false},
		{safeflow.StatusUpdated, true},
		{safeflow.StatusFailed, true},
		{safeflow.StatusRolledBack, true},
		{safeflow.ContainerStatus("bogus"), false},
	}
	for _, tc := range cases {
		t.Run(string(tc.status), func(t *testing.T) {
			c := safeflow.CycleReport{Updates: []safeflow.ContainerReport{{Status: tc.status}}}
			assert.Equal(t, tc.want, notifiable(c))
		})
	}
}
