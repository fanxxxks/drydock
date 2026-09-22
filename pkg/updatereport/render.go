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
	"fmt"
	"strings"
	"time"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// placeholder is rendered wherever an optional sub-structure is absent.
const placeholder = "—"

const (
	subjectPrefix    = "drydock: "
	subjectNoChanges = "drydock: no changes"
)

// defaultTemplate is the single built-in layout (no user template flag in
// v0.1). One line per container: NAME, STATUS, old->new image ref,
// PRECHECK reason, HEALTH status+elapsed, ROLLBACK result, ERROR. The view
// pre-pads every column except the last so the template stays trivial and
// the output stays deterministic. The first row emitted through the range
// loop is the column header (see buildCycleView).
const defaultTemplate = `{{.Subject}} — drydock cycle {{.StartedAt}} ({{.Count}} containers)
{{if .Rows -}}
{{range .Rows}}{{.Name}}  {{.Status}}  {{.Image}}  {{.Precheck}}  {{.Health}}  {{.Rollback}}  {{.Error}}
{{end}}{{else}}no containers were in scope this cycle
{{end}}`

// rowView is one pre-formatted, column-padded report line.
type rowView struct {
	Name, Status, Image, Precheck, Health, Rollback, Error string
}

// cycleView is the template data for one cycle summary.
type cycleView struct {
	Subject   string
	StartedAt string
	Count     int
	Rows      []rowView
}

// render executes the default template. All cell strings are pre-built by
// buildCycleView, so execution itself cannot panic on nil input data.
func (r *Reporter) render(cycle safeflow.CycleReport, subject string) (string, error) {
	var buf bytes.Buffer
	if err := r.tpl.Execute(&buf, buildCycleView(cycle, subject)); err != nil {
		return "", fmt.Errorf("execute default template: %w", err)
	}
	return buf.String(), nil
}

// buildCycleView is a pure, panic-free projection of a CycleReport into the
// template view: every nil sub-structure and every empty string becomes the
// "—" placeholder, and an empty Updates slice yields a valid empty summary.
func buildCycleView(cycle safeflow.CycleReport, subject string) cycleView {
	header := []string{"NAME", "STATUS", "IMAGE", "PRECHECK", "HEALTH", "ROLLBACK", "ERROR"}
	rows := make([][]string, 0, len(cycle.Updates))
	for i := range cycle.Updates {
		u := &cycle.Updates[i]
		rows = append(rows, []string{
			orPlaceholder(u.ContainerName),
			orPlaceholder(string(u.Status)),
			imageCell(u),
			precheckCell(u.Precheck),
			healthCell(u.Health),
			rollbackCell(u.Rollback),
			orPlaceholder(u.Error),
		})
	}

	widths := columnWidths(header, rows)
	view := cycleView{
		Subject:   subject,
		StartedAt: startedAtCell(cycle.StartedAt),
		Count:     len(rows),
		Rows:      make([]rowView, 0, len(rows)+1),
	}
	if len(rows) == 0 {
		return view
	}
	// The header shares the range loop (and therefore the padding) with the
	// data rows.
	view.Rows = append(view.Rows, paddedRow(header, widths))
	for _, cells := range rows {
		view.Rows = append(view.Rows, paddedRow(cells, widths))
	}
	return view
}

// columnWidths computes the per-column width over the header and all rows.
func columnWidths(header []string, rows [][]string) []int {
	widths := make([]int, len(header))
	consider := func(cells []string) {
		for i, c := range cells {
			if i < len(widths) && len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	consider(header)
	for _, cells := range rows {
		consider(cells)
	}
	return widths
}

// paddedRow left-aligns every cell to its column width except the last
// column, which is emitted verbatim (no trailing whitespace).
func paddedRow(cells []string, widths []int) rowView {
	get := func(i int) string {
		if i >= len(cells) {
			return ""
		}
		if i >= len(widths) || i == len(cells)-1 {
			return cells[i]
		}
		return cells[i] + strings.Repeat(" ", widths[i]-len(cells[i]))
	}
	return rowView{
		Name:     get(0),
		Status:   get(1),
		Image:    get(2),
		Precheck: get(3),
		Health:   get(4),
		Rollback: get(5),
		Error:    get(6),
	}
}

// subjectLine builds the deterministic notification subject:
//
//	drydock: N updated, M failed, K rolled back
//
// Count-zero terms are omitted; when all three are zero (a cycle that can
// never trigger a send) the subject falls back to "drydock: no changes".
func subjectLine(cycle safeflow.CycleReport) string {
	var updated, failed, rolledBack int
	for i := range cycle.Updates {
		switch cycle.Updates[i].Status {
		case safeflow.StatusUpdated:
			updated++
		case safeflow.StatusFailed:
			failed++
		case safeflow.StatusRolledBack:
			rolledBack++
		}
	}
	var terms []string
	if updated > 0 {
		terms = append(terms, fmt.Sprintf("%d updated", updated))
	}
	if failed > 0 {
		terms = append(terms, fmt.Sprintf("%d failed", failed))
	}
	if rolledBack > 0 {
		terms = append(terms, fmt.Sprintf("%d rolled back", rolledBack))
	}
	if len(terms) == 0 {
		return subjectNoChanges
	}
	return subjectPrefix + strings.Join(terms, ", ")
}

// notifiable reports whether the cycle contains at least one container whose
// status warrants a notification (anything but fresh/skipped).
func notifiable(cycle safeflow.CycleReport) bool {
	for i := range cycle.Updates {
		switch cycle.Updates[i].Status {
		case safeflow.StatusUpdated, safeflow.StatusFailed, safeflow.StatusRolledBack:
			return true
		}
	}
	return false
}

func orPlaceholder(s string) string {
	if s == "" {
		return placeholder
	}
	return s
}

// imageCell renders "old -> new"; "—" when both sides are unknown.
func imageCell(u *safeflow.ContainerReport) string {
	if u.OldImageRef == "" && u.NewImageRef == "" {
		return placeholder
	}
	return orPlaceholder(u.OldImageRef) + " -> " + orPlaceholder(u.NewImageRef)
}

func precheckCell(v *safeflow.PrecheckVerdict) string {
	if v == nil {
		return placeholder
	}
	return orPlaceholder(string(v.Reason))
}

// healthCell renders the gate verdict as "<status> (<elapsed>)".
func healthCell(h *safeflow.HealthResult) string {
	if h == nil {
		return placeholder
	}
	return fmt.Sprintf("%s (%s)", orPlaceholder(string(h.Status)), formatDuration(h.Elapsed))
}

// rollbackCell renders the restore outcome, surfacing the snapshot ID so
// operators can correlate with pkg/snapshot state on disk.
func rollbackCell(rb *safeflow.RollbackReport) string {
	if rb == nil {
		return placeholder
	}
	snap := orPlaceholder(rb.SnapshotID)
	if rb.Error != "" {
		return fmt.Sprintf("restore of snapshot %s failed: %s", snap, rb.Error)
	}
	return fmt.Sprintf("restored from snapshot %s", snap)
}

func startedAtCell(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

// formatDuration renders a gate elapsed time in whole seconds ("12s",
// "1m5s"); durations are rounded, never negative-adjusted, and always
// deterministic for a given input.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	return d.Round(time.Second).String()
}
