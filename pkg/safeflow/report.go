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

package safeflow

import (
	"context"
	"time"
)

// This file extends the shared-contract surface started in safeflow.go with
// the reporting types consumed by pkg/updatereport (the fourth v0.1 feature
// package). safeflow.go itself is frozen; new contract types are appended
// here so the zero-conflict rule (feature packages import safeflow, the
// standard library and upstream dependencies only) keeps holding.
//
// The shapes mirror what the upstream update flow already reports per
// container (internal/actions/update.go: UpdateReport appended per container,
// t.Report passed to SendNotification at internal/actions/update.go:193-200)
// plus the Drydock safety-loop outcomes that upstream cannot express
// (precheck verdicts, health-gate results, rollbacks).

// ContainerStatus is the terminal outcome of one container within one update
// cycle. Statuses are mutually exclusive per container; a container whose
// update failed the health gate and was successfully restored reports
// StatusRolledBack (the restore details live in ContainerReport.Rollback).
type ContainerStatus string

const (
	// StatusFresh means the running container already used the newest image;
	// nothing was pulled or recreated (upstream "fresh" scan result).
	StatusFresh ContainerStatus = "fresh"

	// StatusSkipped means the container was stale but the update was vetoed
	// (precheck verdict Allow=false) or opted out via LabelPrecheck.
	StatusSkipped ContainerStatus = "skipped"

	// StatusUpdated means the container was recreated on a newer image and
	// passed the health gate.
	StatusUpdated ContainerStatus = "updated"

	// StatusFailed means the update attempt errored (pull failure, recreate
	// failure, health gate timeout/unhealthy without a completed rollback).
	StatusFailed ContainerStatus = "failed"

	// StatusRolledBack means the update was attempted, judged unhealthy, and
	// the pre-update snapshot was restored via the Rollbacker.
	StatusRolledBack ContainerStatus = "rolled-back"
)

// RollbackReport records the outcome of restoring one container from its
// pre-update Snapshot along the Rollbacker path. A nil *RollbackReport in a
// ContainerReport means no rollback was attempted for that container.
type RollbackReport struct {
	// SnapshotID is the ID of the safeflow.Snapshot the container was
	// restored from (format "<containerName>-<unixnano>", see Snapshot).
	SnapshotID string
	// RestoredContainerID is the ID of the recreated (old-image) container;
	// "" when the rollback itself failed before ContainerStart returned.
	RestoredContainerID string
	// Error is the rollback failure message; "" on a successful restore.
	// Errors here wrap ErrRollbackImageMissing or ErrSnapshotInvalid when
	// applicable (the sentinel text is preserved by the Rollbacker).
	Error string
}

// ContainerReport is the per-container slice of one cycle's outcome. Every
// pointer field may be nil: reporters must render nil sub-structures as an
// explicit placeholder rather than dereferencing them.
type ContainerReport struct {
	ContainerName string
	Status        ContainerStatus
	OldImageRef   string // ref the container ran before the cycle ("" unknown)
	NewImageRef   string // ref the container runs after the cycle ("" when not recreated)
	// SnapshotID is the pre-update snapshot recorded for this container (""
	// when the snapshot stage is disabled, not applicable, or failed). It is
	// report data only; the restore path always reads the snapshot it is
	// handed. Added by the v0.1 cmd wiring so cycle notifications carry the
	// snapshot identifier even for healthy updates.
	SnapshotID string
	Precheck   *PrecheckVerdict
	Health     *HealthResult
	Rollback   *RollbackReport
	Error      string // terminal error for StatusFailed / failed rollback; "" otherwise
}

// CycleReport is the aggregate handed to a Reporter when a cycle finishes.
// Field types are deliberately map-free so encoding/json marshals them with
// a stable, diffable field order.
type CycleReport struct {
	StartedAt time.Time
	Updates   []ContainerReport // may be empty; never contains nil entries by contract
}

// Reporter summarizes one completed update cycle. Implementations render a
// human-readable summary (always written to the console), emit a
// machine-readable form, and deliver notifications through their configured
// sender only when the cycle contains at least one StatusUpdated,
// StatusFailed or StatusRolledBack container (silence rule for all-quiet
// cycles, cf. upstream pain watchtower#1962/#1313).
//
// Delivery failures are logged, never returned: the error return is
// reserved for rendering/template programmer errors.
type Reporter interface {
	Report(ctx context.Context, cycle CycleReport) error
}
