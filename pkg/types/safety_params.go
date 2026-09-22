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

package types

import (
	"time"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// SafetyLoop carries Drydock's update safety loop (precheck -> snapshot ->
// update -> health gate -> rollback) through UpdateParams into the update
// flow. It is composed exclusively in the cmd layer (the safeflow
// zero-conflict rule): cmd constructs the concrete pkg/precheck,
// pkg/rollback, pkg/healthgate components and hands them over here.
//
// A nil *SafetyLoop in UpdateParams (the zero value, and the shape every
// pre-Drydock caller uses) disables all five stages, which is exactly
// upstream watchtower behavior.
//
// Stage switches: PrecheckEnabled/SnapshotEnabled gate their stages
// independently (--precheck / --snapshot); the health gate runs whenever
// HealthGater is non-nil (the cmd layer leaves it nil under
// --health-gate=false, restoring plain upstream update behavior);
// RollbackOnUnhealthy additionally requires a snapshot for the container at
// runtime. Nil components disable their stage regardless of the switches,
// so partial wiring degrades gracefully.
type SafetyLoop struct {
	// PrecheckEnabled mirrors --precheck. false falls back to watchtower-
	// equivalent behavior (no policy gate; UpdateReport precheck verdicts
	// are absent rather than nil-per-container).
	PrecheckEnabled bool

	// SnapshotEnabled mirrors --snapshot. When false no snapshot is taken
	// and rollback has nothing to restore from (cmd startup validation
	// rejects --snapshot=false together with RollbackOnUnhealthy).
	SnapshotEnabled bool

	// RollbackOnUnhealthy mirrors --rollback-on-unhealthy. When false a
	// failed gate only marks the container failed; the replacement container
	// is left as-is for manual intervention and the old image is never
	// cleaned for it.
	RollbackOnUnhealthy bool

	// Prechecker evaluates the per-container update policy. Nil disables
	// the gate even when PrecheckEnabled is true.
	Prechecker safeflow.Prechecker

	// Snapshotter records pre-update snapshots. Nil disables the stage.
	Snapshotter safeflow.Snapshotter

	// SnapshotKeep mirrors --snapshot-keep: how many snapshots to retain per
	// container after a successful (healthy) update. <= 0 deletes all
	// snapshots for the container after success.
	SnapshotKeep int

	// HealthGater gates freshly recreated containers. Nil disables the gate.
	HealthGater safeflow.HealthGater

	// GateTimeout mirrors --health-timeout; GateInterval mirrors
	// --health-interval. Non-positive values fall back to the healthgate
	// package defaults.
	GateTimeout  time.Duration
	GateInterval time.Duration

	// Rollbacker restores a container from its pre-update snapshot. Nil
	// disables rollback even when RollbackOnUnhealthy is true.
	Rollbacker safeflow.Rollbacker

	// Cycle accumulates the safeflow view of one update cycle. The cmd layer
	// allocates a fresh Cycle (StartedAt set) per cycle before calling
	// actions.Update and reads it afterwards to drive the safeflow.Reporter.
	// actions.Update fills Updates entries as containers progress; it is
	// shared through the pointer, so every UpdateParams copy observes it.
	Cycle *safeflow.CycleReport
}

// GateActive reports whether the health-gate stage will run.
func (s *SafetyLoop) GateActive() bool {
	return s != nil && s.HealthGater != nil
}

// PrecheckActive reports whether the pre-update policy gate will run.
func (s *SafetyLoop) PrecheckActive() bool {
	return s != nil && s.PrecheckEnabled && s.Prechecker != nil
}

// SnapshotActive reports whether the pre-update snapshot stage will run.
func (s *SafetyLoop) SnapshotActive() bool {
	return s != nil && s.SnapshotEnabled && s.Snapshotter != nil
}

// RollbackActive reports whether an unhealthy gate verdict may trigger a
// rollback. A runtime snapshot is still required per container.
func (s *SafetyLoop) RollbackActive() bool {
	return s != nil && s.RollbackOnUnhealthy && s.Rollbacker != nil
}
