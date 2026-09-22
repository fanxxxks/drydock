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

// Package safeflow defines the shared contracts for Drydock's update safety
// loop: precheck -> snapshot -> update -> health gate -> rollback.
// Module: github.com/drydock-updater/drydock. This file is the single
// shared-contract surface for the four v0.1 feature packages.
//
// Interface shapes are sized to drop into the update flow mapped from the
// upstream containrrr/watchtower tree (cloned at D:\github\.upstream\watchtower):
//
//	Prechecker  -> internal/actions/update.go:36-38   (after IsContainerStale
//	               returned stale=true with the newest image ID and the image
//	               name incl. tag, before the shouldUpdate decision)
//	Snapshotter -> internal/actions/update.go:85-97   (before any container is
//	               stopped or rolling-restarted)
//	HealthGater -> internal/actions/update.go:224-228 (after StartContainer
//	               returned the new container ID, before post-update hooks and
//	               before cleanupImages at update.go:193-200)
//	Rollbacker  -> pkg/container/client.go:248-300    (the proven recreate
//	               path: create config -> ContainerCreate -> NetworkConnect
//	               -> ContainerStart)
//
// Zero-conflict rule for v0.1: pkg/precheck, pkg/rollback, pkg/healthgate and
// pkg/updatereport may import this package, the standard library and upstream
// dependencies only - never each other. Composition happens exclusively in
// the cmd layer.
package safeflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/docker/api/types"
)

// Container label keys consumed by more than one package.
const (
	// LabelPrecheck disables the policy gate for a single container. When the
	// label value parses via strconv.ParseBool to false ("false", "0", "f",
	// "F", "FALSE"...), the gate is bypassed for that container. Unset or
	// any other value keeps the gate active. This mirrors upstream's
	// label-driven veto philosophy (lifecycle exit code 75,
	// internal/actions/update.go:162-165, labels defined in
	// pkg/container/metadata.go:14-19).
	LabelPrecheck = "com.drydock.updater.precheck"
)

// Sentinel errors. Implementations wrap these with %w so callers can use
// errors.Is; tests assert against them.
var (
	// ErrHealthTimeout is returned by HealthGater when the gate window elapses
	// before the container reports healthy.
	ErrHealthTimeout = errors.New("safeflow: health gate timed out")

	// ErrUnhealthy is returned by HealthGater when the container reports an
	// unhealthy status or exits (non-running) during the gate window.
	ErrUnhealthy = errors.New("safeflow: container is unhealthy")

	// ErrSnapshotInvalid is returned by Snapshotter.Take when the supplied
	// inspect payload cannot produce a recreatable snapshot.
	ErrSnapshotInvalid = errors.New("safeflow: invalid container inspect for snapshot")

	// ErrRollbackImageMissing is returned by Rollbacker when the snapshot's
	// image is no longer present on the host (e.g. removed by an eager
	// cleanup) and therefore cannot serve a restore.
	ErrRollbackImageMissing = errors.New("safeflow: snapshot image missing on host")
)

// PrecheckRequest carries everything the pre-update policy gate decides on.
// All data is local: CurrentImageRef comes from the running container's
// inspect (Config.Image, cf. upstream ImageName pkg/container/container.go:104-116
// implying ":latest" when no tag); TargetImageRef, TargetImageLabels and
// TargetHasHealthcheck come from the freshly pulled image's ImageInspect
// (upstream already pulls before staleness is decided, IsContainerStale at
// pkg/container/client.go:319-329), so precheck adds no registry traffic.
type PrecheckRequest struct {
	ContainerID          string
	ContainerName        string
	CurrentImageRef      string            // e.g. "docker.io/library/nginx:1.25.3"
	TargetImageRef       string            // same repository, newer tag/digest
	ContainerLabels      map[string]string // may be nil
	TargetImageLabels    map[string]string // org.opencontainers.image.* if published; may be nil
	TargetHasHealthcheck bool              // target image defines a real HEALTHCHECK (test != ["NONE"])
}

// PrecheckReason is the machine-readable outcome of the policy gate.
type PrecheckReason string

const (
	PrecheckAllowed              PrecheckReason = "allowed"
	PrecheckBlockedMajor         PrecheckReason = "blocked-major"          // semver major bump and --block-major
	PrecheckBlockedPrerelease    PrecheckReason = "blocked-prerelease"     // target carries a -prerelease and --block-prerelease
	PrecheckBlockedUnknownTag    PrecheckReason = "blocked-unknown-tag"    // non-semver tag and --precheck-unknown-tag=block
	PrecheckBlockedNoHealthcheck PrecheckReason = "blocked-no-healthcheck" // --require-healthcheck and target lacks HEALTHCHECK
	PrecheckBypassed             PrecheckReason = "bypassed-by-label"      // per-container opt-out via LabelPrecheck
)

// PrecheckVerdict is the decision the orchestrator acts on. Allow=false
// means the update is vetoed for this cycle (container is left untouched,
// reported as StatusSkipped).
type PrecheckVerdict struct {
	Allow      bool
	Reason     PrecheckReason
	Detail     string   // human-readable explanation; non-empty whenever Allow=false
	CurrentTag string   // tag portion of CurrentImageRef ("" when digest-pinned or absent)
	TargetTag  string   // tag portion of TargetImageRef
	Semver     bool     // both tags parsed as semver
	MajorBump  bool     // target major > current major (only meaningful when Semver)
	Notes      []string // changelog/source metadata surfaced verbatim to reports; never a block reason
}

// Prechecker evaluates the update policy. Implementations must be
// deterministic and side-effect free; v0.1 implementations always return a
// nil error (the error return exists so v0.2 can add network-backed checks
// without changing the interface).
type Prechecker interface {
	Precheck(ctx context.Context, req PrecheckRequest) (PrecheckVerdict, error)
}

// Snapshot is a deep copy of a container's inspect state taken before any
// stop/update mutation, sufficient to recreate the container exactly
// (proven by upstream's recreate path, which derives create/host/network
// config purely from in-memory ContainerJSON: pkg/container/client.go:248-300).
//
// CRITICAL: upstream mutates the inspect payload in place in three spots -
// GetCreateConfig strips image defaults from Config (pkg/container/container.go:283-348),
// GetCreateHostConfig rewrites HostConfig.Links (container.go:352-363), and
// GetNetworkConfig strips container-ID aliases from EndpointSettings
// (client.go:226-246). Snapshotter.Take MUST deep-copy before any of those
// can run; the snapshot must never observe later mutations.
type Snapshot struct {
	ID            string    // unique within the store; format "<containerName>-<unixnano>"
	ContainerName string    // docker name without leading "/"; STABLE across recreates (container IDs are not)
	CreatedAt     time.Time // host clock at Take time
	Inspect       types.ContainerJSON
}

// ImageRef returns the image reference the snapshotted container was started
// with (Config.Image); "" when unknown. May carry no tag, in which case
// ":latest" is implied (upstream ImageName convention).
func (s Snapshot) ImageRef() string {
	if s.Inspect.Config == nil {
		return ""
	}
	return s.Inspect.Config.Image
}

// ImageID returns the local image ID ("sha256:...", ContainerJSONBase.Image)
// the snapshot pins; "" when the embedded base is absent.
func (s Snapshot) ImageID() string {
	if s.Inspect.ContainerJSONBase == nil {
		return ""
	}
	return s.Inspect.Image
}

// Validate reports whether the snapshot carries the minimum state needed to
// recreate the container.
func (s Snapshot) Validate() error {
	if s.ContainerName == "" {
		return fmt.Errorf("%w: empty container name", ErrSnapshotInvalid)
	}
	if s.Inspect.ContainerJSONBase == nil {
		return fmt.Errorf("%w: missing ContainerJSONBase", ErrSnapshotInvalid)
	}
	if s.Inspect.Config == nil {
		return fmt.Errorf("%w: nil Config", ErrSnapshotInvalid)
	}
	if s.Inspect.HostConfig == nil {
		return fmt.Errorf("%w: nil HostConfig", ErrSnapshotInvalid)
	}
	if s.ImageRef() == "" {
		return fmt.Errorf("%w: empty image reference", ErrSnapshotInvalid)
	}
	if s.ImageID() == "" {
		return fmt.Errorf("%w: empty image ID", ErrSnapshotInvalid)
	}
	return nil
}

// Snapshotter records and retrieves pre-update snapshots. Implementations
// persist snapshots as JSON files (stdlib encoding/json) under the
// --snapshot-dir, keyed by container NAME, written atomically (temp file +
// os.Rename), so a rollback survives a Drydock restart within the same host.
type Snapshotter interface {
	// Take deep-copies inspect (see the Snapshot doc comment), validates it
	// via Snapshot.Validate, persists it and returns it. An invalid payload
	// yields an error wrapping ErrSnapshotInvalid and nothing is persisted.
	Take(ctx context.Context, inspect types.ContainerJSON) (Snapshot, error)

	// Latest returns the most recent snapshot recorded for containerName.
	// (Snapshot{}, false, nil) when none exists - not an error.
	Latest(ctx context.Context, containerName string) (Snapshot, bool, error)

	// Prune keeps at most the newest `keep` snapshots for containerName and
	// deletes the rest; keep <= 0 deletes all snapshots for that name.
	Prune(ctx context.Context, containerName string, keep int) error
}

// HealthStatus is the gate's view of a container's health.
type HealthStatus string

const (
	HealthUnknown   HealthStatus = "unknown"  // image defines no HEALTHCHECK; gate judged by running state
	HealthStarting  HealthStatus = "starting" // healthcheck present, still starting at timeout
	HealthHealthy   HealthStatus = "healthy"
	HealthUnhealthy HealthStatus = "unhealthy" // healthcheck reported unhealthy
	HealthExited    HealthStatus = "exited"    // container stopped during the gate window
)

// HealthResult is the outcome of one gate window.
type HealthResult struct {
	Status     HealthStatus
	Reason     string        // last transition or failure cause; non-empty on non-healthy outcomes
	Checks     int           // inspect polls performed (>= 1)
	ExitCode   int           // populated iff Status == HealthExited
	LastOutput string        // last healthcheck log output, truncated to 512 bytes; "" when none
	Elapsed    time.Duration // wall time spent inside the gate
}

// GateOptions tunes one gate window. Non-positive values mean "use the
// implementation default" (v0.1 defaults: 60s timeout, 5s interval, matching
// --health-timeout / --health-interval; the cmd layer always passes explicit
// values so defaults are a safety net for library consumers only).
type GateOptions struct {
	Timeout  time.Duration
	Interval time.Duration
}

// HealthGater blocks until the fresh container reports healthy or the gate
// window closes. Implementations poll the container with Docker inspect
// every opts.Interval for at most opts.Timeout and translate what they see
// into a HealthResult:
//
//   - image without a HEALTHCHECK: the gate passes once the container is
//     running (Status HealthUnknown, Reason noting the absent healthcheck);
//   - image with a HEALTHCHECK: the gate passes on HealthHealthy and fails
//     with an error wrapping ErrUnhealthy on HealthUnhealthy or HealthExited;
//   - the window closing before a verdict yields an error wrapping
//     ErrHealthTimeout (Status HealthStarting when a healthcheck exists).
//
// The gate only observes; it never restarts or mutates the container.
type HealthGater interface {
	// AwaitHealthy runs one gate window for containerID (the freshly started
	// replacement container). Non-healthy outcomes are reported both in the
	// returned HealthResult and via the error return, which wraps
	// ErrHealthTimeout or ErrUnhealthy so callers can branch with errors.Is.
	// Cancelling ctx aborts the window early.
	AwaitHealthy(ctx context.Context, containerID string, opts GateOptions) (HealthResult, error)
}

// Rollbacker restores a container from a pre-update Snapshot along the
// proven upstream recreate path (create config -> ContainerCreate ->
// NetworkConnect -> ContainerStart, pkg/container/client.go:248-300): the
// failed replacement is removed and the snapshot's container is recreated
// under its original name with its original image and configuration.
type Rollbacker interface {
	// Rollback recreates the container described by snapshot and returns the
	// new container ID. When the snapshot's image no longer exists on the
	// host the error wraps ErrRollbackImageMissing; an invalid snapshot
	// yields an error wrapping ErrSnapshotInvalid (via Snapshot.Validate).
	Rollback(ctx context.Context, snapshot Snapshot) (string, error)
}
