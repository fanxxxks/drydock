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

package actions

// This file wires Drydock's four safety-loop feature packages into the
// upstream update flow at the seams mapped by the safeflow contract:
//
//	precheck  -> the staleness loop in update.go, after IsContainerStale
//	             decided stale=true and before the container is marked for
//	             update (runPrecheck);
//	snapshot  -> after sorting/marking, before any container is stopped
//	             (takeSafetySnapshots);
//	gate      -> restartStaleContainer, right after StartContainer returned
//	             the new container ID, before the post-update hooks and
//	             before cleanupImages (gateReplacement);
//	rollback  -> inside gateReplacement, only on a non-healthy verdict with
//	             --rollback-on-unhealthy and a snapshot available.
//
// Composition of the concrete components happens in the cmd layer; this file
// only orchestrates them around the untouched upstream stop/recreate path.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	dockercontainer "github.com/docker/docker/api/types/container"
	log "github.com/sirupsen/logrus"

	"github.com/drydock-updater/drydock/pkg/container"
	"github.com/drydock-updater/drydock/pkg/safeflow"
	"github.com/drydock-updater/drydock/pkg/types"
)

// containerName strips the leading "/" the docker daemon prepends to inspect
// names, matching safeflow.Snapshot.ContainerName's convention.
func containerName(c types.Container) string {
	return strings.TrimPrefix(c.Name(), "/")
}

// cycleEntry returns the safeflow cycle report entry for c, creating it on
// first touch. Entries are matched by (slash-stripped) container name: names
// are unique on a docker host and, unlike IDs, stable across recreates -
// the same key the snapshot store uses.
func cycleEntry(safety *types.SafetyLoop, c types.Container) *safeflow.ContainerReport {
	if safety.Cycle == nil {
		safety.Cycle = &safeflow.CycleReport{}
	}
	name := containerName(c)
	for i := range safety.Cycle.Updates {
		if safety.Cycle.Updates[i].ContainerName == name {
			return &safety.Cycle.Updates[i]
		}
	}
	safety.Cycle.Updates = append(safety.Cycle.Updates, safeflow.ContainerReport{
		ContainerName: name,
		OldImageRef:   inspectImageRef(c),
	})
	return &safety.Cycle.Updates[len(safety.Cycle.Updates)-1]
}

// inspectImageRef returns the image reference the container was created with
// (Config.Image, which may carry no tag); "" when the inspect payload is
// unavailable.
func inspectImageRef(c types.Container) string {
	ci := c.ContainerInfo()
	if ci == nil || ci.Config == nil {
		return ""
	}
	return ci.Config.Image
}

// markCycleFailed records a terminal failure on c's cycle entry. A nil
// safety (upstream-only callers) is a no-op.
func markCycleFailed(safety *types.SafetyLoop, c types.Container, err error) {
	if safety == nil {
		return
	}
	entry := cycleEntry(safety, c)
	entry.Status = safeflow.StatusFailed
	entry.Error = err.Error()
}

// markCycleSkipped records a deliberate skip (update vetoed or opted out) on
// c's cycle entry. A nil safety is a no-op.
func markCycleSkipped(safety *types.SafetyLoop, c types.Container) {
	if safety == nil {
		return
	}
	cycleEntry(safety, c).Status = safeflow.StatusSkipped
}

// isRunningBeforeUpdate reports whether the container was running before the
// update. It is nil-safe against inspect payloads without state (every real
// docker inspect carries one; test mocks may not).
func isRunningBeforeUpdate(c types.Container) bool {
	ci := c.ContainerInfo()
	return ci != nil && ci.State != nil && ci.State.Running
}

// buildPrecheckRequest assembles the policy gate input for a stale
// container. Everything is local: the current ref and labels come from the
// running container's inspect, the target side from the freshly pulled
// image's local inspect (upstream already pulled it inside
// IsContainerStale), so precheck adds no registry traffic.
func buildPrecheckRequest(ctx context.Context, client container.Client, target types.Container) safeflow.PrecheckRequest {
	req := safeflow.PrecheckRequest{
		ContainerID:    string(target.ID()),
		ContainerName:  containerName(target),
		TargetImageRef: target.ImageName(),
	}
	ci := target.ContainerInfo()
	if ci != nil && ci.Config != nil {
		req.CurrentImageRef = ci.Config.Image
		req.ContainerLabels = ci.Config.Labels
	}
	if info, err := client.InspectImage(ctx, req.TargetImageRef); err != nil {
		// The image is on the host (it was just pulled); an inspect failure
		// is transient daemon trouble. Precheck then sees no labels and no
		// HEALTHCHECK, which only matters under --require-healthcheck.
		log.WithError(err).Warnf("Could not inspect target image %q for precheck; assuming no labels and no HEALTHCHECK", req.TargetImageRef)
	} else if info.Config != nil {
		req.TargetImageLabels = info.Config.Labels
		req.TargetHasHealthcheck = hasRealHealthcheck(info.Config.Healthcheck)
	}
	return req
}

// hasRealHealthcheck mirrors docker's semantics: a nil/empty HEALTHCHECK, or
// one whose test is exactly ["NONE"], does not define a healthcheck.
func hasRealHealthcheck(hc *dockercontainer.HealthConfig) bool {
	if hc == nil || len(hc.Test) == 0 {
		return false
	}
	return !(len(hc.Test) == 1 && hc.Test[0] == "NONE")
}

// runPrecheck evaluates the pre-update policy gate for a stale container.
// The returned verdict is always meaningful; the returned error is non-nil
// exactly when the update is vetoed. Following the upstream lifecycle-hook
// precedent (a failing pre-update command skips the container,
// internal/actions/update.go stopStaleContainer), a checker implementation
// error also vetoes the update for that container rather than letting it
// proceed unverified.
func runPrecheck(ctx context.Context, client container.Client, safety *types.SafetyLoop, target types.Container) (safeflow.PrecheckVerdict, error) {
	verdict, err := safety.Prechecker.Precheck(ctx, buildPrecheckRequest(ctx, client, target))
	if err != nil {
		return verdict, fmt.Errorf("precheck for %s failed: %w", target.Name(), err)
	}
	if !verdict.Allow {
		return verdict, errors.New(verdict.Detail)
	}
	return verdict, nil
}

// takeSafetySnapshots records a pre-update snapshot for every container that
// is about to be stopped and recreated (ToRestart: stale plus
// linked-to-restarting). The snapshot is taken from the container's live
// inspect payload BEFORE upstream's recreate helpers can mutate it in place
// (GetCreateConfig strips image defaults, GetCreateHostConfig rewrites
// links, GetNetworkConfig deletes container-ID aliases); the store deep-copies
// internally, but the timing here is what keeps the payload pristine.
//
// A snapshot failure is logged and the update proceeds without a restore
// point - an I/O error must not brick the updater - at the cost that the
// rollback stage will have nothing to restore for that container.
func takeSafetySnapshots(ctx context.Context, safety *types.SafetyLoop, containers []types.Container) map[types.ContainerID]safeflow.Snapshot {
	if !safety.SnapshotActive() {
		return nil
	}
	snaps := make(map[types.ContainerID]safeflow.Snapshot)
	for _, c := range containers {
		if !c.ToRestart() {
			continue
		}
		ci := c.ContainerInfo()
		if ci == nil {
			continue
		}
		snap, err := safety.Snapshotter.Take(ctx, *ci)
		if err != nil {
			log.WithError(err).Errorf("Failed to snapshot container %q before update; rollback will be unavailable for it this cycle", c.Name())
			continue
		}
		snaps[c.ID()] = snap
		cycleEntry(safety, c).SnapshotID = snap.ID
		log.WithFields(log.Fields{
			"container": snap.ContainerName,
			"snapshot":  snap.ID,
			"image":     snap.ImageRef(),
		}).Info("Recorded pre-update snapshot")
	}
	return snaps
}

// gateReplacement runs the health gate on the freshly started replacement
// and, on a non-healthy verdict, rolls the container back from its
// pre-update snapshot when --rollback-on-unhealthy is enabled and a
// snapshot exists. It finalizes the container's cycle entry and returns a
// non-nil error whenever the update did not stick, so the caller records the
// container as failed and keeps its old image out of the cleanup set.
//
// Containers that were not running before the update (include-stopped flows
// that do not revive) are recreated but never started, so there is nothing
// to gate; they pass and count as updated.
func gateReplacement(
	safety *types.SafetyLoop,
	c types.Container,
	newContainerID string,
	snaps map[types.ContainerID]safeflow.Snapshot,
	entry *safeflow.ContainerReport,
) error {
	if !safety.GateActive() || !isRunningBeforeUpdate(c) {
		return nil
	}
	ctx := context.Background()

	res, err := safety.HealthGater.AwaitHealthy(ctx, newContainerID, safeflow.GateOptions{
		Timeout:  safety.GateTimeout,
		Interval: safety.GateInterval,
	})
	entry.Health = &res
	entry.NewImageRef = c.ImageName()

	if err == nil {
		entry.Status = safeflow.StatusUpdated
		if safety.Snapshotter != nil {
			if perr := safety.Snapshotter.Prune(ctx, containerName(c), safety.SnapshotKeep); perr != nil {
				log.WithError(perr).Warnf("Failed to prune snapshots for %q", c.Name())
			}
		}
		return nil
	}

	log.WithError(err).Warnf("Health gate failed for updated container %q", c.Name())

	// Without an active rollback path the unhealthy replacement is left
	// as-is for manual intervention (StatusFailed), matching
	// --rollback-on-unhealthy=false semantics.
	snap, hasSnapshot := snaps[c.ID()]
	if !safety.RollbackActive() || !hasSnapshot {
		entry.Status = safeflow.StatusFailed
		entry.Error = err.Error()
		if safety.RollbackActive() {
			entry.Error = err.Error() + "; no pre-update snapshot available for rollback"
		}
		return fmt.Errorf("health gate failed for %s: %w", c.Name(), err)
	}

	restoredID, rbErr := safety.Rollbacker.Rollback(ctx, snap)
	rb := &safeflow.RollbackReport{
		SnapshotID:          snap.ID,
		RestoredContainerID: restoredID,
	}
	entry.Rollback = rb
	if rbErr != nil {
		rb.Error = rbErr.Error()
		entry.Status = safeflow.StatusFailed
		entry.Error = fmt.Sprintf("health gate failed: %v; rollback failed: %v", err, rbErr)
		log.WithError(rbErr).Errorf("Rollback of %q failed; unhealthy replacement left in place", c.Name())
		return fmt.Errorf("health gate failed for %s: %w (rollback failed: %v)", c.Name(), err, rbErr)
	}

	entry.Status = safeflow.StatusRolledBack
	entry.NewImageRef = snap.ImageRef()
	log.WithFields(log.Fields{
		"container": snap.ContainerName,
		"snapshot":  snap.ID,
		"restored":  restoredID,
	}).Info("Rolled back unhealthy container from pre-update snapshot")
	return fmt.Errorf("health gate failed for %s: %w (rolled back from snapshot %s)", c.Name(), err, snap.ID)
}
