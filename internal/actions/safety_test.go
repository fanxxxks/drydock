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

package actions_test

// Integration tests for the Drydock safety loop wired into actions.Update:
// precheck -> snapshot -> (upstream stop/recreate) -> health gate ->
// rollback. The safeflow components are fakes recording their calls; the
// docker side is the upstream MockClient. These tests prove the wiring
// (ordering, verdict plumbing, report contents), not the components - those
// carry their own suites in pkg/precheck, pkg/rollback, pkg/healthgate and
// pkg/updatereport.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	dockerTypes "github.com/docker/docker/api/types"
	dockerContainer "github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drydock-updater/drydock/internal/actions"
	. "github.com/drydock-updater/drydock/internal/actions/mocks"
	"github.com/drydock-updater/drydock/pkg/safeflow"
	"github.com/drydock-updater/drydock/pkg/types"
)

// eventLog records the stage sequence across all fakes of one cycle.
type eventLog struct{ events []string }

func (l *eventLog) record(format string, args ...interface{}) {
	l.events = append(l.events, fmt.Sprintf(format, args...))
}

type fakePrechecker struct {
	log      *eventLog
	verdict  safeflow.PrecheckVerdict
	err      error
	requests []safeflow.PrecheckRequest
}

func (f *fakePrechecker) Precheck(_ context.Context, req safeflow.PrecheckRequest) (safeflow.PrecheckVerdict, error) {
	f.log.record("precheck:%s", req.ContainerName)
	f.requests = append(f.requests, req)
	return f.verdict, f.err
}

type fakeSnapshotter struct {
	log    *eventLog
	snap   safeflow.Snapshot
	err    error
	taken  []string
	pruned []string
}

func (f *fakeSnapshotter) Take(_ context.Context, inspect dockerTypes.ContainerJSON) (safeflow.Snapshot, error) {
	name := strings.TrimPrefix(inspect.Name, "/")
	f.log.record("snapshot:%s", name)
	f.taken = append(f.taken, name)
	if f.err != nil {
		return safeflow.Snapshot{}, f.err
	}
	snap := f.snap
	snap.ContainerName = name
	return snap, nil
}

func (f *fakeSnapshotter) Latest(_ context.Context, _ string) (safeflow.Snapshot, bool, error) {
	return safeflow.Snapshot{}, false, nil
}

func (f *fakeSnapshotter) Prune(_ context.Context, name string, _ int) error {
	f.log.record("prune:%s", name)
	f.pruned = append(f.pruned, name)
	return nil
}

type fakeGater struct {
	log    *eventLog
	result safeflow.HealthResult
	err    error
	calls  []string
}

func (f *fakeGater) AwaitHealthy(_ context.Context, containerID string, _ safeflow.GateOptions) (safeflow.HealthResult, error) {
	f.log.record("gate:%s", containerID)
	f.calls = append(f.calls, containerID)
	return f.result, f.err
}

type fakeRollbacker struct {
	log   *eventLog
	id    string
	err   error
	calls []safeflow.Snapshot
}

func (f *fakeRollbacker) Rollback(_ context.Context, snapshot safeflow.Snapshot) (string, error) {
	f.log.record("rollback:%s", snapshot.ID)
	f.calls = append(f.calls, snapshot)
	return f.id, f.err
}

// safetyFixture assembles one Update call with the safety loop wired to the
// fakes above, around a single running stale container.
func safetyFixture(t *testing.T) (client MockClient, log *eventLog, pre *fakePrechecker, snap *fakeSnapshotter, gate *fakeGater, rb *fakeRollbacker, params types.UpdateParams) {
	t.Helper()

	log = &eventLog{}
	pre = &fakePrechecker{
		log: log,
		verdict: safeflow.PrecheckVerdict{
			Allow:  true,
			Reason: safeflow.PrecheckAllowed,
		},
	}
	snap = &fakeSnapshotter{
		log:  log,
		snap: safeflow.Snapshot{ID: "web-1700000000000000000"},
	}
	gate = &fakeGater{
		log: log,
		result: safeflow.HealthResult{
			Status: safeflow.HealthHealthy,
			Reason: "healthcheck reported healthy",
		},
	}
	rb = &fakeRollbacker{log: log, id: "restored-container-id"}

	container := CreateMockContainerWithConfig(
		"c79web",
		"/web",
		"fake-image:latest",
		true, // running: the gate only judges replacements of running containers
		false,
		time.Now(),
		&dockerContainer.Config{
			Image:        "fake-image:latest",
			Labels:       map[string]string{},
			ExposedPorts: map[nat.Port]struct{}{},
		})

	client = CreateMockClient(&TestData{
		Containers: []types.Container{container},
	}, false, false)

	params = types.UpdateParams{
		Safety: &types.SafetyLoop{
			PrecheckEnabled:     true,
			SnapshotEnabled:     true,
			RollbackOnUnhealthy: true,
			Prechecker:          pre,
			Snapshotter:         snap,
			SnapshotKeep:        3,
			HealthGater:         gate,
			Rollbacker:          rb,
			GateTimeout:         time.Second,
			GateInterval:        100 * time.Millisecond,
			Cycle:               &safeflow.CycleReport{StartedAt: time.Now()},
		},
	}
	return client, log, pre, snap, gate, rb, params
}

func TestSafetyLoopHappyPath(t *testing.T) {
	client, log, pre, _, _, rb, params := safetyFixture(t)

	report, err := actions.Update(client, params)
	require.NoError(t, err)

	// Session view: the container was updated.
	require.Len(t, report.Updated(), 1)

	// Stage order: precheck before snapshot before gate; no rollback; the
	// healthy verdict prunes the snapshot store.
	require.Equal(t, []string{
		"precheck:web",
		"snapshot:web",
		"gate:",
		"prune:web",
	}, log.events)

	// The precheck request carried both image refs.
	require.Len(t, pre.requests, 1)
	assert.Equal(t, "web", pre.requests[0].ContainerName)
	assert.Equal(t, "c79web", pre.requests[0].ContainerID)
	assert.Equal(t, "fake-image:latest", pre.requests[0].CurrentImageRef)
	assert.Equal(t, "fake-image:latest", pre.requests[0].TargetImageRef)

	// Cycle report: updated, verdict + snapshot ID + health attached.
	require.Len(t, params.Safety.Cycle.Updates, 1)
	entry := params.Safety.Cycle.Updates[0]
	assert.Equal(t, safeflow.StatusUpdated, entry.Status)
	require.NotNil(t, entry.Precheck)
	assert.Equal(t, safeflow.PrecheckAllowed, entry.Precheck.Reason)
	assert.Equal(t, "web-1700000000000000000", entry.SnapshotID)
	require.NotNil(t, entry.Health)
	assert.Equal(t, safeflow.HealthHealthy, entry.Health.Status)
	assert.Nil(t, entry.Rollback)
	assert.Empty(t, entry.Error)

	assert.Empty(t, rb.calls)
}

func TestSafetyLoopPrecheckVetoSkipsContainer(t *testing.T) {
	client, log, _, _, _, rb, params := safetyFixture(t)
	params.Safety.Prechecker = &fakePrechecker{
		log: log,
		verdict: safeflow.PrecheckVerdict{
			Allow:  false,
			Reason: safeflow.PrecheckBlockedMajor,
			Detail: `major version bump "1.9.0" -> "2.0.0" vetoed by --block-major`,
		},
	}

	report, err := actions.Update(client, params)
	require.NoError(t, err)

	// Session view: skipped with the veto reason.
	require.Len(t, report.Skipped(), 1)
	assert.Contains(t, report.Skipped()[0].Error(), "vetoed by --block-major")

	// Nothing beyond the precheck ran: no snapshot, no stop/remove, no gate.
	assert.Equal(t, []string{"precheck:web"}, log.events)
	assert.Empty(t, rb.calls)
	assert.Equal(t, 0, client.TestData.TriedToRemoveImageCount)

	// Cycle view: skipped with the verdict attached.
	require.Len(t, params.Safety.Cycle.Updates, 1)
	entry := params.Safety.Cycle.Updates[0]
	assert.Equal(t, safeflow.StatusSkipped, entry.Status)
	require.NotNil(t, entry.Precheck)
	assert.Equal(t, safeflow.PrecheckBlockedMajor, entry.Precheck.Reason)
	assert.Empty(t, entry.SnapshotID)
}

func TestSafetyLoopUnhealthyTriggersRollback(t *testing.T) {
	client, log, _, _, gate, rb, params := safetyFixture(t)
	gate.result = safeflow.HealthResult{
		Status: safeflow.HealthUnhealthy,
		Reason: "healthcheck reported unhealthy",
	}
	gate.err = fmt.Errorf("%w: container web: healthcheck reported unhealthy", safeflow.ErrUnhealthy)

	report, err := actions.Update(client, params)
	require.NoError(t, err)

	// Session view: the update attempt failed (and its old image was never
	// a cleanup candidate).
	require.Len(t, report.Failed(), 1)
	assert.Contains(t, report.Failed()[0].Error(), "rolled back from snapshot")
	assert.Equal(t, 0, client.TestData.TriedToRemoveImageCount)

	// The rollbacker restored from the snapshot taken this cycle.
	require.Len(t, rb.calls, 1)
	assert.Equal(t, "web-1700000000000000000", rb.calls[0].ID)

	require.Equal(t, []string{
		"precheck:web",
		"snapshot:web",
		"gate:",
		"rollback:web-1700000000000000000",
	}, log.events)

	// Cycle view: rolled back, health + rollback reports attached, the
	// container runs its old ref again.
	require.Len(t, params.Safety.Cycle.Updates, 1)
	entry := params.Safety.Cycle.Updates[0]
	assert.Equal(t, safeflow.StatusRolledBack, entry.Status)
	require.NotNil(t, entry.Health)
	assert.Equal(t, safeflow.HealthUnhealthy, entry.Health.Status)
	require.NotNil(t, entry.Rollback)
	assert.Equal(t, "web-1700000000000000000", entry.Rollback.SnapshotID)
	assert.Equal(t, "restored-container-id", entry.Rollback.RestoredContainerID)
	assert.Empty(t, entry.Rollback.Error)
}

func TestSafetyLoopUnhealthyWithoutRollbackFlag(t *testing.T) {
	client, _, _, _, gate, rb, params := safetyFixture(t)
	params.Safety.RollbackOnUnhealthy = false
	gate.err = fmt.Errorf("%w: container web: healthcheck reported unhealthy", safeflow.ErrUnhealthy)

	report, err := actions.Update(client, params)
	require.NoError(t, err)

	require.Len(t, report.Failed(), 1)
	assert.Empty(t, rb.calls) // rollbacker never invoked

	entry := params.Safety.Cycle.Updates[0]
	assert.Equal(t, safeflow.StatusFailed, entry.Status)
	assert.Nil(t, entry.Rollback)
	assert.Contains(t, entry.Error, "unhealthy")
	// The replacement stays in place, so the cycle records the new ref.
	assert.Equal(t, "fake-image:latest", entry.NewImageRef)
}

func TestSafetyLoopRollbackFailureMarksFailed(t *testing.T) {
	client, _, _, _, gate, rb, params := safetyFixture(t)
	gate.err = fmt.Errorf("%w: container web: healthcheck reported unhealthy", safeflow.ErrUnhealthy)
	rb.err = errors.New("rollback: creating restored container \"web\": boom")

	report, err := actions.Update(client, params)
	require.NoError(t, err)

	require.Len(t, report.Failed(), 1)

	entry := params.Safety.Cycle.Updates[0]
	assert.Equal(t, safeflow.StatusFailed, entry.Status)
	require.NotNil(t, entry.Rollback)
	assert.Contains(t, entry.Rollback.Error, "boom")
	assert.Contains(t, entry.Error, "rollback failed")
}

func TestSafetyLoopDisabledKeepsUpstreamBehavior(t *testing.T) {
	// Safety nil: the exact upstream flow, and no cycle bookkeeping.
	client := CreateMockClient(&TestData{
		Containers: []types.Container{
			CreateMockContainer("test-container-01", "test-container-01", "fake-image:latest", time.Now()),
		},
	}, false, false)

	report, err := actions.Update(client, types.UpdateParams{Cleanup: true})
	require.NoError(t, err)
	assert.Len(t, report.Updated(), 1)
	assert.Equal(t, 1, client.TestData.TriedToRemoveImageCount)
}

func TestSafetyLoopFreshContainerReportsFresh(t *testing.T) {
	client, _, _, snap, gate, _, params := safetyFixture(t)
	client.TestData.Staleness = map[string]bool{"/web": false}

	report, err := actions.Update(client, params)
	require.NoError(t, err)
	// The session's fresh classification compares image IDs, which the mock
	// leaves empty; the authoritative check here is the cycle entry below.
	require.NotEmpty(t, report.All())

	// No stages ran beyond the scan (precheck only sees updating containers).
	assert.Empty(t, snap.taken)
	assert.Empty(t, gate.calls)

	entry := params.Safety.Cycle.Updates[0]
	assert.Equal(t, safeflow.StatusFresh, entry.Status)
	assert.Nil(t, entry.Precheck)
}
