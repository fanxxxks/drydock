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

package healthgate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/errdefs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// Wiring proof from the test side as well: the concrete Gater slots into the
// safeflow.HealthGater contract without any adapter (the implementation file
// carries the mirror assertion against the docker client).
var _ safeflow.HealthGater = (*Gater)(nil)

// fakeInspector is the function-field stand-in for the docker SDK client,
// which satisfies Inspector by construction. Tests swap the function.
type fakeInspector struct {
	inspect func(ctx context.Context, containerID string) (types.ContainerJSON, error)
}

func (f *fakeInspector) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	return f.inspect(ctx, containerID)
}

// healthInspect builds an inspect payload whose image defines a HEALTHCHECK.
func healthInspect(h *types.Health) types.ContainerJSON {
	return types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "c1",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
				Health:  h,
			},
		},
	}
}

// exitedHealthInspect: HEALTHCHECK present but the container stopped - its
// Health.Status is frozen stale data.
func exitedHealthInspect(exitCode int, h *types.Health) types.ContainerJSON {
	j := healthInspect(h)
	j.State.Running = false
	j.State.Status = "exited"
	j.State.ExitCode = exitCode
	return j
}

// plainInspect builds an inspect payload without any Health key, exactly like
// pkg/container/mocks/data/container_running.json whose State has no Health.
func plainInspect(running bool, exitCode int) types.ContainerJSON {
	status := "running"
	if !running {
		status = "exited"
	}
	return types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "c1",
			State: &types.ContainerState{
				Status:   status,
				Running:  running,
				ExitCode: exitCode,
			},
		},
	}
}

// scripted replays pollFn in order and repeats the last entry forever, so a
// gate stuck in its polling loop has something to observe.
func scripted(pollFns ...func(call int) (types.ContainerJSON, error)) func(context.Context, string) (types.ContainerJSON, error) {
	calls := 0
	return func(context.Context, string) (types.ContainerJSON, error) {
		idx := calls
		if idx >= len(pollFns) {
			idx = len(pollFns) - 1
		}
		calls++
		return pollFns[idx](calls)
	}
}

// of adapts a fixed payload to the scripted step signature.
func of(j types.ContainerJSON) func(int) (types.ContainerJSON, error) {
	return func(int) (types.ContainerJSON, error) { return j, nil }
}

// errf adapts a fixed error to the scripted step signature.
func errf(err error) func(int) (types.ContainerJSON, error) {
	return func(int) (types.ContainerJSON, error) { return types.ContainerJSON{}, err }
}

func TestNormalizeOptions(t *testing.T) {
	tests := []struct {
		name string
		in   safeflow.GateOptions
		want safeflow.GateOptions
	}{
		{
			name: "zero values become defaults",
			in:   safeflow.GateOptions{},
			want: safeflow.GateOptions{Timeout: 60 * time.Second, Interval: 5 * time.Second},
		},
		{
			name: "negative values become defaults",
			in:   safeflow.GateOptions{Timeout: -3 * time.Second, Interval: -1 * time.Millisecond},
			want: safeflow.GateOptions{Timeout: 60 * time.Second, Interval: 5 * time.Second},
		},
		{
			name: "sub-floor interval is clamped up to 100ms",
			in:   safeflow.GateOptions{Timeout: 10 * time.Second, Interval: time.Nanosecond},
			want: safeflow.GateOptions{Timeout: 10 * time.Second, Interval: 100 * time.Millisecond},
		},
		{
			name: "over-ceiling interval is clamped down to timeout/2",
			in:   safeflow.GateOptions{Timeout: 10 * time.Second, Interval: 30 * time.Second},
			want: safeflow.GateOptions{Timeout: 10 * time.Second, Interval: 5 * time.Second},
		},
		{
			name: "default interval collapses to timeout/2 when window < 200ms",
			in:   safeflow.GateOptions{Timeout: 150 * time.Millisecond},
			want: safeflow.GateOptions{Timeout: 150 * time.Millisecond, Interval: 75 * time.Millisecond},
		},
		{
			name: "floor yields to timeout/2 when window < 200ms",
			in:   safeflow.GateOptions{Timeout: 150 * time.Millisecond, Interval: 10 * time.Millisecond},
			want: safeflow.GateOptions{Timeout: 150 * time.Millisecond, Interval: 75 * time.Millisecond},
		},
		{
			name: "in-range interval passes through",
			in:   safeflow.GateOptions{Timeout: time.Second, Interval: 300 * time.Millisecond},
			want: safeflow.GateOptions{Timeout: time.Second, Interval: 300 * time.Millisecond},
		},
		{
			name: "5s default interval clamped by a 250ms window",
			in:   safeflow.GateOptions{Timeout: 250 * time.Millisecond},
			want: safeflow.GateOptions{Timeout: 250 * time.Millisecond, Interval: 125 * time.Millisecond},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			timeout, interval := normalizeOptions(tc.in)
			assert.Equal(t, tc.want.Timeout, timeout, "timeout")
			assert.Equal(t, tc.want.Interval, interval, "interval")
			// Two-probe guarantee: the cadence always fits at least twice
			// inside the window.
			assert.LessOrEqual(t, interval, timeout/2, "interval must fit twice in the window")
		})
	}
}

func TestAwaitHealthy(t *testing.T) {
	const id = "test-container-1"

	tests := []struct {
		name    string
		opts    safeflow.GateOptions
		inspect func(ctx context.Context, containerID string) (types.ContainerJSON, error)
		verify  func(t *testing.T, res safeflow.HealthResult, err error)
	}{
		{
			// A7 class 1: HEALTHCHECK image reports healthy.
			name: "healthy on first poll passes",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{Status: types.Healthy}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, safeflow.HealthHealthy, res.Status)
				assert.Equal(t, 1, res.Checks)
				assert.Less(t, res.Elapsed, time.Second, "must not idle out the window")
			},
		},
		{
			// A7 class 1 (transition): starting, then healthy.
			name: "healthy after starting passes on second poll",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second, Interval: time.Millisecond},
			inspect: scripted(
				of(healthInspect(&types.Health{Status: types.Starting})),
				of(healthInspect(&types.Health{Status: types.Healthy})),
			),
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, safeflow.HealthHealthy, res.Status)
				assert.Equal(t, 2, res.Checks)
				// Interval was clamped up to the 100ms floor.
				assert.GreaterOrEqual(t, res.Elapsed, 90*time.Millisecond)
				assert.Less(t, res.Elapsed, time.Second)
			},
		},
		{
			// A7 class 2: HEALTHCHECK image reports unhealthy - immediate
			// failure, LastOutput is the NEWEST log entry.
			name: "unhealthy fails immediately carrying newest log output",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{
					Status: types.Unhealthy,
					Log: []*types.HealthcheckResult{
						{Output: "probe 1 failed"},
						{Output: "probe 2 failed"},
					},
				}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.NotErrorIs(t, err, safeflow.ErrHealthTimeout)
				assert.Equal(t, safeflow.HealthUnhealthy, res.Status)
				assert.Equal(t, "probe 2 failed", res.LastOutput)
				assert.Equal(t, 1, res.Checks)
				assert.Less(t, res.Elapsed, time.Second)
			},
		},
		{
			// A7 class 2 (truncation): 600-byte probe output capped at 512.
			name: "unhealthy log output truncated to 512 bytes",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{
					Status: types.Unhealthy,
					Log: []*types.HealthcheckResult{
						{Output: "older entry"},
						{Output: strings.Repeat("x", 600)},
					},
				}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Len(t, res.LastOutput, 512)
				assert.Equal(t, strings.Repeat("x", 512), res.LastOutput)
			},
		},
		{
			// A7 class 2 (degenerate log): nil newest entry yields "".
			name: "unhealthy with nil newest log entry yields empty LastOutput",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{
					Status: types.Unhealthy,
					Log:    []*types.HealthcheckResult{{Output: "older entry"}, nil},
				}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Empty(t, res.LastOutput)
			},
		},
		{
			// A7 class 3: stuck in starting until the window closes.
			name: "starting polls until timeout",
			opts: safeflow.GateOptions{Timeout: 200 * time.Millisecond},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{Status: types.Starting}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrHealthTimeout)
				assert.NotErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Equal(t, safeflow.HealthStarting, res.Status)
				assert.GreaterOrEqual(t, res.Checks, 2, "window must fit at least two probes")
				assert.GreaterOrEqual(t, res.Elapsed, 190*time.Millisecond)
				assert.LessOrEqual(t, res.Elapsed, 2*time.Second)
			},
		},
		{
			// A7 class 4: no HEALTHCHECK, container running - single probe,
			// never idles out the window.
			name: "no healthcheck running passes after a single probe",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return plainInspect(true, 0), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, safeflow.HealthUnknown, res.Status)
				assert.Equal(t, reasonNoHealthRunning, res.Reason)
				assert.Equal(t, 1, res.Checks)
				assert.Less(t, res.Elapsed, time.Second, "must not idle out the window")
			},
		},
		{
			// A7 class 5: no HEALTHCHECK, container exited.
			name: "no healthcheck exited fails immediately with exit code",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return plainInspect(false, 42), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.NotErrorIs(t, err, safeflow.ErrHealthTimeout)
				assert.Equal(t, safeflow.HealthExited, res.Status)
				assert.Equal(t, 42, res.ExitCode)
				assert.Equal(t, 1, res.Checks)
				assert.Less(t, res.Elapsed, time.Second)
			},
		},
		{
			// A7 class 7a: transient inspect error retried inside the window.
			name: "transient inspect error is retried then passes",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second, Interval: time.Millisecond},
			inspect: scripted(
				errf(errors.New("connection reset by peer")),
				of(healthInspect(&types.Health{Status: types.Healthy})),
			),
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, safeflow.HealthHealthy, res.Status)
				assert.Equal(t, 2, res.Checks, "first poll errored, second succeeded")
			},
		},
		{
			// A7 class 7b: container vanished mid-gate.
			name: "container gone fails immediately",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return types.ContainerJSON{}, errdefs.NotFound(errors.New("No such container: " + id))
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Equal(t, safeflow.HealthUnhealthy, res.Status)
				assert.Equal(t, reasonContainerGone, res.Reason)
				assert.Equal(t, 1, res.Checks)
				assert.Empty(t, res.LastOutput)
				assert.Less(t, res.Elapsed, time.Second, "must not idle out the window")
			},
		},
		{
			// A7 class 7c: transient errors for the whole window time out.
			name: "persistent transient inspect errors time out",
			opts: safeflow.GateOptions{Timeout: 200 * time.Millisecond},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return types.ContainerJSON{}, errors.New("i/o timeout")
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrHealthTimeout)
				assert.Equal(t, safeflow.HealthStarting, res.Status)
				assert.GreaterOrEqual(t, res.Checks, 2)
				assert.Contains(t, res.Reason, "inspect failed")
			},
		},
		{
			// Contract extra (safeflow HealthExited): HEALTHCHECK image whose
			// container dies mid-window fails immediately despite its frozen
			// starting status.
			name: "healthcheck container that exited fails as exited",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return exitedHealthInspect(7, &types.Health{Status: types.Starting}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Equal(t, safeflow.HealthExited, res.Status)
				assert.Equal(t, 7, res.ExitCode)
				assert.Equal(t, 1, res.Checks)
			},
		},
		{
			// Nil-guard: an inspect payload without ContainerJSONBase/State
			// must not crash; it reads as "no verdict yet" and times out.
			name: "stateless inspect polls to timeout without panicking",
			opts: safeflow.GateOptions{Timeout: 200 * time.Millisecond},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return types.ContainerJSON{}, nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrHealthTimeout)
				assert.Equal(t, safeflow.HealthStarting, res.Status)
				assert.GreaterOrEqual(t, res.Checks, 2)
			},
		},
		{
			// Empty-value boundary: zero GateOptions fall back to the package
			// defaults (60s/5s); a decisive first poll still returns at once
			// instead of idling out the default window.
			name: "zero gate options use defaults and still pass fast",
			opts: safeflow.GateOptions{},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{Status: types.Healthy}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, safeflow.HealthHealthy, res.Status)
				assert.Equal(t, 1, res.Checks)
				assert.Less(t, res.Elapsed, time.Second, "defaults must not idle out a decisive first poll")
			},
		},
		{
			// Empty-value boundary: negative options also normalize, and the
			// default window does not delay an immediate unhealthy verdict.
			name: "negative gate options use defaults and still fail fast",
			opts: safeflow.GateOptions{Timeout: -time.Second, Interval: -time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{
					Status: types.Unhealthy,
					Log:    []*types.HealthcheckResult{{Output: "boom"}},
				}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Equal(t, safeflow.HealthUnhealthy, res.Status)
				assert.Equal(t, 1, res.Checks)
				assert.Less(t, res.Elapsed, time.Second)
			},
		},
		{
			// Decision-table default arm: any health status value the gate
			// does not recognize is treated as "keep polling".
			name: "unknown health status value polls to timeout",
			opts: safeflow.GateOptions{Timeout: 200 * time.Millisecond},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{Status: "bogus"}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrHealthTimeout)
				assert.Equal(t, safeflow.HealthStarting, res.Status)
				assert.Contains(t, res.Reason, `health status "bogus"`)
				assert.GreaterOrEqual(t, res.Checks, 2)
			},
		},
		{
			// Decision-table default arm with the zero value of HealthStatus.
			name: "empty health status polls to timeout",
			opts: safeflow.GateOptions{Timeout: 200 * time.Millisecond},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrHealthTimeout)
				assert.Equal(t, safeflow.HealthStarting, res.Status)
				assert.Contains(t, res.Reason, `health status ""`)
			},
		},
		{
			// Degenerate unhealthy payload: Health present, log slice empty.
			name: "unhealthy with empty log slice yields empty LastOutput",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{
					Status: types.Unhealthy,
					Log:    []*types.HealthcheckResult{},
				}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Equal(t, safeflow.HealthUnhealthy, res.Status)
				assert.Empty(t, res.LastOutput)
			},
		},
		{
			// Truncation boundary: output exactly at the cap passes through
			// unmodified (len == 512 is not "greater than" 512).
			name: "unhealthy log output of exactly 512 bytes is not truncated",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{
					Status: types.Unhealthy,
					Log:    []*types.HealthcheckResult{{Output: strings.Repeat("y", 512)}},
				}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Equal(t, strings.Repeat("y", 512), res.LastOutput)
			},
		},
		{
			// Mid-window transition: starting turns unhealthy on a later poll;
			// the verdict, its log output and the container id in the wrapped
			// error all come from the newest probe.
			name: "starting turning unhealthy fails on the second poll",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second, Interval: time.Millisecond},
			inspect: scripted(
				of(healthInspect(&types.Health{Status: types.Starting})),
				of(healthInspect(&types.Health{
					Status: types.Unhealthy,
					Log:    []*types.HealthcheckResult{{Output: "late failure"}},
				})),
			),
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Contains(t, err.Error(), id, "unhealthy error must name the container")
				assert.Equal(t, safeflow.HealthUnhealthy, res.Status)
				assert.Equal(t, 2, res.Checks)
				assert.Equal(t, "late failure", res.LastOutput)
			},
		},
		{
			// Mid-window transition: a starting container dies; the exit
			// check outranks the frozen health status even mid-window.
			name: "starting container exiting mid-window fails as exited",
			opts: safeflow.GateOptions{Timeout: 2 * time.Second, Interval: time.Millisecond},
			inspect: scripted(
				of(healthInspect(&types.Health{Status: types.Starting})),
				of(exitedHealthInspect(9, &types.Health{Status: types.Starting})),
			),
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrUnhealthy)
				assert.Equal(t, safeflow.HealthExited, res.Status)
				assert.Equal(t, 9, res.ExitCode)
				assert.Equal(t, 2, res.Checks)
			},
		},
		{
			// Cadence clamp through the real loop: an interval larger than
			// the whole window is pulled down to timeout/2 so the window still
			// fits two probes and never overshoots the deadline.
			name: "oversized interval is clamped so the window fits two probes",
			opts: safeflow.GateOptions{Timeout: 250 * time.Millisecond, Interval: 30 * time.Second},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{Status: types.Starting}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrHealthTimeout)
				assert.GreaterOrEqual(t, res.Checks, 2, "clamped cadence must fit twice in the window")
				assert.GreaterOrEqual(t, res.Elapsed, 200*time.Millisecond)
				assert.LessOrEqual(t, res.Elapsed, 2*time.Second, "window must not overshoot by a full interval")
			},
		},
		{
			// Error propagation: the timeout error names the container, the
			// window, the poll count and the last reason.
			name: "timeout error carries id, window, checks and reason",
			opts: safeflow.GateOptions{Timeout: 200 * time.Millisecond},
			inspect: func(context.Context, string) (types.ContainerJSON, error) {
				return healthInspect(&types.Health{Status: "limbo"}), nil
			},
			verify: func(t *testing.T, res safeflow.HealthResult, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, safeflow.ErrHealthTimeout)
				assert.Contains(t, err.Error(), id)
				assert.Contains(t, err.Error(), "200ms")
				assert.Contains(t, err.Error(), fmt.Sprintf("after %d checks", res.Checks))
				assert.Contains(t, err.Error(), `health status "limbo"`)
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			g := New(&fakeInspector{inspect: tc.inspect})
			res, err := g.AwaitHealthy(context.Background(), id, tc.opts)

			// Contract invariants enforced on every case.
			assert.GreaterOrEqual(t, res.Checks, 1, "Checks >= 1 is a contract invariant")
			if res.Status != safeflow.HealthHealthy {
				assert.NotEmpty(t, res.Reason, "non-healthy outcomes must carry a Reason")
			}
			if res.Status != safeflow.HealthExited {
				assert.Zero(t, res.ExitCode, "ExitCode is populated iff Status is exited")
			}
			assert.GreaterOrEqual(t, res.Elapsed, time.Duration(0))

			tc.verify(t, res, err)
		})
	}
}

// A7 class 6: cancelling ctx between probes returns the HealthResult
// accumulated so far plus the raw ctx error - never ErrHealthTimeout.
func TestAwaitHealthyContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	calls := 0
	fake := &fakeInspector{
		inspect: func(context.Context, string) (types.ContainerJSON, error) {
			calls++
			cancel() // cancel while the gate is between probes
			return healthInspect(&types.Health{Status: types.Starting}), nil
		},
	}

	g := New(fake)
	start := time.Now()
	res, err := g.AwaitHealthy(ctx, "test-container-1", safeflow.GateOptions{
		Timeout:  30 * time.Second,
		Interval: 500 * time.Millisecond,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, safeflow.ErrHealthTimeout, "cancellation must not be disguised as a timeout")
	assert.NotErrorIs(t, err, safeflow.ErrUnhealthy)
	assert.Equal(t, safeflow.HealthStarting, res.Status)
	assert.Equal(t, 1, res.Checks)
	assert.NotEmpty(t, res.Reason)
	assert.Equal(t, 1, calls, "no probe may run after cancellation")
	assert.Less(t, time.Since(start), 5*time.Second, "ctx must wake the gate before the window closes")
}

// Dead-on-arrival contexts: the contract says a cancelled ctx returns the
// accumulated HealthResult plus the raw ctx error, never ErrHealthTimeout -
// and the probe-first rule keeps Checks >= 1 even here.
func TestAwaitHealthyDeadOnArrivalContext(t *testing.T) {
	const id = "test-container-1"

	tests := []struct {
		name    string
		ctx     context.Context
		wantErr error
	}{
		{
			name: "canceled before the first probe",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
			wantErr: context.Canceled,
		},
		{
			name: "deadline already exceeded before the first probe",
			ctx: func() context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
				cancel() // release the timer; ctx.Err() stays DeadlineExceeded
				return ctx
			}(),
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			g := New(&fakeInspector{
				inspect: func(context.Context, string) (types.ContainerJSON, error) {
					return healthInspect(&types.Health{Status: types.Starting}), nil
				},
			})

			start := time.Now()
			res, err := g.AwaitHealthy(tc.ctx, id, safeflow.GateOptions{
				Timeout:  30 * time.Second,
				Interval: 500 * time.Millisecond,
			})

			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr, "the raw ctx error must surface verbatim")
			assert.NotErrorIs(t, err, safeflow.ErrHealthTimeout, "ctx abort must not be disguised as a timeout")
			assert.NotErrorIs(t, err, safeflow.ErrUnhealthy)
			assert.Equal(t, safeflow.HealthStarting, res.Status)
			assert.Equal(t, 1, res.Checks, "probe-first rule: one probe runs even on a dead ctx")
			assert.NotEmpty(t, res.Reason)
			assert.Less(t, time.Since(start), 5*time.Second, "dead ctx must wake immediately, not after the window")
		})
	}
}

// Empty-value boundary at the interface edge: whatever container string the
// caller hands the gate reaches the inspector untouched - including "".
func TestAwaitHealthyPassesContainerIDThrough(t *testing.T) {
	for _, id := range []string{"", "test-container-1", strings.Repeat("f", 64)} {
		id := id
		t.Run(fmt.Sprintf("id %q", id), func(t *testing.T) {
			var got string
			g := New(&fakeInspector{
				inspect: func(_ context.Context, containerID string) (types.ContainerJSON, error) {
					got = containerID
					return healthInspect(&types.Health{Status: types.Healthy}), nil
				},
			})

			res, err := g.AwaitHealthy(context.Background(), id, safeflow.GateOptions{Timeout: time.Second})

			require.NoError(t, err)
			assert.Equal(t, safeflow.HealthHealthy, res.Status)
			assert.Equal(t, id, got, "inspector must receive the caller's container id verbatim")
		})
	}
}

// Statelessness: one Gater serves concurrent windows (the type docs promise
// this as long as the Inspector is; the fake is mutex-guarded).
func TestAwaitHealthyConcurrentWindows(t *testing.T) {
	const n = 8

	var mu sync.Mutex
	seen := make(map[string]int)
	fake := &fakeInspector{
		inspect: func(_ context.Context, containerID string) (types.ContainerJSON, error) {
			mu.Lock()
			seen[containerID]++
			mu.Unlock()
			return healthInspect(&types.Health{Status: types.Healthy}), nil
		},
	}

	g := New(fake)
	results := make([]safeflow.HealthResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = g.AwaitHealthy(context.Background(), fmt.Sprintf("c-%d", i),
				safeflow.GateOptions{Timeout: 5 * time.Second})
		}(i)
	}
	wg.Wait()

	for i := range results {
		require.NoError(t, errs[i], "window %d", i)
		assert.Equal(t, safeflow.HealthHealthy, results[i].Status, "window %d", i)
		assert.Equal(t, 1, results[i].Checks, "window %d", i)
	}
	require.Len(t, seen, n, "each window must probe its own container exactly once")
	for id, calls := range seen {
		assert.Equal(t, 1, calls, "container %s", id)
	}
}

// truncate is contract-bound to byte-level truncation at 512; the table pins
// both sides of the cap and the mid-rune split.
func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty string", in: "", want: ""},
		{name: "short string unchanged", in: "probe output", want: "probe output"},
		{name: "511 bytes unchanged just under the cap", in: strings.Repeat("a", 511), want: strings.Repeat("a", 511)},
		{name: "exactly 512 bytes unchanged at the cap", in: strings.Repeat("b", 512), want: strings.Repeat("b", 512)},
		{name: "513 bytes cut to 512", in: strings.Repeat("c", 513), want: strings.Repeat("c", 512)},
		{
			// Byte-level truncation may split a multi-byte rune at the cap:
			// 512 = 170*3 + 2, so the 171st rune loses its final byte.
			name: "multibyte output cut mid-rune at the cap",
			in:   strings.Repeat("中", 200),
			want: strings.Repeat("中", 170) + "中"[:2],
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.in)
			assert.Equal(t, tc.want, got)
			assert.LessOrEqual(t, len(got), maxLastOutput, "result must never exceed the cap")
		})
	}
}

// lastHealthOutput must survive every degenerate Health.Log shape and always
// report the NEWEST entry.
func TestLastHealthOutput(t *testing.T) {
	tests := []struct {
		name string
		h    *types.Health
		want string
	}{
		{name: "nil health", h: nil, want: ""},
		{name: "nil log", h: &types.Health{}, want: ""},
		{name: "empty log", h: &types.Health{Log: []*types.HealthcheckResult{}}, want: ""},
		{name: "single entry", h: &types.Health{Log: []*types.HealthcheckResult{{Output: "only"}}}, want: "only"},
		{
			name: "newest entry wins",
			h:    &types.Health{Log: []*types.HealthcheckResult{{Output: "older"}, {Output: "newer"}}},
			want: "newer",
		},
		{
			name: "nil newest entry",
			h:    &types.Health{Log: []*types.HealthcheckResult{{Output: "older"}, nil}},
			want: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, lastHealthOutput(tc.h))
		})
	}
}
