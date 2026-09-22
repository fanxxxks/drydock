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

// Package healthgate implements safeflow.HealthGater, the post-update health
// door that decides whether a freshly recreated container may keep its place
// or must be rolled back. It slots into the update flow right where upstream
// watchtower hands the new container back to the orchestrator
// (internal/actions/update.go:224-228: after StartContainer returned the new
// container ID, before post-update hooks and before the old image is cleaned
// up) - the gate MUST veto image cleanup, which is why it blocks instead of
// sampling asynchronously.
//
// The gate is a pure observer: it polls docker inspect and never restarts,
// stops or otherwise mutates the container. Its only dependency is the narrow
// Inspector interface below, which the stock docker SDK client satisfies by
// construction, so wiring it into the cmd layer is a one-liner.
//
// Decision table (State is types.ContainerState):
//
//	State.Health == nil (image defines no HEALTHCHECK - the common case; the
//	  upstream inspect fixture pkg/container/mocks/data/container_running.json
//	  carries no Health key at all):
//	    State.Running == true  -> pass immediately, Status HealthUnknown,
//	                               single probe, never waits out the window
//	    State.Running == false -> fail immediately wrapping ErrUnhealthy,
//	                               Status HealthExited, ExitCode populated
//	State.Health != nil (image defines a HEALTHCHECK):
//	    exited (Running false) -> fail immediately wrapping ErrUnhealthy
//	    Health.Status healthy   -> pass, Status HealthHealthy
//	    Health.Status unhealthy -> fail immediately wrapping ErrUnhealthy,
//	                               Status HealthUnhealthy, LastOutput = newest
//	                               Health.Log entry output capped at 512 bytes
//	    starting or any other value -> keep polling every interval until the
//	                               window closes, then ErrHealthTimeout with
//	                               Status HealthStarting
//	inspect errors:
//	    client.IsErrNotFound    -> fail immediately wrapping ErrUnhealthy,
//	                               Reason "container gone"
//	    anything else (transient connection errors included) -> retried
//	                               within the window
//	ctx cancellation between probes -> returns the HealthResult accumulated
//	                               so far plus the raw ctx.Err(); never
//	                               disguised as ErrHealthTimeout
//
// Non-goals for v0.1: the gate does not subscribe to the docker event stream
// (pure polling keeps it daemon-version agnostic and trivially testable), it
// does not monitor RestartCount growth, and it does not run custom probe
// commands. Those are candidate v0.2 additions behind the same interface.
package healthgate

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// Defaults applied by normalizeOptions when the corresponding GateOptions
// field is non-positive. They mirror the planned --health-timeout /
// --health-interval flags; the cmd layer always passes explicit values, so
// these are a safety net for library consumers only.
const (
	DefaultTimeout  = 60 * time.Second
	DefaultInterval = 5 * time.Second
)

const (
	// minInterval is the floor for the poll cadence: any finer and tests
	// (and busy hosts) would hammer the daemon for no signal gain.
	minInterval = 100 * time.Millisecond
	// maxLastOutput caps HealthResult.LastOutput at 512 bytes, matching the
	// safeflow contract. Truncation is by raw bytes.
	maxLastOutput = 512
)

// Spec-mandated Reason strings; tests assert these verbatim.
const (
	reasonNoHealthRunning = "no HEALTHCHECK defined; container running"
	reasonContainerGone   = "container gone"
)

// Inspector is the complete docker surface the gate needs: one inspect call.
// *client.Client satisfies it out of the box (client.ContainerInspect,
// docker/docker client/container_inspect.go:14); tests inject a fake with a
// function field.
type Inspector interface {
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
}

// Compile-time wiring proofs.
var (
	_ Inspector            = (*client.Client)(nil)
	_ safeflow.HealthGater = (*Gater)(nil)
)

// Gater is a polling safeflow.HealthGater. It is stateless and safe for
// concurrent use across containers as long as the underlying Inspector is.
type Gater struct {
	inspector Inspector
}

// New returns a Gater polling container state through inspector.
func New(inspector Inspector) *Gater {
	return &Gater{inspector: inspector}
}

// AwaitHealthy runs one gate window for containerID per the package decision
// table. See safeflow.HealthGater for the contract; see the package comment
// for the exact semantics of each outcome.
func (g *Gater) AwaitHealthy(ctx context.Context, containerID string, opts safeflow.GateOptions) (safeflow.HealthResult, error) {
	timeout, interval := normalizeOptions(opts)
	start := time.Now()
	deadline := start.Add(timeout)

	res := safeflow.HealthResult{Status: safeflow.HealthStarting}

	for {
		// Probe first, ask questions later: Checks >= 1 is a contract
		// invariant even when the window is cut short right away.
		inspect, inspectErr := g.inspector.ContainerInspect(ctx, containerID)
		res.Checks++

		if done, retErr := evaluate(containerID, inspect, inspectErr, &res); done {
			res.Elapsed = time.Since(start)
			return res, retErr
		}

		// No verdict yet - sleep one interval, woken early by ctx
		// cancellation. The sleep is capped at the time remaining so the
		// window never overshoots Timeout by a full interval and no probe
		// happens past the deadline.
		sleepFor := interval
		if remain := time.Until(deadline); remain < sleepFor {
			sleepFor = remain
		}
		timer := time.NewTimer(sleepFor)
		select {
		case <-ctx.Done():
			timer.Stop()
			res.Elapsed = time.Since(start)
			// Caller-initiated abort: surface the raw ctx error, never
			// ErrHealthTimeout. res already reflects the last probe.
			return res, ctx.Err()
		case <-timer.C:
		}

		// Between-probes ctx check: the timer may win the select race even
		// though ctx is also done; do not burn a probe on a dead context.
		if err := ctx.Err(); err != nil {
			res.Elapsed = time.Since(start)
			return res, err
		}

		if !time.Now().Before(deadline) {
			res.Elapsed = time.Since(start)
			return res, fmt.Errorf("%w: container %s: no healthy verdict within %s after %d checks: %s",
				safeflow.ErrHealthTimeout, containerID, timeout, res.Checks, res.Reason)
		}
	}
}

// evaluate folds one poll (or its error) into res and reports whether the
// window is over. done=true means AwaitHealthy must return (retErr, which is
// nil for a pass); done=false means "keep polling". Every path through here
// leaves res.Reason non-empty, which keeps the contract invariant (non-healthy
// outcomes carry a reason) true for mid-window returns as well.
func evaluate(containerID string, inspect types.ContainerJSON, inspectErr error, res *safeflow.HealthResult) (done bool, retErr error) {
	if inspectErr != nil {
		if client.IsErrNotFound(inspectErr) {
			res.Status = safeflow.HealthUnhealthy
			res.Reason = reasonContainerGone
			return true, fmt.Errorf("%w: container %s: %s",
				safeflow.ErrUnhealthy, containerID, reasonContainerGone)
		}
		// Transient (connection reset, daemon restarting, canceled mid-call
		// ...): no verdict, retry within the window.
		res.Status = safeflow.HealthStarting
		res.Reason = fmt.Sprintf("inspect failed: %v", inspectErr)
		return false, nil
	}

	// ContainerJSON embeds *ContainerJSONBase: a missing base or state would
	// panic on the field access below, so guard and treat it as a transient
	// anomaly instead.
	if inspect.ContainerJSONBase == nil || inspect.State == nil {
		res.Status = safeflow.HealthStarting
		res.Reason = "inspect carried no container state"
		return false, nil
	}
	state := inspect.State

	// Image without a HEALTHCHECK: State.Health is nil (the running-container
	// fixture has no Health key at all). Single-probe semantics - decide now,
	// never idle out the window.
	if state.Health == nil {
		if state.Running {
			res.Status = safeflow.HealthUnknown
			res.Reason = reasonNoHealthRunning
			return true, nil
		}
		res.Status = safeflow.HealthExited
		res.ExitCode = state.ExitCode
		res.Reason = "no HEALTHCHECK defined; container not running"
		return true, fmt.Errorf("%w: container %s: no HEALTHCHECK defined; container not running (exit code %d)",
			safeflow.ErrUnhealthy, containerID, state.ExitCode)
	}

	// Image with a HEALTHCHECK. A container that is no longer running will
	// never turn healthy (its Health.Status is frozen stale data), so the
	// exit check wins over the reported status.
	if !state.Running {
		res.Status = safeflow.HealthExited
		res.ExitCode = state.ExitCode
		res.Reason = fmt.Sprintf("container exited during gate window (exit code %d)", state.ExitCode)
		return true, fmt.Errorf("%w: container %s: %s",
			safeflow.ErrUnhealthy, containerID, res.Reason)
	}

	switch state.Health.Status {
	case types.Healthy:
		res.Status = safeflow.HealthHealthy
		res.Reason = "healthcheck reported healthy"
		return true, nil

	case types.Unhealthy:
		res.Status = safeflow.HealthUnhealthy
		res.Reason = "healthcheck reported unhealthy"
		res.LastOutput = truncate(lastHealthOutput(state.Health))
		return true, fmt.Errorf("%w: container %s: healthcheck reported unhealthy",
			safeflow.ErrUnhealthy, containerID)

	default:
		// types.Starting, "" and any unknown value: keep polling.
		res.Status = safeflow.HealthStarting
		res.Reason = fmt.Sprintf("health status %q", state.Health.Status)
		return false, nil
	}
}

// lastHealthOutput returns the Output of the newest Health.Log entry (""
// when there is no log or the last entry is nil - Log is []*HealthcheckResult).
func lastHealthOutput(h *types.Health) string {
	if h == nil || len(h.Log) == 0 {
		return ""
	}
	last := h.Log[len(h.Log)-1]
	if last == nil {
		return ""
	}
	return last.Output
}

// truncate caps s at maxLastOutput bytes. Byte-level, per the contract
// ("truncated to 512 bytes"); a multi-byte rune may be split at the cap.
func truncate(s string) string {
	if len(s) <= maxLastOutput {
		return s
	}
	return s[:maxLastOutput]
}

// normalizeOptions applies the v0.1 defaults for non-positive values and
// clamps the interval into [100ms, Timeout/2] - lowering the floor to
// Timeout/2 when the window is smaller than 2*minInterval - so that any
// window, however small, always fits at least two probes. Millisecond-scale
// windows therefore make deterministic tests possible.
func normalizeOptions(opts safeflow.GateOptions) (timeout, interval time.Duration) {
	timeout = opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	interval = opts.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	upper := timeout / 2
	lower := minInterval
	if upper < lower {
		lower = upper
	}
	switch {
	case interval < lower:
		interval = lower
	case interval > upper:
		interval = upper
	}
	return timeout, interval
}
