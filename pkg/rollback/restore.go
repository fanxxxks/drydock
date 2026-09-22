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

package rollback

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	sdkclient "github.com/docker/docker/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// watchtowerLabelKey is the label the upstream watchtower image puts on its
// own container (self-detection: pkg/container/metadata.go:44-47, special
// update path internal/actions/update.go:216-221). A snapshot carrying this
// label is Drydock's own container and is refused a rollback in v0.1.
const watchtowerLabelKey = "com.centurylinklabs.watchtower"

const (
	// failedContainerPrefix brands the renamed, unhealthy replacement so it is
	// kept for forensics instead of being deleted ("drydock-failed-<name>-<unixnano>").
	failedContainerPrefix = "drydock-failed-"

	// logTailLines is how many trailing log lines are captured from the failed
	// container before anything can stop (and, for AutoRemove containers,
	// destroy) it.
	logTailLines = 50

	// defaultStopTimeout is the graceful-stop window (SIGTERM -> wait ->
	// SIGKILL), matching upstream's 1m --timeout default.
	defaultStopTimeout = 60 * time.Second

	// dockerShortIDLen is the length of a docker "short ID"; endpoints carry
	// an alias of this form that must not survive a recreate
	// (pkg/container/client.go:231-244).
	dockerShortIDLen = 12
)

// apiClient is the narrow Docker API surface the Restorer needs. It is a
// subset of the SDK client's method set, so *sdkclient.Client satisfies it
// without adapters (asserted below); tests supply an in-memory fake.
//
// The opencontainers image-spec import exists only to name the Platform
// parameter of ContainerCreate - the SDK signature forces it.
type apiClient interface {
	ContainerLogs(ctx context.Context, container string, options types.ContainerLogsOptions) (io.ReadCloser, error)
	ContainerRename(ctx context.Context, containerID, newContainerName string) error
	ContainerStop(ctx context.Context, containerID string, options dockercontainer.StopOptions) error
	ContainerRemove(ctx context.Context, containerID string, options types.ContainerRemoveOptions) error
	ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error)
	ContainerCreate(ctx context.Context, config *dockercontainer.Config, hostConfig *dockercontainer.HostConfig, networkingConfig *network.NetworkingConfig, platform *ocispec.Platform, containerName string) (dockercontainer.CreateResponse, error)
	NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error
	NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error
	ContainerStart(ctx context.Context, containerID string, options types.ContainerStartOptions) error
}

// RollbackResult reports how far a rollback got. On error every field filled
// so far is still returned, so callers and reports can tell "logs captured,
// renamed, never recreated" apart.
type RollbackResult struct {
	// Restored is true only when step 8 (ContainerStart) succeeded.
	Restored bool
	// ContainerID is the ID of the recreated container (filled after step 6).
	ContainerID string
	// ContainerName is the original, "/"-stripped name being restored.
	ContainerName string
	// SnapshotID identifies the snapshot restored from.
	SnapshotID string
	// FailedContainerName is the name the failed replacement ran under before
	// the rename (the original name).
	FailedContainerName string
	// FailedRenamedTo is the forensic name the failed replacement was renamed
	// to (filled after step 2; never deleted by v0.1).
	FailedRenamedTo string
	// FailedLogs holds the tail (<= 50 lines) captured from the failed
	// container before the rename/stop; "" when capture failed (tolerated).
	FailedLogs string
}

// Restorer recreates a container from a pre-update safeflow.Snapshot,
// implementing safeflow.Rollbacker.
type Restorer struct {
	api apiClient

	// now timestamps forensic renames; injected by tests for determinism.
	now func() time.Time

	// StopTimeout is the graceful stop window for the failed container
	// (SIGTERM -> wait -> SIGKILL, enforced by the daemon's stop API).
	// Non-positive falls back to defaultStopTimeout.
	StopTimeout time.Duration
}

// Compile-time contract checks: Restorer is a safeflow.Rollbacker, and the
// real SDK client satisfies the narrow apiClient interface as-is.
var (
	_ safeflow.Rollbacker = (*Restorer)(nil)
	_ apiClient           = (*sdkclient.Client)(nil)
)

// NewRestorer returns a Restorer driving api (pass a *sdkclient.Client in
// production). The default stop timeout matches upstream's 1m.
func NewRestorer(api apiClient) *Restorer {
	return &Restorer{api: api, now: time.Now, StopTimeout: defaultStopTimeout}
}

// Rollback implements safeflow.Rollbacker: it restores the snapshot and
// returns the recreated container's ID.
func (r *Restorer) Rollback(ctx context.Context, snapshot safeflow.Snapshot) (string, error) {
	res, err := r.RollbackDetailed(ctx, snapshot)
	return res.ContainerID, err
}

// RollbackDetailed runs the documented rollback sequence. The step order is
// part of the contract:
//
//  1. capture the failed container's log tail (must be first: AutoRemove
//     containers destroy themselves when stopped);
//  2. rename the failed container to "drydock-failed-<name>-<unixnano>"
//     (forensic retention; v0.1 never deletes it) - this frees the name;
//  3. graceful stop of the renamed container (no remove);
//  4. ImageInspect(snap.ImageID()) - a missing image aborts with an error
//     wrapping safeflow.ErrRollbackImageMissing and no ContainerCreate call;
//  5. build create config from a deep copy of the snapshot's Inspect:
//     Config passed through untouched (deliberately skipping upstream
//     GetCreateConfig's image-default subtraction, which would drop
//     "explicitly set = image default" overrides), Config.Image set to
//     snap.ImageID() - the immutable local image ID ("sha256:...") whose
//     existence step 4 just verified, NEVER the mutable tag reference the
//     container was started with. By the time a rollback runs, the update
//     flow has already re-pulled the same tag (e.g. "app:latest"), so the
//     daemon would resolve that tag to the freshly failed - or poisoned -
//     image. Pinning the image ID makes "what step 4 verified" and "what
//     step 6 runs" byte-for-byte the same reference; the old container-ID
//     short alias is stripped from endpoint aliases
//     (pkg/container/client.go:235-241);
//  6. ContainerCreate under the original name;
//  7. for non-host networking, mirror upstream's reconnect dance
//     (pkg/container/client.go:254-291): the container is created attached to
//     a single endpoint, that endpoint is force-disconnected, then every
//     network from NetworkSettings.Networks is reconnected - host mode skips
//     the whole block;
//  8. ContainerStart - Restored is true only if this succeeds.
//
// Failure semantics: steps 2/3 failing abort with no create (the failed
// container is left exactly as it is - running or stopped, never deleted).
// Steps 6/7/8 failing trigger a best-effort revival (ContainerStart) of the
// renamed failed container to avoid double downtime, and the half-created
// replacement is removed (force) so the original name is free for the next
// attempt; the wrapped error is still returned.
func (r *Restorer) RollbackDetailed(ctx context.Context, snap safeflow.Snapshot) (RollbackResult, error) {
	res := RollbackResult{
		ContainerName: containerName(snap.ContainerName),
		SnapshotID:    snap.ID,
	}

	if err := snap.Validate(); err != nil {
		return res, fmt.Errorf("rollback: invalid snapshot %q: %w", snap.ID, err)
	}
	if isDrydockOwnContainer(snap) {
		return res, fmt.Errorf("rollback: refusing to roll back %q: its labels contain %q (Drydock's own container; self-rollback is out of scope for v0.1)",
			res.ContainerName, watchtowerLabelKey)
	}

	name := res.ContainerName
	res.FailedContainerName = name

	// Step 1: logs first - an AutoRemove container may self-destruct the
	// moment it stops, and this is the only chance to capture evidence.
	res.FailedLogs = r.captureLogs(ctx, name, snap)

	// Step 2: rename for forensics; frees the original name for step 6.
	renamedTo := fmt.Sprintf("%s%s-%d", failedContainerPrefix, name, r.now().UnixNano())
	if err := r.api.ContainerRename(ctx, name, renamedTo); err != nil {
		return res, fmt.Errorf("rollback: renaming failed container %q to %q: %w", name, renamedTo, err)
	}
	res.FailedRenamedTo = renamedTo

	// Step 3: graceful stop (SIGTERM -> timeout -> SIGKILL via the daemon's
	// stop API), explicitly WITHOUT the remove that upstream's StopContainer
	// performs. A NotFound error means the container already went away (e.g.
	// AutoRemove) and counts as success.
	stopSignal := ""
	if snap.Inspect.Config != nil {
		stopSignal = snap.Inspect.Config.StopSignal
	}
	if err := r.api.ContainerStop(ctx, renamedTo, dockercontainer.StopOptions{
		Signal:  stopSignal,
		Timeout: secondsPtr(r.stopTimeout()),
	}); err != nil && !isNotFound(err) {
		return res, fmt.Errorf("rollback: stopping failed container %q: %w (left as-is, never deleted)", renamedTo, err)
	}

	// Step 4: the old image must still exist on the host before anything is
	// created; otherwise abort with ErrRollbackImageMissing. imageRef below
	// reuses this exact reference for the create, so what is verified here is
	// precisely what gets run.
	imageRef := snap.ImageID()
	if _, _, err := r.api.ImageInspectWithRaw(ctx, imageRef); err != nil {
		if isNotFound(err) {
			return res, fmt.Errorf("rollback: %w: snapshot image %q for container %q",
				safeflow.ErrRollbackImageMissing, imageRef, name)
		}
		return res, fmt.Errorf("rollback: inspecting snapshot image %q: %w", imageRef, err)
	}

	// Step 5: derive create/host/network config from a private deep copy, so
	// neither the caller's snapshot nor the stored one is mutated.
	createConfig, hostConfig, networkConfig, err := r.buildConfigs(snap)
	if err != nil {
		return res, fmt.Errorf("rollback: building create config for %q: %w", name, err)
	}

	// Step 6: create. Like upstream (docker#29265 workaround,
	// pkg/container/client.go:254-264) the container is created attached to at
	// most ONE endpoint; the full connectivity is applied in step 7.
	simpleNetworkConfig := firstEndpointOnly(networkConfig)
	created, err := r.api.ContainerCreate(ctx, createConfig, hostConfig, simpleNetworkConfig, nil, name)
	if err != nil {
		r.reviveFailedContainer(ctx, res)
		return res, fmt.Errorf("rollback: creating restored container %q: %w", name, err)
	}
	res.ContainerID = created.ID

	// Step 7: reconnect networks (host mode skips, upstream client.go:275).
	if !isHostNetwork(hostConfig) {
		for _, netName := range sortedNetworkNames(simpleNetworkConfig.EndpointsConfig) {
			if err := r.api.NetworkDisconnect(ctx, netName, created.ID, true); err != nil {
				return res, r.abortAfterCreate(ctx, res, fmt.Errorf("rollback: disconnecting %q from restored container %s: %w", netName, created.ID, err))
			}
		}
		for _, netName := range sortedNetworkNames(networkConfig.EndpointsConfig) {
			if err := r.api.NetworkConnect(ctx, netName, created.ID, networkConfig.EndpointsConfig[netName]); err != nil {
				return res, r.abortAfterCreate(ctx, res, fmt.Errorf("rollback: connecting restored container %s to network %q: %w", created.ID, netName, err))
			}
		}
	}

	// Step 8: start. Only a successful start counts as restored.
	if err := r.api.ContainerStart(ctx, created.ID, types.ContainerStartOptions{}); err != nil {
		return res, r.abortAfterCreate(ctx, res, fmt.Errorf("rollback: starting restored container %s (%q): %w", created.ID, name, err))
	}
	res.Restored = true
	return res, nil
}

// buildConfigs derives the create, host and network configs from the
// snapshot. It operates on a deep copy, so the snapshot's Inspect is never
// mutated (the caller may hold it concurrently, e.g. a retry).
func (r *Restorer) buildConfigs(snap safeflow.Snapshot) (*dockercontainer.Config, *dockercontainer.HostConfig, *network.NetworkingConfig, error) {
	inspect, err := deepCopyContainerJSON(snap.Inspect)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("deep-copy snapshot inspect: %w", err)
	}

	// Config is passed through AS-IS on purpose. Upstream GetCreateConfig
	// (pkg/container/container.go:283-348) subtracts the image's defaults from
	// the container config so a newer image can change them - exactly wrong
	// for a rollback, whose whole point is reproducing the recorded container.
	// Keeping the snapshot values verbatim also preserves fields that happen
	// to equal the image defaults ("explicitly set = image default").
	//
	// Image is deliberately the immutable local image ID, not the tag the
	// container was started with: the update flow already re-pulled the same
	// tag before the gate failed, so a tag reference would resolve to the new
	// (failed or poisoned) image instead of the verified old one. See the
	// RollbackDetailed step-5 contract above.
	createConfig := inspect.Config
	createConfig.Image = snap.ImageID()

	hostConfig := inspect.HostConfig

	// Rebuild endpoint configs with the old container ID's short alias
	// stripped (mirrors pkg/container/client.go:231-244): docker adds
	// "<short-id>" as a network alias on every endpoint, and re-submitting it
	// for a new container ID would accumulate stale aliases across updates.
	networkConfig := &network.NetworkingConfig{
		EndpointsConfig: make(map[string]*network.EndpointSettings),
	}
	if inspect.NetworkSettings != nil {
		shortID := shortContainerID(inspect.ID)
		for netName, ep := range inspect.NetworkSettings.Networks {
			aliases := make([]string, 0, len(ep.Aliases))
			for _, alias := range ep.Aliases {
				if alias == shortID {
					continue
				}
				aliases = append(aliases, alias)
			}
			ep.Aliases = aliases
			networkConfig.EndpointsConfig[netName] = ep
		}
	}

	return createConfig, hostConfig, networkConfig, nil
}

// captureLogs grabs the last logTailLines lines from the failed container.
// Any error is tolerated (the container may be too broken to serve logs) and
// yields an empty string - rollback must still proceed.
func (r *Restorer) captureLogs(ctx context.Context, containerName string, snap safeflow.Snapshot) string {
	reader, err := r.api.ContainerLogs(ctx, containerName, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       strconv.Itoa(logTailLines),
	})
	if err != nil {
		log.Printf("rollback: capturing logs of failed container %q failed (tolerated): %v", containerName, err)
		return ""
	}
	defer reader.Close()

	raw, err := io.ReadAll(reader)
	if err != nil {
		log.Printf("rollback: reading logs of failed container %q failed (tolerated): %v", containerName, err)
		return ""
	}

	// Non-TTY containers get stdout/stderr multiplexed with an 8-byte frame
	// header per chunk; TTY containers get a plain stream (see the SDK's
	// ContainerLogs doc).
	if snap.Inspect.Config != nil && snap.Inspect.Config.Tty {
		return string(raw)
	}
	return string(demultiplexDockerStream(raw))
}

// demultiplexDockerStream strips the [STREAM_TYPE, 0, 0, 0, SIZE...] frame
// headers the daemon prepends to non-TTY log streams and concatenates the
// payloads. Truncated or malformed trailing data is appended verbatim rather
// than dropped - this is forensic output, best-effort by design.
func demultiplexDockerStream(raw []byte) []byte {
	var out []byte
	for len(raw) >= 8 {
		size := binary.BigEndian.Uint32(raw[4:8])
		if uint64(size) > uint64(len(raw)-8) {
			break // truncated frame
		}
		out = append(out, raw[8:8+size]...)
		raw = raw[8+size:]
	}
	return append(out, raw...)
}

// abortAfterCreate handles failures after the replacement container exists
// (steps 7/8): the unusable replacement is force-removed so the original name
// is free for a retry, and the renamed failed container is revived
// best-effort so the service is not down twice. Cleanup errors are logged,
// never mask the original error.
func (r *Restorer) abortAfterCreate(ctx context.Context, res RollbackResult, cause error) error {
	if res.ContainerID != "" {
		if err := r.api.ContainerRemove(ctx, res.ContainerID, types.ContainerRemoveOptions{Force: true}); err != nil && !isNotFound(err) {
			log.Printf("rollback: removing unusable replacement %s failed: %v", res.ContainerID, err)
		}
	}
	r.reviveFailedContainer(ctx, res)
	return cause
}

// reviveFailedContainer best-effort starts the renamed failed container to
// avoid leaving the service down after a failed rollback. Errors are logged
// only; the caller's error is the authoritative one.
func (r *Restorer) reviveFailedContainer(ctx context.Context, res RollbackResult) {
	if res.FailedRenamedTo == "" {
		return
	}
	if err := r.api.ContainerStart(ctx, res.FailedRenamedTo, types.ContainerStartOptions{}); err != nil {
		log.Printf("rollback: reviving failed container %q after unsuccessful rollback failed: %v", res.FailedRenamedTo, err)
		return
	}
	log.Printf("rollback: revived failed container %q after unsuccessful rollback", res.FailedRenamedTo)
}

// isDrydockOwnContainer reports whether the snapshotted container is Drydock
// (or its ancestor watchtower) itself, detected via the
// "com.centurylinklabs.watchtower" label key.
func isDrydockOwnContainer(snap safeflow.Snapshot) bool {
	if snap.Inspect.Config == nil {
		return false
	}
	_, ok := snap.Inspect.Config.Labels[watchtowerLabelKey]
	return ok
}

// isHostNetwork reports whether the container uses the host network stack.
// It deliberately does NOT use NetworkMode.IsHost(): the SDK hardcodes that
// method to false on Windows builds (api/types/container/hostconfig_windows.go:11-13),
// which would misfire for a Linux daemon driven from a Windows Drydock binary
// (DOCKER_HOST can point anywhere). A plain comparison is platform-neutral.
func isHostNetwork(hostConfig *dockercontainer.HostConfig) bool {
	return hostConfig != nil && string(hostConfig.NetworkMode) == "host"
}

// shortContainerID returns the leading 12 characters of a container ID
// (docker's "short ID" form, used as the network alias that must be
// stripped on recreate).
func shortContainerID(id string) string {
	if len(id) > dockerShortIDLen {
		return id[:dockerShortIDLen]
	}
	return id
}

// firstEndpointOnly mirrors upstream's docker#29265 workaround
// (pkg/container/client.go:254-264): a networking config carrying only the
// first (deterministically: lexicographically smallest) endpoint, so
// ContainerCreate never receives multiple endpoints.
func firstEndpointOnly(config *network.NetworkingConfig) *network.NetworkingConfig {
	single := &network.NetworkingConfig{EndpointsConfig: make(map[string]*network.EndpointSettings)}
	for _, netName := range sortedNetworkNames(config.EndpointsConfig) {
		single.EndpointsConfig[netName] = config.EndpointsConfig[netName]
		break
	}
	return single
}

// sortedNetworkNames iterates endpoint maps deterministically (Go map order
// is random; upstream tolerates that, tests should not have to).
func sortedNetworkNames(endpoints map[string]*network.EndpointSettings) []string {
	names := make([]string, 0, len(endpoints))
	for netName := range endpoints {
		names = append(names, netName)
	}
	sort.Strings(names)
	return names
}

func (r *Restorer) stopTimeout() time.Duration {
	if r.StopTimeout <= 0 {
		return defaultStopTimeout
	}
	return r.StopTimeout
}

func secondsPtr(d time.Duration) *int {
	secs := int(d / time.Second)
	return &secs
}

// isNotFound reports whether err means "the object is already gone" for
// stop/remove/inspect calls. The typed check is the SDK's own
// client.IsErrNotFound; the message fallbacks keep detection working for
// plain errors (as returned by older daemons and by test doubles).
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if sdkclient.IsErrNotFound(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such container") ||
		strings.Contains(msg, "no such image") ||
		strings.Contains(msg, "no such network")
}
