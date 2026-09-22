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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// ---------------------------------------------------------------------------
// Fixture: modeled on upstream pkg/container/mocks/data/container_running.json
// (the "portainer" running-container fixture; its State carries no Health key,
// which this literal reproduces by leaving ContainerState.Health nil).
// ---------------------------------------------------------------------------

const (
	fixtureContainerID = "b978af0b858aa8855cce46b628817d4ed58e58f2c4f66c9b9c5449134ed4c008"
	fixtureShortID     = "b978af0b858a"
	fixtureImageID     = "sha256:19d07168491a3f9e2798a9bed96544e34d57ddc4757a4ac5bb199dea896c87fd"
	fixtureNetworkID   = "9352796e0330dcf31ce3d44fae4b719304b8b3fd97b02ade3aefb8737251682b"
)

func fixtureInspect() types.ContainerJSON {
	return types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:      fixtureContainerID,
			Name:    "/portainer",
			Image:   fixtureImageID,
			Created: "2019-04-04T20:28:32.5710901Z",
			State: &types.ContainerState{ // no Health key, like the upstream fixture
				Status:     "running",
				Running:    true,
				Pid:        3854,
				ExitCode:   0,
				StartedAt:  "2019-04-13T22:38:24.498745809Z",
				FinishedAt: "2019-04-13T22:38:18.486292076Z",
			},
			HostConfig: &dockercontainer.HostConfig{
				Binds: []string{
					"portainer_data:/data",
					"/var/run/docker.sock:/var/run/docker.sock",
				},
				NetworkMode: "default",
				PortBindings: nat.PortMap{
					"9000/tcp": []nat.PortBinding{{HostIP: "", HostPort: "9000"}},
				},
				RestartPolicy: dockercontainer.RestartPolicy{Name: "always"},
				AutoRemove:    false,
			},
		},
		Config: &dockercontainer.Config{
			Hostname:     "822f0f2efd78",
			Image:        "portainer/portainer:latest",
			Env:          []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			Entrypoint:   []string{"/portainer"},
			WorkingDir:   "/",
			ExposedPorts: nat.PortSet{"9000/tcp": struct{}{}},
			Volumes:      map[string]struct{}{"/data": {}},
			Labels:       map[string]string{"com.example.owner": "team-a"},
			Tty:          false,
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"bridge": {
					NetworkID: fixtureNetworkID,
					// docker adds the short container ID as an endpoint alias;
					// the restore path must strip it before re-submitting.
					Aliases: []string{fixtureShortID, "portainer"},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// In-memory fake Docker client (records the call sequence; no daemon, no net).
// ---------------------------------------------------------------------------

type fakeAPIClient struct {
	calls []string

	failLogs       error
	failRename     error
	failStop       error
	failImage      error
	failCreate     error
	failDisconnect error
	failConnect    error
	failStart      error

	createResponse dockercontainer.CreateResponse
	logsPayload    []byte

	lastCreateConfig    *dockercontainer.Config
	lastCreateHost      *dockercontainer.HostConfig
	lastCreateNetwork   *network.NetworkingConfig
	lastCreateName      string
	lastConnectEndpoint map[string]*network.EndpointSettings
}

func newFakeAPIClient() *fakeAPIClient {
	return &fakeAPIClient{
		createResponse: dockercontainer.CreateResponse{ID: "restored-1"},
		logsPayload:    append(dockerFrame(1, "line1\n"), dockerFrame(2, "boom\n")...),
	}
}

func dockerFrame(stream byte, payload string) []byte {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))
	return append(header, payload...)
}

func (f *fakeAPIClient) ContainerLogs(_ context.Context, container string, opts types.ContainerLogsOptions) (io.ReadCloser, error) {
	f.calls = append(f.calls, fmt.Sprintf("logs:%s:tail=%s", container, opts.Tail))
	if f.failLogs != nil {
		return nil, f.failLogs
	}
	return io.NopCloser(bytes.NewReader(f.logsPayload)), nil
}

func (f *fakeAPIClient) ContainerRename(_ context.Context, containerID, newName string) error {
	f.calls = append(f.calls, fmt.Sprintf("rename:%s->%s", containerID, newName))
	return f.failRename
}

func (f *fakeAPIClient) ContainerStop(_ context.Context, containerID string, opts dockercontainer.StopOptions) error {
	timeout := -1
	if opts.Timeout != nil {
		timeout = *opts.Timeout
	}
	f.calls = append(f.calls, fmt.Sprintf("stop:%s:t=%d:s=%s", containerID, timeout, opts.Signal))
	return f.failStop
}

func (f *fakeAPIClient) ContainerRemove(_ context.Context, containerID string, opts types.ContainerRemoveOptions) error {
	f.calls = append(f.calls, fmt.Sprintf("remove:%s:force=%t", containerID, opts.Force))
	return nil
}

func (f *fakeAPIClient) ImageInspectWithRaw(_ context.Context, imageID string) (types.ImageInspect, []byte, error) {
	f.calls = append(f.calls, "image-inspect:"+imageID)
	if f.failImage != nil {
		return types.ImageInspect{}, nil, f.failImage
	}
	return types.ImageInspect{ID: imageID}, []byte("{}"), nil
}

func (f *fakeAPIClient) ContainerCreate(_ context.Context, config *dockercontainer.Config, hostConfig *dockercontainer.HostConfig, networkingConfig *network.NetworkingConfig, _ *ocispec.Platform, containerName string) (dockercontainer.CreateResponse, error) {
	f.calls = append(f.calls, fmt.Sprintf("create:%s:%s", config.Image, containerName))
	f.lastCreateConfig = config
	f.lastCreateHost = hostConfig
	f.lastCreateNetwork = networkingConfig
	f.lastCreateName = containerName
	if f.failCreate != nil {
		return dockercontainer.CreateResponse{}, f.failCreate
	}
	return f.createResponse, nil
}

func (f *fakeAPIClient) NetworkDisconnect(_ context.Context, networkID, containerID string, force bool) error {
	f.calls = append(f.calls, fmt.Sprintf("disconnect:%s:%s:force=%t", networkID, containerID, force))
	return f.failDisconnect
}

func (f *fakeAPIClient) NetworkConnect(_ context.Context, networkID, containerID string, config *network.EndpointSettings) error {
	f.calls = append(f.calls, fmt.Sprintf("connect:%s:%s:aliases=%s", networkID, containerID, strings.Join(config.Aliases, ",")))
	if f.lastConnectEndpoint == nil {
		f.lastConnectEndpoint = map[string]*network.EndpointSettings{}
	}
	f.lastConnectEndpoint[networkID] = config
	return f.failConnect
}

func (f *fakeAPIClient) ContainerStart(_ context.Context, containerID string, _ types.ContainerStartOptions) error {
	f.calls = append(f.calls, "start:"+containerID)
	return f.failStart
}

// ---------------------------------------------------------------------------
// Small stdlib-only assertion helpers.
// ---------------------------------------------------------------------------

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func requireError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func requireErrorsIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error %q does not wrap %q", err, target)
	}
}

func requireDeepEqual(t *testing.T, label string, want, got interface{}) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%s mismatch:\n want: %#v\n  got: %#v", label, want, got)
	}
}

func requireCalls(t *testing.T, want, got []string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("call sequence mismatch:\n want: %q\n  got: %q", want, got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("call sequence mismatch at step %d:\n want: %q\n  got: %q", i+1, want, got)
		}
	}
}

func snapshotFiles(t *testing.T, dir, name string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	requireNoError(t, err)
	var files []string
	for _, e := range entries {
		base := e.Name()
		if strings.HasPrefix(base, name+"-") && strings.HasSuffix(base, ".json") {
			files = append(files, base)
		}
	}
	return files
}

// takeBase is the frozen clock newStore starts from; each Take advances it by
// one second.
var takeBase = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// firstTakeID is the snapshot ID of the first Take from a fresh store.
func firstTakeID() string {
	return snapshotID("portainer", takeBase.Add(time.Second))
}

// newStore returns a store whose clock advances one second per Take, keeping
// CreatedAt ordering deterministic.
func newStore(t *testing.T, dir string) *FileSnapshotStore {
	t.Helper()
	n := 0
	store := NewFileSnapshotStore(dir)
	store.now = func() time.Time {
		n++
		return takeBase.Add(time.Duration(n) * time.Second)
	}
	return store
}

func newRestorer(fake *fakeAPIClient) *Restorer {
	r := NewRestorer(fake)
	r.now = func() time.Time { return time.Unix(1690000000, 0) } // 1690000000000000000 ns
	return r
}

const frozenNano = "1690000000000000000"

// ---------------------------------------------------------------------------
// FileSnapshotStore tests.
// ---------------------------------------------------------------------------

func TestFileSnapshotStoreTakePersistsJSONFile(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir)

	snap, err := store.Take(context.Background(), fixtureInspect())
	requireNoError(t, err)

	if snap.ContainerName != "portainer" {
		t.Fatalf("ContainerName = %q, want %q (leading / stripped)", snap.ContainerName, "portainer")
	}
	wantFile := filepath.Join(dir, firstTakeID()+".json")
	if snap.ID != firstTakeID() {
		t.Fatalf("snapshot ID = %q, want %q", snap.ID, firstTakeID())
	}
	if _, err := os.Stat(wantFile); err != nil {
		t.Fatalf("snapshot file missing after Take: %v", err)
	}
	// Exactly one file: the atomic write must not leave temp files behind.
	files := snapshotFiles(t, dir, "portainer")
	if len(files) != 1 {
		t.Fatalf("found %d snapshot files (%q), want 1", len(files), files)
	}

	// The file content must be the JSON encoding of the snapshot.
	data, err := os.ReadFile(wantFile)
	requireNoError(t, err)
	var persisted safeflow.Snapshot
	requireNoError(t, json.Unmarshal(data, &persisted))
	if persisted.ID != snap.ID || persisted.ContainerName != "portainer" {
		t.Fatalf("persisted snapshot identity = %q/%q", persisted.ID, persisted.ContainerName)
	}
	if persisted.Inspect.Config == nil || persisted.Inspect.Config.Image != "portainer/portainer:latest" {
		t.Fatalf("persisted snapshot lost Config.Image: %#v", persisted.Inspect.Config)
	}

	// Latest returns the same snapshot.
	latest, ok, err := store.Latest(context.Background(), "portainer")
	requireNoError(t, err)
	if !ok {
		t.Fatal("Latest returned ok=false after a Take")
	}
	if latest.ID != snap.ID || !latest.CreatedAt.Equal(snap.CreatedAt) {
		t.Fatalf("Latest = %q@%v, want %q@%v", latest.ID, latest.CreatedAt, snap.ID, snap.CreatedAt)
	}
	requireDeepEqual(t, "Latest Config", snap.Inspect.Config, latest.Inspect.Config)
	requireDeepEqual(t, "Latest HostConfig", snap.Inspect.HostConfig, latest.Inspect.HostConfig)
	aliases := latest.Inspect.NetworkSettings.Networks["bridge"].Aliases
	requireDeepEqual(t, "Latest aliases", []string{fixtureShortID, "portainer"}, aliases)
}

func TestFileSnapshotStoreTakeDeepCopiesInspect(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir)

	inspect := fixtureInspect()
	snap, err := store.Take(context.Background(), inspect)
	requireNoError(t, err)

	// Pollute the original inspect exactly the way the upstream recreate
	// helpers do (GetCreateConfig strips image defaults, container.go:283-348;
	// GetCreateHostConfig rewrites links, :352-363; GetNetworkConfig deletes
	// the container-ID alias, client.go:226-246) plus a few extra fields.
	inspect.Name = "/mutated"
	inspect.Config.Image = "mutated:image"
	inspect.Config.WorkingDir = ""
	inspect.Config.User = ""
	inspect.Config.Entrypoint = nil
	inspect.Config.Env = nil
	inspect.Config.Healthcheck = &dockercontainer.HealthConfig{Test: []string{"NONE"}}
	inspect.HostConfig.NetworkMode = "host"
	inspect.HostConfig.Binds = []string{"polluted:/data"}
	for _, ep := range inspect.NetworkSettings.Networks {
		ep.Aliases = []string{"polluted"}
	}

	latest, ok, err := store.Latest(context.Background(), "portainer")
	requireNoError(t, err)
	if !ok {
		t.Fatal("Latest returned ok=false")
	}
	if got := latest.Inspect.Name; got != "/portainer" {
		t.Errorf("snapshot Name polluted: %q", got)
	}
	if got := latest.Inspect.Config.Image; got != "portainer/portainer:latest" {
		t.Errorf("snapshot Config.Image polluted: %q", got)
	}
	if got := latest.Inspect.Config.WorkingDir; got != "/" {
		t.Errorf("snapshot Config.WorkingDir polluted: %q", got)
	}
	if got := latest.Inspect.Config.Entrypoint; !reflect.DeepEqual([]string(got), []string{"/portainer"}) {
		t.Errorf("snapshot Config.Entrypoint polluted: %q", got)
	}
	if len(latest.Inspect.Config.Env) != 1 || latest.Inspect.Config.Env[0] != "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Errorf("snapshot Config.Env polluted: %q", latest.Inspect.Config.Env)
	}
	if latest.Inspect.Config.Healthcheck != nil {
		t.Errorf("snapshot Config.Healthcheck polluted: %v", latest.Inspect.Config.Healthcheck)
	}
	if got := latest.Inspect.HostConfig.NetworkMode; got != "default" {
		t.Errorf("snapshot HostConfig.NetworkMode polluted: %q", got)
	}
	if got := latest.Inspect.HostConfig.Binds; !reflect.DeepEqual(got, fixtureInspect().HostConfig.Binds) {
		t.Errorf("snapshot HostConfig.Binds polluted: %q", got)
	}
	if got := latest.Inspect.NetworkSettings.Networks["bridge"].Aliases; !reflect.DeepEqual(got, []string{fixtureShortID, "portainer"}) {
		t.Errorf("snapshot endpoint aliases polluted: %q", got)
	}

	// The Take return value must not alias the caller's inspect either.
	if snap.Inspect.Config == inspect.Config {
		t.Error("snapshot shares its Config pointer with the caller's inspect")
	}
}

// redactionFixtureEnv models a container carrying a secret in its
// environment (dummy placeholder value, never a real credential).
var redactionFixtureEnv = []string{
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"POSTGRES_PASSWORD=super-secret-dummy-value",
	"FLAG_WITHOUT_EQUALS",
}

func TestFileSnapshotStoreRedactsEnvOnDisk(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir)
	store.RedactEnv = true

	inspect := fixtureInspect()
	inspect.Config.Env = append([]string{}, redactionFixtureEnv...)
	snap, err := store.Take(context.Background(), inspect)
	requireNoError(t, err)

	// The in-memory snapshot keeps the real values: this-cycle rollbacks
	// (which use it directly) must recreate an identical container.
	if !reflect.DeepEqual(snap.Inspect.Config.Env, redactionFixtureEnv) {
		t.Fatalf("in-memory snapshot env was redacted: %q", snap.Inspect.Config.Env)
	}

	// The persisted JSON carries placeholders only - the secret value must
	// not appear anywhere in the file.
	snapData, err := os.ReadFile(filepath.Join(dir, snap.ID+snapshotFileSuffix))
	requireNoError(t, err)
	if strings.Contains(string(snapData), "super-secret-dummy-value") {
		t.Fatal("persisted snapshot JSON contains the secret env value")
	}
	var persisted safeflow.Snapshot
	requireNoError(t, json.Unmarshal(snapData, &persisted))
	requireDeepEqual(t, "persisted env", []string{
		"PATH=" + redactedEnvPlaceholder,
		"POSTGRES_PASSWORD=" + redactedEnvPlaceholder,
		redactedEnvPlaceholder,
	}, persisted.Inspect.Config.Env)

	// The real values live in a 0600 sidecar next to the snapshot. (The
	// permission is asserted on POSIX only: Windows maps chmod to the
	// read-only bit, so Mode().Perm() reports 0666 no matter what.)
	sidecar := filepath.Join(dir, snap.ID+envSidecarSuffix)
	sidecarData, err := os.ReadFile(sidecar)
	requireNoError(t, err)
	var sidecarEnv []string
	requireNoError(t, json.Unmarshal(sidecarData, &sidecarEnv))
	requireDeepEqual(t, "sidecar env", redactionFixtureEnv, sidecarEnv)
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(sidecar); err != nil {
			t.Fatalf("stat sidecar: %v", err)
		} else if fi.Mode().Perm() != 0o600 {
			t.Fatalf("sidecar mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	// Latest transparently rejoins the sidecar: a Drydock restart still gets
	// a fully recreatable snapshot.
	latest, ok, err := store.Latest(context.Background(), "portainer")
	requireNoError(t, err)
	if !ok {
		t.Fatal("Latest returned ok=false after a Take")
	}
	if !reflect.DeepEqual(latest.Inspect.Config.Env, redactionFixtureEnv) {
		t.Fatalf("Latest env = %q, want the sidecar values restored", latest.Inspect.Config.Env)
	}
}

func TestFileSnapshotStoreWithoutRedactionKeepsEnvInline(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir) // RedactEnv defaults to false

	inspect := fixtureInspect()
	inspect.Config.Env = append([]string{}, redactionFixtureEnv...)
	snap, err := store.Take(context.Background(), inspect)
	requireNoError(t, err)

	// No sidecar is written and the JSON keeps the values verbatim
	// (pre-redaction behavior for library consumers).
	if _, err := os.Stat(filepath.Join(dir, snap.ID+envSidecarSuffix)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sidecar exists although RedactEnv is off: %v", err)
	}
	snapData, err := os.ReadFile(filepath.Join(dir, snap.ID+snapshotFileSuffix))
	requireNoError(t, err)
	if !strings.Contains(string(snapData), "super-secret-dummy-value") {
		t.Fatal("plaintext snapshot (RedactEnv=false) lost the env values")
	}
}

func TestFileSnapshotStorePruneRemovesEnvSidecars(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir)
	store.RedactEnv = true

	inspect := fixtureInspect()
	inspect.Config.Env = append([]string{}, redactionFixtureEnv...)
	for i := 0; i < 3; i++ {
		_, err := store.Take(context.Background(), inspect)
		requireNoError(t, err)
	}

	requireNoError(t, store.Prune(context.Background(), "portainer", 1))

	entries, err := os.ReadDir(dir)
	requireNoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// Exactly the newest snapshot AND its sidecar survive; orphaned
	// secret-bearing sidecars must not outlive their snapshots.
	newest := snapshotID("portainer", takeBase.Add(3*time.Second))
	want := []string{newest + envSidecarSuffix, newest + snapshotFileSuffix}
	sort.Strings(want)
	got := append([]string{}, names...)
	if len(got) != 2 {
		t.Fatalf("files after prune = %q, want exactly %q", got, want)
	}
	requireDeepEqual(t, "pruned file set", want, got)
}

func TestRedactEnvValues(t *testing.T) {
	env := []string{"A=1", "NO_EQUALS_SIGN", "B=two=equals"}
	redactEnvValues(env)
	requireDeepEqual(t, "redacted env", []string{
		"A=" + redactedEnvPlaceholder,
		redactedEnvPlaceholder,
		"B=" + redactedEnvPlaceholder,
	}, env)
}

func TestFileSnapshotStoreTakeInvalidRefusesToPersist(t *testing.T) {
	for name, mutate := range map[string]func(*types.ContainerJSON){
		"no base":           func(j *types.ContainerJSON) { j.ContainerJSONBase = nil },
		"nil config":        func(j *types.ContainerJSON) { j.Config = nil },
		"nil host config":   func(j *types.ContainerJSON) { j.HostConfig = nil },
		"empty image ref":   func(j *types.ContainerJSON) { j.Config.Image = "" },
		"empty image id":    func(j *types.ContainerJSON) { j.ContainerJSONBase.Image = "" },
		"unnamed container": func(j *types.ContainerJSON) { j.ContainerJSONBase.Name = "" },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			store := newStore(t, dir)
			inspect := fixtureInspect()
			mutate(&inspect)

			snap, err := store.Take(context.Background(), inspect)
			requireError(t, err)
			requireErrorsIs(t, err, safeflow.ErrSnapshotInvalid)
			if snap.ID != "" {
				t.Errorf("Take returned snapshot %+v on error", snap)
			}
			if files := snapshotFiles(t, dir, "portainer"); len(files) != 0 {
				t.Fatalf("invalid snapshot was persisted: %q", files)
			}
		})
	}
}

func TestFileSnapshotStoreLatestEmptyIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir)

	got, ok, err := store.Latest(context.Background(), "portainer")
	requireNoError(t, err)
	if ok {
		t.Fatalf("Latest on empty store returned ok=true: %+v", got)
	}
	if got.ID != "" || got.ContainerName != "" || got.Inspect.ContainerJSONBase != nil {
		t.Fatalf("Latest on empty store returned non-zero snapshot: %+v", got)
	}

	// Snapshots for other names must not leak into this lookup.
	other := fixtureInspect()
	other.Name = "/other-runner"
	_, err = store.Take(context.Background(), other)
	requireNoError(t, err)
	got, ok, err = store.Latest(context.Background(), "portainer")
	requireNoError(t, err)
	if ok {
		t.Fatalf("Latest(portainer) leaked a snapshot of another container: %+v", got)
	}
}

func TestFileSnapshotStoreLatestSkipsCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir)

	_, err := store.Take(context.Background(), fixtureInspect())
	requireNoError(t, err)
	requireNoError(t, os.WriteFile(filepath.Join(dir, "portainer-9999999999999999999.json"), []byte("{not json"), 0o600))

	got, ok, err := store.Latest(context.Background(), "portainer")
	requireNoError(t, err)
	if !ok {
		t.Fatal("Latest failed to see the valid snapshot alongside a corrupt one")
	}
	if got.ID != firstTakeID() {
		t.Fatalf("Latest picked %q, want the only valid snapshot", got.ID)
	}
}

func TestFileSnapshotStorePrune(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir)

	var ids []string
	for i := 0; i < 3; i++ {
		snap, err := store.Take(context.Background(), fixtureInspect())
		requireNoError(t, err)
		ids = append(ids, snap.ID)
	}
	other := fixtureInspect()
	other.Name = "/other-runner"
	otherSnap, err := store.Take(context.Background(), other)
	requireNoError(t, err)

	// keep=2: the oldest portainer snapshot goes, the other name is untouched.
	requireNoError(t, store.Prune(context.Background(), "portainer", 2))
	requireDeepEqual(t, "remaining after keep=2",
		[]string{ids[1] + ".json", ids[2] + ".json"}, snapshotFiles(t, dir, "portainer"))
	if files := snapshotFiles(t, dir, "other-runner"); len(files) != 1 || files[0] != otherSnap.ID+".json" {
		t.Fatalf("prune of portainer touched other-runner: %q", files)
	}

	// keep larger than the count: no-op, no error.
	requireNoError(t, store.Prune(context.Background(), "portainer", 5))
	if got := len(snapshotFiles(t, dir, "portainer")); got != 2 {
		t.Fatalf("keep=5 deleted files: %d remain", got)
	}

	// keep=0 and negative keeps delete everything for that name.
	requireNoError(t, store.Prune(context.Background(), "portainer", 0))
	if got := snapshotFiles(t, dir, "portainer"); len(got) != 0 {
		t.Fatalf("keep=0 left files behind: %q", got)
	}
	requireNoError(t, store.Prune(context.Background(), "other-runner", -1))
	if got := snapshotFiles(t, dir, "other-runner"); len(got) != 0 {
		t.Fatalf("keep=-1 left files behind: %q", got)
	}

	// Pruning a name with no snapshots at all is fine.
	requireNoError(t, store.Prune(context.Background(), "ghost", 3))
}

func TestFileSnapshotStorePruneToleratesSingleFileFailure(t *testing.T) {
	dir := t.TempDir()
	store := newStore(t, dir)

	older, err := store.Take(context.Background(), fixtureInspect())
	requireNoError(t, err)
	newer, err := store.Take(context.Background(), fixtureInspect())
	requireNoError(t, err)

	// Simulate one undeletable file via the remove seam. (A chmod 0444 is not
	// portable anymore: Go 1.25+ clears the read-only attribute on Windows, so
	// os.Remove succeeds there.)
	protected := filepath.Join(dir, newer.ID+".json")
	store.remove = func(path string) error {
		if path == protected {
			return errors.New("simulated: file locked by a backup agent")
		}
		return os.Remove(path)
	}

	// keep=1 wants to delete `older` only - that must succeed; the prune as a
	// whole must never fail because of one file.
	requireNoError(t, store.Prune(context.Background(), "portainer", 1))
	if _, err := os.Stat(filepath.Join(dir, older.ID+".json")); !os.IsNotExist(err) {
		t.Fatalf("older snapshot not pruned: %v", err)
	}
	if _, err := os.Stat(protected); err != nil {
		t.Fatalf("protected snapshot unexpectedly removed: %v", err)
	}

	// keep=0 cannot delete the protected file either, but must still report
	// success (the failure is logged, not returned).
	requireNoError(t, store.Prune(context.Background(), "portainer", 0))
	if _, err := os.Stat(protected); err != nil {
		t.Fatalf("protected snapshot unexpectedly removed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Restorer tests.
// ---------------------------------------------------------------------------

func TestRestorerSuccessSequence(t *testing.T) {
	fake := newFakeAPIClient()
	restorer := newRestorer(fake)

	snap := safeflow.Snapshot{
		ID:            "portainer-1",
		ContainerName: "portainer",
		CreatedAt:     time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
		Inspect:       fixtureInspect(),
	}

	res, err := restorer.RollbackDetailed(context.Background(), snap)
	requireNoError(t, err)

	if !res.Restored {
		t.Fatalf("Restored = false, want true (result: %+v)", res)
	}
	if res.ContainerID != "restored-1" {
		t.Fatalf("ContainerID = %q, want restored-1", res.ContainerID)
	}
	if res.FailedLogs != "line1\nboom\n" {
		t.Fatalf("FailedLogs = %q, want demultiplexed log tail", res.FailedLogs)
	}
	if res.FailedRenamedTo != "drydock-failed-portainer-"+frozenNano {
		t.Fatalf("FailedRenamedTo = %q", res.FailedRenamedTo)
	}

	renamed := "drydock-failed-portainer-" + frozenNano
	requireCalls(t, []string{
		// 1: logs first, tail 50, before anything can stop or auto-remove it.
		"logs:portainer:tail=50",
		// 2: rename for forensics, freeing the name.
		"rename:portainer->" + renamed,
		// 3: graceful stop (default 60s window), never a remove.
		"stop:" + renamed + ":t=60:s=",
		// 4: the old image must still exist.
		"image-inspect:" + fixtureImageID,
		// 5+6: create under the original name, pinned to the immutable image
		// ID that step 4 just verified - never the (re-pulled) tag.
		"create:" + fixtureImageID + ":portainer",
		// 7: upstream reconnect dance - disconnect the single create-time
		// endpoint, then reconnect with the full endpoint config.
		"disconnect:bridge:restored-1:force=true",
		"connect:bridge:restored-1:aliases=portainer",
		// 8: start.
		"start:restored-1",
	}, fake.calls)

	// Config must be the snapshot's Config passed through verbatim (no
	// image-default subtraction a la upstream GetCreateConfig), and its Image
	// must be the immutable image ID - byte-for-byte the reference the
	// existence check (image-inspect above) verified.
	cfg := fake.lastCreateConfig
	if cfg.Image != fixtureImageID {
		t.Errorf("create Config.Image = %q, want the verified snapshot image ID %q", cfg.Image, fixtureImageID)
	}
	if cfg.WorkingDir != "/" || cfg.User != "" || cfg.Hostname != "822f0f2efd78" {
		t.Errorf("create Config lost pass-through fields: %#v", cfg)
	}
	if !reflect.DeepEqual([]string(cfg.Entrypoint), []string{"/portainer"}) || len(cfg.Env) != 1 {
		t.Errorf("create Config lost Env/Entrypoint: %#v", cfg)
	}
	if got := fake.lastCreateHost.NetworkMode; got != "default" {
		t.Errorf("create HostConfig.NetworkMode = %q", got)
	}
	if !reflect.DeepEqual(fake.lastCreateHost.Binds, fixtureInspect().HostConfig.Binds) {
		t.Errorf("create HostConfig.Binds = %q", fake.lastCreateHost.Binds)
	}

	// The old container ID's short alias must have been stripped from the
	// endpoint config handed to NetworkConnect.
	ep := fake.lastConnectEndpoint["bridge"]
	if ep == nil {
		t.Fatal("NetworkConnect was not called for network bridge")
	}
	requireDeepEqual(t, "connected aliases", []string{"portainer"}, ep.Aliases)

	// The snapshot itself must not be mutated by the rollback.
	if snap.Inspect.Config.Image != "portainer/portainer:latest" {
		t.Errorf("rollback mutated snapshot Config.Image: %q", snap.Inspect.Config.Image)
	}
	if got := snap.Inspect.NetworkSettings.Networks["bridge"].Aliases; !reflect.DeepEqual(got, []string{fixtureShortID, "portainer"}) {
		t.Errorf("rollback mutated snapshot endpoint aliases: %q", got)
	}
}

func TestRestorerImplementsSafeflowRollbacker(t *testing.T) {
	var rollbacker safeflow.Rollbacker = newRestorer(newFakeAPIClient())

	id, err := rollbacker.Rollback(context.Background(), snapshotFromFixture(t, nil))
	requireNoError(t, err)
	if id != "restored-1" {
		t.Fatalf("Rollback returned id %q, want restored-1", id)
	}
}

// snapshotFromFixture builds a validated snapshot from the fixture inspect,
// optionally mutating the inspect first.
func snapshotFromFixture(t *testing.T, mutate func(*types.ContainerJSON)) safeflow.Snapshot {
	t.Helper()
	inspect := fixtureInspect()
	if mutate != nil {
		mutate(&inspect)
	}
	snap := safeflow.Snapshot{
		ID:            "portainer-1",
		ContainerName: containerName(inspect.Name),
		CreatedAt:     time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
		Inspect:       inspect,
	}
	requireNoError(t, snap.Validate())
	return snap
}

func TestRestorerImageMissingAbortsBeforeCreate(t *testing.T) {
	fake := newFakeAPIClient()
	fake.failImage = errors.New("Error response from daemon: No such image: " + fixtureImageID)
	restorer := newRestorer(fake)

	res, err := restorer.RollbackDetailed(context.Background(), snapshotFromFixture(t, nil))
	requireError(t, err)
	requireErrorsIs(t, err, safeflow.ErrRollbackImageMissing)
	if res.Restored {
		t.Fatal("Restored = true despite missing image")
	}
	if res.ContainerID != "" {
		t.Fatalf("ContainerID = %q, want empty (nothing created)", res.ContainerID)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "create:") || strings.HasPrefix(call, "start:") {
			t.Fatalf("ContainerCreate/Start must not run when the image is missing, got %q", call)
		}
	}
	// Steps 1-4 still ran, in order.
	requireCalls(t, []string{
		"logs:portainer:tail=50",
		"rename:portainer->drydock-failed-portainer-" + frozenNano,
		"stop:drydock-failed-portainer-" + frozenNano + ":t=60:s=",
		"image-inspect:" + fixtureImageID,
	}, fake.calls)
}

func TestRestorerRenameFailureAbortsBeforeStopAndCreate(t *testing.T) {
	fake := newFakeAPIClient()
	fake.failRename = errors.New("Error response from daemon: rename conflict")
	restorer := newRestorer(fake)

	res, err := restorer.RollbackDetailed(context.Background(), snapshotFromFixture(t, nil))
	requireError(t, err)
	if !strings.Contains(err.Error(), "renaming failed container") {
		t.Fatalf("error does not identify the rename step: %v", err)
	}
	if res.Restored || res.ContainerID != "" || res.FailedRenamedTo != "" {
		t.Fatalf("partial result not as expected: %+v", res)
	}
	requireCalls(t, []string{
		"logs:portainer:tail=50",
		"rename:portainer->drydock-failed-portainer-" + frozenNano,
	}, fake.calls)
}

func TestRestorerStopFailureAbortsBeforeCreate(t *testing.T) {
	fake := newFakeAPIClient()
	fake.failStop = errors.New("Error response from daemon: container is marked for removal")
	restorer := newRestorer(fake)

	res, err := restorer.RollbackDetailed(context.Background(), snapshotFromFixture(t, nil))
	requireError(t, err)
	if res.Restored || res.ContainerID != "" {
		t.Fatalf("partial result not as expected: %+v", res)
	}
	if res.FailedRenamedTo != "drydock-failed-portainer-"+frozenNano {
		t.Fatalf("FailedRenamedTo = %q, want it filled before the failed stop", res.FailedRenamedTo)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "create:") || strings.HasPrefix(call, "start:") || strings.HasPrefix(call, "remove:") {
			t.Fatalf("no create/start/remove may run when stop fails, got %q", call)
		}
	}
	// The renamed failed container was neither removed nor revived.
	renamed := "drydock-failed-portainer-" + frozenNano
	requireCalls(t, []string{
		"logs:portainer:tail=50",
		"rename:portainer->" + renamed,
		"stop:" + renamed + ":t=60:s=",
	}, fake.calls)
}

func TestRestorerStopNotFoundIsTolerated(t *testing.T) {
	fake := newFakeAPIClient()
	// AutoRemove containers self-destruct; a NotFound from stop is success.
	fake.failStop = errors.New("Error response from daemon: No such container: drydock-failed-portainer-" + frozenNano)
	restorer := newRestorer(fake)

	res, err := restorer.RollbackDetailed(context.Background(), snapshotFromFixture(t, nil))
	requireNoError(t, err)
	if !res.Restored {
		t.Fatalf("Restored = false, want true: %+v", res)
	}
	requireCalls(t, []string{
		"logs:portainer:tail=50",
		"rename:portainer->drydock-failed-portainer-" + frozenNano,
		"stop:drydock-failed-portainer-" + frozenNano + ":t=60:s=",
		"image-inspect:" + fixtureImageID,
		"create:" + fixtureImageID + ":portainer",
		"disconnect:bridge:restored-1:force=true",
		"connect:bridge:restored-1:aliases=portainer",
		"start:restored-1",
	}, fake.calls)
}

func TestRestorerLogsFailureIsTolerated(t *testing.T) {
	fake := newFakeAPIClient()
	fake.failLogs = errors.New("connection refused")
	restorer := newRestorer(fake)

	res, err := restorer.RollbackDetailed(context.Background(), snapshotFromFixture(t, nil))
	requireNoError(t, err)
	if res.FailedLogs != "" {
		t.Fatalf("FailedLogs = %q, want empty string on capture failure", res.FailedLogs)
	}
	if !res.Restored {
		t.Fatalf("rollback must proceed despite log capture failure: %+v", res)
	}
}

func TestRestorerCreateFailureRevivesFailedContainer(t *testing.T) {
	fake := newFakeAPIClient()
	fake.failCreate = errors.New("Error response from daemon: driver failure")
	restorer := newRestorer(fake)

	res, err := restorer.RollbackDetailed(context.Background(), snapshotFromFixture(t, nil))
	requireError(t, err)
	if res.Restored || res.ContainerID != "" {
		t.Fatalf("partial result not as expected: %+v", res)
	}
	requireCalls(t, []string{
		"logs:portainer:tail=50",
		"rename:portainer->drydock-failed-portainer-" + frozenNano,
		"stop:drydock-failed-portainer-" + frozenNano + ":t=60:s=",
		"image-inspect:" + fixtureImageID,
		"create:" + fixtureImageID + ":portainer",
		// best-effort revival of the renamed failed container, avoiding
		// double downtime; nothing was created, so nothing to remove.
		"start:drydock-failed-portainer-" + frozenNano,
	}, fake.calls)
}

func TestRestorerConnectFailureRemovesReplacementAndRevives(t *testing.T) {
	fake := newFakeAPIClient()
	fake.failConnect = errors.New("Error response from daemon: network bridge not found")
	restorer := newRestorer(fake)

	res, err := restorer.RollbackDetailed(context.Background(), snapshotFromFixture(t, nil))
	requireError(t, err)
	if res.Restored {
		t.Fatal("Restored = true despite connect failure")
	}
	if res.ContainerID != "restored-1" {
		t.Fatalf("ContainerID = %q, want it filled after the successful create", res.ContainerID)
	}
	requireCalls(t, []string{
		"logs:portainer:tail=50",
		"rename:portainer->drydock-failed-portainer-" + frozenNano,
		"stop:drydock-failed-portainer-" + frozenNano + ":t=60:s=",
		"image-inspect:" + fixtureImageID,
		"create:" + fixtureImageID + ":portainer",
		"disconnect:bridge:restored-1:force=true",
		"connect:bridge:restored-1:aliases=portainer",
		// the unusable replacement is force-removed to free the name, ...
		"remove:restored-1:force=true",
		// ... then the renamed failed container is revived.
		"start:drydock-failed-portainer-" + frozenNano,
	}, fake.calls)
}

func TestRestorerStartFailureRemovesReplacementAndRevives(t *testing.T) {
	fake := newFakeAPIClient()
	fake.failStart = errors.New("Error response from daemon: cannot start")
	restorer := newRestorer(fake)

	res, err := restorer.RollbackDetailed(context.Background(), snapshotFromFixture(t, nil))
	requireError(t, err)
	if res.Restored {
		t.Fatal("Restored = true despite start failure")
	}
	if res.ContainerID != "restored-1" {
		t.Fatalf("ContainerID = %q, want it filled after the successful create", res.ContainerID)
	}
	requireCalls(t, []string{
		"logs:portainer:tail=50",
		"rename:portainer->drydock-failed-portainer-" + frozenNano,
		"stop:drydock-failed-portainer-" + frozenNano + ":t=60:s=",
		"image-inspect:" + fixtureImageID,
		"create:" + fixtureImageID + ":portainer",
		"disconnect:bridge:restored-1:force=true",
		"connect:bridge:restored-1:aliases=portainer",
		"start:restored-1",
		"remove:restored-1:force=true",
		"start:drydock-failed-portainer-" + frozenNano,
	}, fake.calls)
}

func TestRestorerRefusesDrydockOwnContainer(t *testing.T) {
	fake := newFakeAPIClient()
	restorer := newRestorer(fake)

	snap := snapshotFromFixture(t, func(j *types.ContainerJSON) {
		j.Config.Labels["com.centurylinklabs.watchtower"] = "true"
	})

	res, err := restorer.RollbackDetailed(context.Background(), snap)
	requireError(t, err)
	if !strings.Contains(err.Error(), "refusing to roll back") {
		t.Fatalf("error does not state the refusal: %v", err)
	}
	if res.Restored || res.FailedRenamedTo != "" {
		t.Fatalf("refused rollback must not touch anything: %+v", res)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("refused rollback must not call docker, got %q", fake.calls)
	}
}

func TestRestorerInvalidSnapshotRejected(t *testing.T) {
	fake := newFakeAPIClient()
	restorer := newRestorer(fake)

	// Cannot go through the helper: it validates. Drop the required base.
	broken := safeflow.Snapshot{ID: "broken-1", ContainerName: "portainer", Inspect: fixtureInspect()}
	broken.Inspect.ContainerJSONBase = nil

	_, err := restorer.Rollback(context.Background(), broken)
	requireError(t, err)
	requireErrorsIs(t, err, safeflow.ErrSnapshotInvalid)
	if len(fake.calls) != 0 {
		t.Fatalf("invalid snapshot must not reach docker, got %q", fake.calls)
	}
}

func TestRestorerHostNetworkSkipsReconnect(t *testing.T) {
	fake := newFakeAPIClient()
	restorer := newRestorer(fake)

	snap := snapshotFromFixture(t, func(j *types.ContainerJSON) {
		j.HostConfig.NetworkMode = "host"
	})

	res, err := restorer.RollbackDetailed(context.Background(), snap)
	requireNoError(t, err)
	if !res.Restored {
		t.Fatalf("Restored = false, want true: %+v", res)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "disconnect:") || strings.HasPrefix(call, "connect:") {
			t.Fatalf("host network must skip reconnection, got %q", call)
		}
	}
	requireCalls(t, []string{
		"logs:portainer:tail=50",
		"rename:portainer->drydock-failed-portainer-" + frozenNano,
		"stop:drydock-failed-portainer-" + frozenNano + ":t=60:s=",
		"image-inspect:" + fixtureImageID,
		"create:" + fixtureImageID + ":portainer",
		"start:restored-1",
	}, fake.calls)
}

func TestRestorerMultiNetworkReconnectOrder(t *testing.T) {
	fake := newFakeAPIClient()
	restorer := newRestorer(fake)

	snap := snapshotFromFixture(t, func(j *types.ContainerJSON) {
		j.NetworkSettings.Networks["frontend"] = &network.EndpointSettings{
			NetworkID: "net-frontend",
			Aliases:   []string{fixtureShortID, "web"},
		}
	})

	res, err := restorer.RollbackDetailed(context.Background(), snap)
	requireNoError(t, err)
	if !res.Restored {
		t.Fatalf("Restored = false: %+v", res)
	}
	requireCalls(t, []string{
		"logs:portainer:tail=50",
		"rename:portainer->drydock-failed-portainer-" + frozenNano,
		"stop:drydock-failed-portainer-" + frozenNano + ":t=60:s=",
		"image-inspect:" + fixtureImageID,
		"create:" + fixtureImageID + ":portainer",
		// created attached to the single (lexicographically first) endpoint,
		// disconnected, then every network reconnected in order.
		"disconnect:bridge:restored-1:force=true",
		"connect:bridge:restored-1:aliases=portainer",
		"connect:frontend:restored-1:aliases=web",
		"start:restored-1",
	}, fake.calls)
}

// TestRestorerRollbackPinsImageIDNotTag is the tag-poisoning regression
// test: by the time a rollback runs, the update flow has already re-pulled
// the SAME tag (watchtower's most common "app:latest" flow), so the daemon
// resolves the tag to the freshly failed - or, for a compromised registry,
// attacker-chosen - image. The snapshot still records the mutable tag in
// Config.Image and the immutable local image ID in ContainerJSONBase.Image;
// the restore must create from the ID so the reference whose existence was
// verified (image-inspect:<ID>) is exactly the code that runs.
func TestRestorerRollbackPinsImageIDNotTag(t *testing.T) {
	fake := newFakeAPIClient()
	restorer := newRestorer(fake)

	// The fixture models the poisoned state: Config.Image is the floating
	// tag "portainer/portainer:latest" (now re-pulled and pointing at a NEW
	// image), while ContainerJSONBase.Image is the OLD image's sha256 ID.
	snap := snapshotFromFixture(t, nil)
	if snap.ImageRef() == snap.ImageID() {
		t.Fatal("fixture must carry a mutable tag distinct from the image ID")
	}

	res, err := restorer.RollbackDetailed(context.Background(), snap)
	requireNoError(t, err)
	if !res.Restored {
		t.Fatalf("Restored = false, want true: %+v", res)
	}

	// The create call must carry the old image ID, not the tag.
	if fake.lastCreateConfig == nil || fake.lastCreateConfig.Image != fixtureImageID {
		t.Fatalf("create Config.Image = %v, want the verified old image ID %q", fake.lastCreateConfig, fixtureImageID)
	}
	inspected := false
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "image-inspect:") {
			inspected = true
			if call != "image-inspect:"+fixtureImageID {
				t.Fatalf("existence check = %q, want the old image ID", call)
			}
		}
		if strings.HasPrefix(call, "create:") && strings.Contains(call, "portainer/portainer") {
			t.Fatalf("create call %q resolves the mutable tag; a moved/poisoned tag would run unverified code", call)
		}
	}
	if !inspected {
		t.Fatalf("no image-inspect call recorded: %q", fake.calls)
	}
}

func TestRestorerHonorsConfiguredStopSignalAndTimeout(t *testing.T) {
	fake := newFakeAPIClient()
	restorer := newRestorer(fake)
	restorer.StopTimeout = 5 * time.Second

	snap := snapshotFromFixture(t, func(j *types.ContainerJSON) {
		j.Config.StopSignal = "SIGQUIT"
	})

	_, err := restorer.RollbackDetailed(context.Background(), snap)
	requireNoError(t, err)
	found := false
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "stop:") {
			found = true
			if !strings.Contains(call, ":t=5:s=SIGQUIT") {
				t.Fatalf("stop call = %q, want t=5 and s=SIGQUIT", call)
			}
		}
	}
	if !found {
		t.Fatalf("ContainerStop was not called: %q", fake.calls)
	}
}

func TestDemultiplexDockerStream(t *testing.T) {
	input := append(dockerFrame(1, "stdout-line\n"), dockerFrame(2, "stderr-line\n")...)
	if got := string(demultiplexDockerStream(input)); got != "stdout-line\nstderr-line\n" {
		t.Fatalf("demultiplexed = %q", got)
	}
	// TTY-style raw payload passes through unchanged.
	if got := string(demultiplexDockerStream([]byte("plain\n"))); got != "plain\n" {
		t.Fatalf("raw passthrough = %q", got)
	}
	// A truncated trailing frame keeps its bytes instead of dropping them.
	truncated := append(dockerFrame(1, "keep\n"), 0x01, 0x00, 0x00)
	if got := string(demultiplexDockerStream(truncated)); got != "keep\n\x01\x00\x00" {
		t.Fatalf("truncated frame handling = %q", got)
	}
}
