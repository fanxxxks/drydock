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

// Table-driven reinforcement suite for pkg/rollback. The bespoke tests in
// rollback_test.go pin individual scenarios; this file re-covers the surface
// as exhaustive tables: normal paths, empty-value boundaries, context
// cancellation (the timeout family), corrupt-snapshot variants, and error
// propagation for every step of the documented rollback sequence.
//
// Everything here runs against fakes and t.TempDir only - no docker daemon,
// no network. (pkg/rollback contains no changelog/HTTP code at all; its only
// external surface is the injectable apiClient interface, faked here.)

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// ---------------------------------------------------------------------------
// Shared table helpers (names deliberately disjoint from rollback_test.go).
// ---------------------------------------------------------------------------

// tblRenamed is the deterministic forensic rename target produced under the
// frozen restorer clock.
const tblRenamed = "drydock-failed-portainer-" + frozenNano

// tblLogsRenameStop is the call prefix every case that passes validation and
// refusal checks produces: logs first (AutoRemove forensics), forensic
// rename, graceful stop.
func tblLogsRenameStop() []string {
	return []string{
		"logs:portainer:tail=50",
		"rename:portainer->" + tblRenamed,
		"stop:" + tblRenamed + ":t=60:s=",
	}
}

// tblSuccessCalls is the full happy-path sequence for the bridge-network
// fixture (8 steps, restore.go:171-262).
func tblSuccessCalls() []string {
	return append(tblLogsRenameStop(),
		"image-inspect:"+fixtureImageID,
		"create:" + fixtureImageID + ":portainer",
		"disconnect:bridge:restored-1:force=true",
		"connect:bridge:restored-1:aliases=portainer",
		"start:restored-1",
	)
}

// idAt returns the on-disk file name of the n-th Take from a fresh store
// (newStore ticks one second per Take starting at takeBase+1s).
func idAt(n int) string {
	return snapshotID("portainer", takeBase.Add(time.Duration(n)*time.Second)) + ".json"
}

// requireFileSet asserts the exact set (in os.ReadDir's sorted order) of
// snapshot files for one container name.
func requireFileSet(t *testing.T, label, dir, name string, want []string) {
	t.Helper()
	got := snapshotFiles(t, dir, name)
	if len(got) != len(want) {
		t.Fatalf("%s: snapshot files = %q, want %q", label, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: snapshot files = %q, want %q", label, got, want)
		}
	}
}

// ctxAwareRenameClient decorates the fake so ContainerRename surfaces the
// context error instead of its scripted result, proving RollbackDetailed
// hands its ctx to the first fallible API call (logs tolerate errors, so the
// cancellation surfaces at the rename).
type ctxAwareRenameClient struct{ *fakeAPIClient }

func (c *ctxAwareRenameClient) ContainerRename(ctx context.Context, containerID, newName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.fakeAPIClient.ContainerRename(ctx, containerID, newName)
}

// ---------------------------------------------------------------------------
// FileSnapshotStore.Take.
// ---------------------------------------------------------------------------

func TestFileSnapshotStoreTakeTable(t *testing.T) {
	cases := []struct {
		name       string
		cancelCtx  bool // pre-canceled context: the timeout/deadline family
		mutate     func(*types.ContainerJSON)
		dirIsFile  bool // snapshot dir path occupied by a regular file
		wantErr    bool
		wantErrIs  error
		wantSnapID string // checked when wantErr is false
		wantFiles  int    // snapshot files on disk; -1 = skip (dir unusable)
	}{
		{
			name:       "happy path persists exactly one JSON file",
			wantSnapID: firstTakeID(),
			wantFiles:  1,
		},
		{
			name:      "canceled context fails before anything is written",
			cancelCtx: true,
			wantErr:   true,
			wantErrIs: context.Canceled,
			wantFiles: 0,
		},
		{
			name: "entirely empty inspect is invalid",
			mutate: func(j *types.ContainerJSON) {
				*j = types.ContainerJSON{}
			},
			wantErr:   true,
			wantErrIs: safeflow.ErrSnapshotInvalid,
			wantFiles: 0,
		},
		{
			name: "missing ContainerJSONBase is invalid",
			mutate: func(j *types.ContainerJSON) {
				j.ContainerJSONBase = nil
			},
			wantErr:   true,
			wantErrIs: safeflow.ErrSnapshotInvalid,
			wantFiles: 0,
		},
		{
			name: "nil Config is invalid",
			mutate: func(j *types.ContainerJSON) {
				j.Config = nil
			},
			wantErr:   true,
			wantErrIs: safeflow.ErrSnapshotInvalid,
			wantFiles: 0,
		},
		{
			name: "nil HostConfig is invalid",
			mutate: func(j *types.ContainerJSON) {
				j.HostConfig = nil
			},
			wantErr:   true,
			wantErrIs: safeflow.ErrSnapshotInvalid,
			wantFiles: 0,
		},
		{
			name: "empty image reference is invalid",
			mutate: func(j *types.ContainerJSON) {
				j.Config.Image = ""
			},
			wantErr:   true,
			wantErrIs: safeflow.ErrSnapshotInvalid,
			wantFiles: 0,
		},
		{
			name: "empty image ID is invalid",
			mutate: func(j *types.ContainerJSON) {
				j.ContainerJSONBase.Image = ""
			},
			wantErr:   true,
			wantErrIs: safeflow.ErrSnapshotInvalid,
			wantFiles: 0,
		},
		{
			name: "empty container name is invalid",
			mutate: func(j *types.ContainerJSON) {
				j.ContainerJSONBase.Name = ""
			},
			wantErr:   true,
			wantErrIs: safeflow.ErrSnapshotInvalid,
			wantFiles: 0,
		},
		{
			name:      "snapshot dir path occupied by a regular file fails persist",
			dirIsFile: true,
			wantErr:   true,
			wantFiles: -1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := base
			if tc.dirIsFile {
				dir = filepath.Join(base, "occupied")
				requireNoError(t, os.WriteFile(dir, []byte("not a dir"), 0o600))
			}
			store := newStore(t, dir)

			inspect := fixtureInspect()
			if tc.mutate != nil {
				tc.mutate(&inspect)
			}

			ctx := context.Background()
			if tc.cancelCtx {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}

			snap, err := store.Take(ctx, inspect)
			if tc.wantErr {
				requireError(t, err)
			} else {
				requireNoError(t, err)
			}
			if tc.wantErrIs != nil {
				requireErrorsIs(t, err, tc.wantErrIs)
			}
			if tc.wantErr {
				if snap.ID != "" || snap.ContainerName != "" || snap.Inspect.ContainerJSONBase != nil {
					t.Fatalf("Take returned non-zero snapshot on error: %+v", snap)
				}
			} else {
				if snap.ID != tc.wantSnapID {
					t.Fatalf("snapshot ID = %q, want %q", snap.ID, tc.wantSnapID)
				}
				if snap.ContainerName != "portainer" {
					t.Fatalf("ContainerName = %q, want portainer (leading / stripped)", snap.ContainerName)
				}
			}
			if tc.wantFiles >= 0 {
				if got := len(snapshotFiles(t, dir, "portainer")); got != tc.wantFiles {
					t.Fatalf("snapshot files on disk = %d, want %d", got, tc.wantFiles)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FileSnapshotStore.Latest.
// ---------------------------------------------------------------------------

func TestFileSnapshotStoreLatestTable(t *testing.T) {
	cases := []struct {
		name      string
		lookup    string
		cancelCtx bool
		dirIsFile bool
		dirPath   string // overrides the store dir outright (invalid-path cases)
		arrange   func(t *testing.T, store *FileSnapshotStore)
		wantFound bool
		wantID    string
		wantErr   bool
		wantErrIs error
	}{
		{
			name:      "empty store returns not-found without error",
			lookup:    "portainer",
			wantFound: false,
		},
		{
			name: "empty container name lookup finds nothing",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				_, err := store.Take(context.Background(), fixtureInspect())
				requireNoError(t, err)
			},
			lookup:    "",
			wantFound: false,
		},
		{
			name: "snapshots of a longer name never bleed into prefix lookups",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				other := fixtureInspect()
				other.Name = "/web-2" // file "web-2-<nano>.json" shares the "web-" prefix
				_, err := store.Take(context.Background(), other)
				requireNoError(t, err)
			},
			lookup:    "web",
			wantFound: false,
		},
		{
			name: "exact name is found",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				other := fixtureInspect()
				other.Name = "/web-2"
				_, err := store.Take(context.Background(), other)
				requireNoError(t, err)
			},
			lookup:    "web-2",
			wantFound: true,
			wantID:    snapshotID("web-2", takeBase.Add(time.Second)),
		},
		{
			name: "newest snapshot by CreatedAt wins",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				for i := 0; i < 3; i++ {
					_, err := store.Take(context.Background(), fixtureInspect())
					requireNoError(t, err)
				}
			},
			lookup:    "portainer",
			wantFound: true,
			wantID:    snapshotID("portainer", takeBase.Add(3*time.Second)),
		},
		{
			name: "corrupt JSON file is skipped, not fatal",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				_, err := store.Take(context.Background(), fixtureInspect())
				requireNoError(t, err)
				requireNoError(t, os.WriteFile(
					filepath.Join(store.Dir, "portainer-9999999999999999999.json"),
					[]byte("{not json"), 0o600))
			},
			lookup:    "portainer",
			wantFound: true,
			wantID:    firstTakeID(),
		},
		{
			name: "truncated JSON file is skipped, not fatal",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				_, err := store.Take(context.Background(), fixtureInspect())
				requireNoError(t, err)
				requireNoError(t, os.WriteFile(
					filepath.Join(store.Dir, "portainer-9999999999999999998.json"),
					[]byte(`{"ContainerName":"por`), 0o600))
			},
			lookup:    "portainer",
			wantFound: true,
			wantID:    firstTakeID(),
		},
		{
			name: "valid JSON but zero-value snapshot is skipped",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				_, err := store.Take(context.Background(), fixtureInspect())
				requireNoError(t, err)
				requireNoError(t, os.WriteFile(
					filepath.Join(store.Dir, "portainer-9999999999999999997.json"),
					[]byte("{}"), 0o600))
			},
			lookup:    "portainer",
			wantFound: true,
			wantID:    firstTakeID(),
		},
		{
			name: "payload CreatedAt outranks the timestamp baked into the file name",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				_, err := store.Take(context.Background(), fixtureInspect())
				requireNoError(t, err)
				_, err = store.Take(context.Background(), fixtureInspect())
				requireNoError(t, err)
				// Smallest possible ID in the name, but the newest payload.
				hand := safeflow.Snapshot{
					ID:            "portainer-0",
					ContainerName: "portainer",
					CreatedAt:     takeBase.Add(10 * time.Second),
					Inspect:       fixtureInspect(),
				}
				data, err := json.Marshal(hand)
				requireNoError(t, err)
				requireNoError(t, os.WriteFile(
					filepath.Join(store.Dir, "portainer-0.json"), data, 0o600))
			},
			lookup:    "portainer",
			wantFound: true,
			wantID:    "portainer-0",
		},
		{
			name: "directory entry shaped like a snapshot file is skipped",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				_, err := store.Take(context.Background(), fixtureInspect())
				requireNoError(t, err)
				requireNoError(t, os.MkdirAll(
					filepath.Join(store.Dir, "portainer-9999999999999999996.json"), 0o700))
			},
			lookup:    "portainer",
			wantFound: true,
			wantID:    firstTakeID(),
		},
		{
			name:      "canceled context fails the lookup",
			lookup:    "portainer",
			cancelCtx: true,
			wantErr:   true,
			wantErrIs: context.Canceled,
			wantFound: false,
		},
		{
			// A NUL byte makes os.ReadDir fail with EINVAL on every platform.
			// (A dir path occupied by a regular file is NOT portable: on
			// Windows os.ReadDir returns (empty, nil) for it, verified
			// empirically on this host.)
			name:    "unreadable store dir propagates the listing error",
			dirPath: "snapshot\x00dir",
			lookup:  "portainer",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := base
			if tc.dirPath != "" {
				dir = tc.dirPath
			}
			if tc.dirIsFile {
				dir = filepath.Join(base, "occupied")
				requireNoError(t, os.WriteFile(dir, []byte("not a dir"), 0o600))
			}
			store := newStore(t, dir)
			if tc.arrange != nil {
				tc.arrange(t, store)
			}

			ctx := context.Background()
			if tc.cancelCtx {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}

			got, ok, err := store.Latest(ctx, tc.lookup)
			if tc.wantErr {
				requireError(t, err)
			} else {
				requireNoError(t, err)
			}
			if tc.wantErrIs != nil {
				requireErrorsIs(t, err, tc.wantErrIs)
			}
			if ok != tc.wantFound {
				t.Fatalf("Latest ok = %t, want %t (snapshot %+v, err %v)", ok, tc.wantFound, got, err)
			}
			if tc.wantFound {
				if got.ID != tc.wantID {
					t.Fatalf("Latest ID = %q, want %q", got.ID, tc.wantID)
				}
			} else if got.ID != "" || got.ContainerName != "" {
				t.Fatalf("not-found Latest returned non-zero snapshot: %+v", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FileSnapshotStore.Prune.
// ---------------------------------------------------------------------------

func TestFileSnapshotStorePruneTable(t *testing.T) {
	cases := []struct {
		name      string
		keep      int
		cancelCtx bool
		dirIsFile bool
		dirPath   string // overrides the store dir outright (invalid-path cases)
		arrange   func(t *testing.T, store *FileSnapshotStore)
		// wantRemaining is the exact set of portainer files after the prune
		// (nil = none). Only checked when the dir is usable.
		wantRemaining  []string
		wantOtherName  string // when set, also assert this other name's file count
		wantOtherFiles int
		wantErr        bool
		wantErrIs      error
	}{
		{
			name: "keep two of three deletes the oldest",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				for i := 0; i < 3; i++ {
					_, err := store.Take(context.Background(), fixtureInspect())
					requireNoError(t, err)
				}
			},
			keep:          2,
			wantRemaining: []string{idAt(2), idAt(3)},
		},
		{
			name: "keep equal to count is a no-op",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				for i := 0; i < 3; i++ {
					_, err := store.Take(context.Background(), fixtureInspect())
					requireNoError(t, err)
				}
			},
			keep:          3,
			wantRemaining: []string{idAt(1), idAt(2), idAt(3)},
		},
		{
			name: "keep above count is a no-op",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				for i := 0; i < 2; i++ {
					_, err := store.Take(context.Background(), fixtureInspect())
					requireNoError(t, err)
				}
			},
			keep:          5,
			wantRemaining: []string{idAt(1), idAt(2)},
		},
		{
			name: "keep zero deletes all",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				for i := 0; i < 2; i++ {
					_, err := store.Take(context.Background(), fixtureInspect())
					requireNoError(t, err)
				}
			},
			keep: 0,
		},
		{
			name: "negative keep deletes all",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				for i := 0; i < 2; i++ {
					_, err := store.Take(context.Background(), fixtureInspect())
					requireNoError(t, err)
				}
			},
			keep: -3,
		},
		{
			name: "prune only touches the named container",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				for i := 0; i < 2; i++ {
					_, err := store.Take(context.Background(), fixtureInspect())
					requireNoError(t, err)
				}
				other := fixtureInspect()
				other.Name = "/web"
				_, err := store.Take(context.Background(), other)
				requireNoError(t, err)
			},
			keep:           0,
			wantOtherName:  "web",
			wantOtherFiles: 1,
		},
		{
			name: "prune of a name with no snapshots is not an error",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				other := fixtureInspect()
				other.Name = "/web"
				_, err := store.Take(context.Background(), other)
				requireNoError(t, err)
			},
			keep:           1,
			wantOtherName:  "web",
			wantOtherFiles: 1,
		},
		{
			name: "corrupt snapshot files are invisible to prune",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				_, err := store.Take(context.Background(), fixtureInspect())
				requireNoError(t, err)
				requireNoError(t, os.WriteFile(
					filepath.Join(store.Dir, "portainer-9999999999999999999.json"),
					[]byte("{not json"), 0o600))
			},
			keep:          0,
			wantRemaining: []string{"portainer-9999999999999999999.json"},
		},
		{
			name: "canceled context fails the prune before deleting anything",
			arrange: func(t *testing.T, store *FileSnapshotStore) {
				for i := 0; i < 2; i++ {
					_, err := store.Take(context.Background(), fixtureInspect())
					requireNoError(t, err)
				}
			},
			cancelCtx:     true,
			wantRemaining: []string{idAt(1), idAt(2)},
			wantErr:       true,
			wantErrIs:     context.Canceled,
		},
		{
			// Same portable mechanism as the Latest table: a NUL byte makes
			// os.ReadDir fail with EINVAL on every platform, exercising the
			// listing-error branch of Prune.
			name:    "unreadable store dir propagates the listing error",
			dirPath: "snapshot\x00dir",
			keep:    1,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := base
			if tc.dirPath != "" {
				dir = tc.dirPath
			}
			if tc.dirIsFile {
				dir = filepath.Join(base, "occupied")
				requireNoError(t, os.WriteFile(dir, []byte("not a dir"), 0o600))
			}
			store := newStore(t, dir)
			if tc.arrange != nil {
				tc.arrange(t, store)
			}

			ctx := context.Background()
			if tc.cancelCtx {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}

			err := store.Prune(ctx, "portainer", tc.keep)
			if tc.wantErr {
				requireError(t, err)
			} else {
				requireNoError(t, err)
			}
			if tc.wantErrIs != nil {
				requireErrorsIs(t, err, tc.wantErrIs)
			}
			if !tc.dirIsFile && tc.dirPath == "" {
				requireFileSet(t, tc.name, dir, "portainer", tc.wantRemaining)
			}
			if tc.wantOtherName != "" {
				if got := len(snapshotFiles(t, dir, tc.wantOtherName)); got != tc.wantOtherFiles {
					t.Fatalf("%s: %s files = %d, want %d", tc.name, tc.wantOtherName, got, tc.wantOtherFiles)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Restorer.RollbackDetailed: the full normal/edge/failure matrix.
// ---------------------------------------------------------------------------

type rollbackTableCase struct {
	name      string
	cancelCtx bool
	mutate    func(*types.ContainerJSON)
	snapName  string // overrides ContainerName after validation
	rawSnap   func() safeflow.Snapshot
	setup     func(*fakeAPIClient)
	wrap      func(*fakeAPIClient) apiClient

	wantErr        bool
	wantErrIs      error
	wantErrSub     string
	wantRestored   bool
	wantID         string
	wantLogs       string
	wantRenamed    bool
	wantFailedName string
	wantCalls      []string
}

func TestRestorerRollbackDetailedTable(t *testing.T) {
	cases := []rollbackTableCase{
		{
			name:           "full success sequence with bridge networking",
			wantRestored:   true,
			wantID:         "restored-1",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls:      tblSuccessCalls(),
		},
		{
			name:           "host networking skips the reconnect dance",
			mutate:         func(j *types.ContainerJSON) { j.HostConfig.NetworkMode = "host" },
			wantRestored:   true,
			wantID:         "restored-1",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls: append(tblLogsRenameStop(),
				"image-inspect:"+fixtureImageID,
				"create:" + fixtureImageID + ":portainer",
				"start:restored-1",
			),
		},
		{
			name: "stop returning NotFound (AutoRemove self-destruct) is tolerated",
			setup: func(f *fakeAPIClient) {
				f.failStop = errors.New("Error response from daemon: No such container: " + tblRenamed)
			},
			wantRestored:   true,
			wantID:         "restored-1",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls:      tblSuccessCalls(),
		},
		{
			name: "failed log capture is tolerated and still restores",
			setup: func(f *fakeAPIClient) {
				f.failLogs = errors.New("i/o timeout")
			},
			wantRestored:   true,
			wantID:         "restored-1",
			wantLogs:       "",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls:      tblSuccessCalls(),
		},
		{
			name:           "leading slash in snapshot ContainerName is stripped for API calls",
			snapName:       "/portainer",
			wantRestored:   true,
			wantID:         "restored-1",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls:      tblSuccessCalls(),
		},
		{
			name: "invalid snapshot without ContainerJSONBase never reaches docker",
			rawSnap: func() safeflow.Snapshot {
				s := safeflow.Snapshot{ID: "broken-1", ContainerName: "portainer", Inspect: fixtureInspect()}
				s.Inspect.ContainerJSONBase = nil
				return s
			},
			wantErr:   true,
			wantErrIs: safeflow.ErrSnapshotInvalid,
			wantCalls: []string{},
		},
		{
			name: "invalid snapshot with empty container name never reaches docker",
			rawSnap: func() safeflow.Snapshot {
				return safeflow.Snapshot{ID: "broken-2", ContainerName: "", Inspect: fixtureInspect()}
			},
			wantErr:   true,
			wantErrIs: safeflow.ErrSnapshotInvalid,
			wantCalls: []string{},
		},
		{
			name: "Drydock's own container is refused without any docker call",
			mutate: func(j *types.ContainerJSON) {
				j.Config.Labels["com.centurylinklabs.watchtower"] = "true"
			},
			wantErr:    true,
			wantErrSub: "refusing to roll back",
			wantCalls:  []string{},
		},
		{
			name:      "canceled context propagates out of the first fallible API call",
			cancelCtx: true,
			wrap: func(f *fakeAPIClient) apiClient {
				return &ctxAwareRenameClient{f}
			},
			wantErr:        true,
			wantErrIs:      context.Canceled,
			wantLogs:       "line1\nboom\n",
			wantFailedName: "portainer",
			wantCalls:      []string{"logs:portainer:tail=50"},
		},
		{
			name: "rename failure aborts before stop and create",
			setup: func(f *fakeAPIClient) {
				f.failRename = errors.New("Error response from daemon: rename conflict")
			},
			wantErr:        true,
			wantErrSub:     "renaming failed container",
			wantLogs:       "line1\nboom\n",
			wantFailedName: "portainer",
			wantCalls: []string{
				"logs:portainer:tail=50",
				"rename:portainer->" + tblRenamed,
			},
		},
		{
			name: "stop failure aborts before create and leaves the failed container as-is",
			setup: func(f *fakeAPIClient) {
				f.failStop = errors.New("Error response from daemon: container is marked for removal")
			},
			wantErr:        true,
			wantErrSub:     "stopping failed container",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls:      tblLogsRenameStop(),
		},
		{
			name: "missing snapshot image aborts with ErrRollbackImageMissing before create",
			setup: func(f *fakeAPIClient) {
				f.failImage = errors.New("Error response from daemon: No such image: " + fixtureImageID)
			},
			wantErr:        true,
			wantErrIs:      safeflow.ErrRollbackImageMissing,
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls: append(tblLogsRenameStop(),
				"image-inspect:"+fixtureImageID,
			),
		},
		{
			name: "image inspect failure other than NotFound aborts before create",
			setup: func(f *fakeAPIClient) {
				f.failImage = errors.New("daemon unreachable")
			},
			wantErr:        true,
			wantErrSub:     "inspecting snapshot image",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls: append(tblLogsRenameStop(),
				"image-inspect:"+fixtureImageID,
			),
		},
		{
			name: "create failure revives the renamed failed container, removes nothing",
			setup: func(f *fakeAPIClient) {
				f.failCreate = errors.New("Error response from daemon: driver failure")
			},
			wantErr:        true,
			wantErrSub:     "creating restored container",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls: append(tblLogsRenameStop(),
				"image-inspect:"+fixtureImageID,
				"create:" + fixtureImageID + ":portainer",
				"start:"+tblRenamed,
			),
		},
		{
			name: "disconnect failure force-removes the replacement and revives the failed one",
			setup: func(f *fakeAPIClient) {
				f.failDisconnect = errors.New("Error response from daemon: network bridge not found")
			},
			wantErr:        true,
			wantErrSub:     "disconnecting",
			wantID:         "restored-1",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls: append(tblLogsRenameStop(),
				"image-inspect:"+fixtureImageID,
				"create:" + fixtureImageID + ":portainer",
				"disconnect:bridge:restored-1:force=true",
				"remove:restored-1:force=true",
				"start:"+tblRenamed,
			),
		},
		{
			name: "connect failure force-removes the replacement and revives the failed one",
			setup: func(f *fakeAPIClient) {
				f.failConnect = errors.New("Error response from daemon: network not found")
			},
			wantErr:        true,
			wantErrSub:     "connecting restored container",
			wantID:         "restored-1",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			// tblSuccessCalls()[:7] = everything through the failed connect;
			// the slice is fresh per call, so truncation + append is safe.
			wantCalls: append(tblSuccessCalls()[:7],
				"remove:restored-1:force=true",
				"start:"+tblRenamed,
			),
		},
		{
			name: "start failure force-removes the replacement and revives the failed one",
			setup: func(f *fakeAPIClient) {
				f.failStart = errors.New("Error response from daemon: cannot start")
			},
			wantErr:        true,
			wantErrSub:     "starting restored container",
			wantID:         "restored-1",
			wantLogs:       "line1\nboom\n",
			wantRenamed:    true,
			wantFailedName: "portainer",
			wantCalls: append(tblSuccessCalls(),
				"remove:restored-1:force=true",
				"start:"+tblRenamed,
			),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeAPIClient()
			if tc.setup != nil {
				tc.setup(fake)
			}
			api := apiClient(fake)
			if tc.wrap != nil {
				api = tc.wrap(fake)
			}
			restorer := NewRestorer(api)
			restorer.now = func() time.Time { return time.Unix(1690000000, 0) }

			var snap safeflow.Snapshot
			if tc.rawSnap != nil {
				snap = tc.rawSnap()
			} else {
				snap = snapshotFromFixture(t, tc.mutate)
				if tc.snapName != "" {
					snap.ContainerName = tc.snapName
				}
			}

			ctx := context.Background()
			if tc.cancelCtx {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}

			res, err := restorer.RollbackDetailed(ctx, snap)

			if tc.wantErr {
				requireError(t, err)
			} else {
				requireNoError(t, err)
			}
			if tc.wantErrIs != nil {
				requireErrorsIs(t, err, tc.wantErrIs)
			}
			if tc.wantErrSub != "" && err != nil && !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErrSub)
			}
			if res.Restored != tc.wantRestored {
				t.Errorf("Restored = %t, want %t", res.Restored, tc.wantRestored)
			}
			if res.ContainerID != tc.wantID {
				t.Errorf("ContainerID = %q, want %q", res.ContainerID, tc.wantID)
			}
			if res.FailedLogs != tc.wantLogs {
				t.Errorf("FailedLogs = %q, want %q", res.FailedLogs, tc.wantLogs)
			}
			if (res.FailedRenamedTo != "") != tc.wantRenamed {
				t.Errorf("FailedRenamedTo = %q, want set: %t", res.FailedRenamedTo, tc.wantRenamed)
			}
			if res.FailedContainerName != tc.wantFailedName {
				t.Errorf("FailedContainerName = %q, want %q", res.FailedContainerName, tc.wantFailedName)
			}
			if res.SnapshotID != snap.ID {
				t.Errorf("SnapshotID = %q, want %q (identity must survive every failure)", res.SnapshotID, snap.ID)
			}
			requireCalls(t, tc.wantCalls, fake.calls)
		})
	}
}

// ---------------------------------------------------------------------------
// Health-gate wiring: the "unhealthy -> automatic rollback" half of the
// safeflow loop, as seen from this package. The gate itself lives in
// pkg/healthgate (which this package must not import, safeflow.go:36-39);
// what rollback owns is that a gate error leads the orchestrator to call
// safeflow.Rollbacker.Rollback with the pre-update snapshot, and that a
// passing gate leaves the container untouched. This table pins exactly that
// contract usage, driven only by safeflow's own status/error vocabulary.
// ---------------------------------------------------------------------------

func TestRestorerRollbackWiringOnGateVerdict(t *testing.T) {
	cases := []struct {
		name         string
		status       safeflow.HealthStatus
		gateErr      error // the error safeflow documents for this verdict
		wantRollback bool
	}{
		{
			name:         "healthy verdict leaves the replacement untouched",
			status:       safeflow.HealthHealthy,
			wantRollback: false,
		},
		{
			name:         "no healthcheck (unknown) judged by running state leaves it untouched",
			status:       safeflow.HealthUnknown,
			wantRollback: false,
		},
		{
			name:         "unhealthy verdict triggers rollback",
			status:       safeflow.HealthUnhealthy,
			gateErr:      safeflow.ErrUnhealthy,
			wantRollback: true,
		},
		{
			name:         "container exited during the gate window triggers rollback",
			status:       safeflow.HealthExited,
			gateErr:      safeflow.ErrUnhealthy,
			wantRollback: true,
		},
		{
			name:         "gate timeout while still starting triggers rollback",
			status:       safeflow.HealthStarting,
			gateErr:      safeflow.ErrHealthTimeout,
			wantRollback: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeAPIClient()
			restorer := newRestorer(fake)
			snap := snapshotFromFixture(t, nil)

			var rollbacker safeflow.Rollbacker = restorer
			if tc.gateErr != nil {
				id, err := rollbacker.Rollback(context.Background(), snap)
				requireNoError(t, err)
				if id != "restored-1" {
					t.Fatalf("Rollback id = %q, want restored-1", id)
				}
			}
			if didRollback := len(fake.calls) > 0; didRollback != tc.wantRollback {
				t.Fatalf("rollback ran = %t, want %t (calls: %q)", didRollback, tc.wantRollback, fake.calls)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// White-box tables for the small helpers.
// ---------------------------------------------------------------------------

func TestStopTimeoutDefaultsAndOverride(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, defaultStopTimeout},
		{-1 * time.Second, defaultStopTimeout},
		{90 * time.Second, 90 * time.Second},
	} {
		r := &Restorer{StopTimeout: tc.in}
		if got := r.stopTimeout(); got != tc.want {
			t.Errorf("StopTimeout %s: stopTimeout() = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestSecondsPtrTable(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want int
	}{
		{60 * time.Second, 60},
		{90 * time.Second, 90},
		{59 * time.Second, 59},
		{1500 * time.Millisecond, 1}, // sub-second remainder truncates
	} {
		if got := secondsPtr(tc.in); *got != tc.want {
			t.Errorf("secondsPtr(%s) = %d, want %d", tc.in, *got, tc.want)
		}
	}
}

func TestShortContainerIDTable(t *testing.T) {
	twelve := strings.Repeat("a", 12)
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"abc", "abc"},
		{twelve, twelve},
		{twelve + "xyz", twelve},
	} {
		if got := shortContainerID(tc.in); got != tc.want {
			t.Errorf("shortContainerID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestContainerNameStripsLeadingSlash(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/portainer", "portainer"},
		{"portainer", "portainer"},
		{"", ""},
		{"/nested/name", "nested/name"}, // only the leading slash goes
	} {
		if got := containerName(tc.in); got != tc.want {
			t.Errorf("containerName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsHostNetworkTable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   string
		hostNi bool
		want   bool
	}{
		{"host mode", "host", false, true},
		{"bridge mode", "bridge", false, false},
		{"empty mode", "", false, false},
		{"nil host config", "", true, false},
	} {
		var hc *dockercontainer.HostConfig
		if !tc.hostNi {
			hc = &dockercontainer.HostConfig{NetworkMode: dockercontainer.NetworkMode(tc.mode)}
		}
		if got := isHostNetwork(hc); got != tc.want {
			t.Errorf("%s: isHostNetwork = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestIsNotFoundTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"container gone", errors.New("Error response from daemon: No such container: abc"), true},
		{"image gone", errors.New("Error response from daemon: no such image"), true},
		{"network gone mixed case", errors.New("NO SUCH NETWORK"), true},
		{"unrelated failure", errors.New("connection refused"), false},
		{"wrapped not-found", fmt.Errorf("step: %w", errors.New("no such container: x")), true},
	} {
		if got := isNotFound(tc.err); got != tc.want {
			t.Errorf("%s: isNotFound = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestFirstEndpointOnlyTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   map[string]*network.EndpointSettings
		want string // expected single endpoint name; "" = empty result
	}{
		{"empty map", map[string]*network.EndpointSettings{}, ""},
		{"nil map", nil, ""},
		{"picks the lexicographically smallest endpoint", map[string]*network.EndpointSettings{
			"bridge":   {},
			"frontend": {},
		}, "bridge"},
	} {
		got := firstEndpointOnly(&network.NetworkingConfig{EndpointsConfig: tc.in})
		if tc.want == "" {
			if len(got.EndpointsConfig) != 0 {
				t.Errorf("%s: got endpoints %v, want none", tc.name, got.EndpointsConfig)
			}
			continue
		}
		if len(got.EndpointsConfig) != 1 {
			t.Fatalf("%s: got %d endpoints, want 1", tc.name, len(got.EndpointsConfig))
		}
		if _, ok := got.EndpointsConfig[tc.want]; !ok {
			t.Errorf("%s: endpoint %q missing from %v", tc.name, tc.want, got.EndpointsConfig)
		}
	}
}

func TestSortSnapshotsNewestFirstTable(t *testing.T) {
	t1 := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		snaps []safeflow.Snapshot
		want  []string // IDs in expected order
	}{
		{
			name: "orders by CreatedAt descending",
			snaps: []safeflow.Snapshot{
				{ID: "old", CreatedAt: t1},
				{ID: "new", CreatedAt: t1.Add(time.Hour)},
			},
			want: []string{"new", "old"},
		},
		{
			name: "exact CreatedAt ties break by descending ID",
			snaps: []safeflow.Snapshot{
				{ID: "aaa", CreatedAt: t1},
				{ID: "zzz", CreatedAt: t1},
			},
			want: []string{"zzz", "aaa"},
		},
		{
			name:  "empty input stays empty",
			snaps: nil,
			want:  nil,
		},
	} {
		sortSnapshotsNewestFirst(tc.snaps)
		var got []string
		for _, s := range tc.snaps {
			got = append(got, s.ID)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: sorted IDs = %q, want %q", tc.name, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: sorted IDs = %q, want %q", tc.name, got, tc.want)
			}
		}
	}
}

func TestDemultiplexDockerStreamTable(t *testing.T) {
	// A frame header that promises 5 payload bytes but is followed by only 2:
	// demultiplex keeps the malformed tail verbatim (forensic best-effort).
	lyingHeader := make([]byte, 8)
	lyingHeader[0] = 1
	binary.BigEndian.PutUint32(lyingHeader[4:8], 5)
	lyingInput := append(lyingHeader, 'a', 'b')

	for _, tc := range []struct {
		name string
		in   []byte
		want string
	}{
		{"empty input", nil, ""},
		{"single stdout frame", dockerFrame(1, "hello\n"), "hello\n"},
		{"frame sequence", append(dockerFrame(1, "a\n"), dockerFrame(2, "b\n")...), "a\nb\n"},
		{"zero-size frame vanishes", append(dockerFrame(1, ""), dockerFrame(2, "x\n")...), "x\n"},
		{"short plain payload passes through", []byte("abc"), "abc"},
		{"truncated frame keeps its bytes verbatim", append(dockerFrame(1, "keep\n"), 0x01, 0x00, 0x00), "keep\n\x01\x00\x00"},
		{"lying header kept verbatim", lyingInput, string(lyingInput)},
	} {
		if got := string(demultiplexDockerStream(tc.in)); got != tc.want {
			t.Errorf("%s: demultiplex = %q, want %q", tc.name, got, tc.want)
		}
	}
}
