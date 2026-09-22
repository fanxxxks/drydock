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

// Package rollback implements the snapshot and restore halves of Drydock's
// update safety loop (the safeflow.Snapshotter and safeflow.Rollbacker
// contracts).
//
// The restore path deliberately mirrors the recreate flow proven by the
// upstream containrrr/watchtower tree (cloned at D:\github\.upstream\watchtower,
// mirrored in this fork's pkg/container): create config derived from the
// snapshotted types.ContainerJSON -> ContainerCreate -> NetworkDisconnect /
// NetworkConnect -> ContainerStart (pkg/container/client.go:248-300).
//
// Import surface is deliberately narrow (v0.1 zero-conflict rule): safeflow,
// the standard library, the Docker SDK packages listed in the project import
// whitelist, and the single type-only import forced by the SDK's own
// ContainerCreate signature (opencontainers image-spec Platform).
package rollback

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/docker/docker/api/types"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// snapshotFileSuffix is appended to the snapshot ID to form the on-disk file
// name: "<containerName>-<unixnano>.json".
const snapshotFileSuffix = ".json"

// envSidecarSuffix forms the name of the per-snapshot environment sidecar
// file ("<containerName>-<unixnano>.env") that holds the real environment
// values when RedactEnv is on. The ".env" (not ".env.json") suffix keeps it
// outside listFor's snapshot-file filter.
const envSidecarSuffix = ".env"

// redactedEnvPlaceholder replaces every environment VALUE in the persisted
// snapshot JSON when RedactEnv is on. Keys are preserved so operators can
// still see which variables a container declared.
const redactedEnvPlaceholder = "<drydock-redacted>"

// FileSnapshotStore is a filesystem-backed safeflow.Snapshotter. Snapshots are
// stored as JSON documents (encoding/json) under Dir, one file per snapshot,
// named "<containerName>-<unixnano>.json", so a rollback survives a Drydock
// restart on the same host. Organization is by container NAME, not ID:
// recreating a container always changes its ID, while watchtower-style updates
// preserve the name.
type FileSnapshotStore struct {
	// Dir is the --snapshot-dir root. Created on demand via os.MkdirAll.
	Dir string

	// RedactEnv keeps container environment values out of the snapshot JSON
	// file: values are replaced with redactedEnvPlaceholder and the real
	// "KEY=VALUE" strings are persisted in a 0600 sidecar file
	// ("<id>.env") next to the snapshot. Reads (Latest/Prune listing)
	// transparently rejoin the sidecar, so snapshots remain fully
	// recreatable while the at-rest JSON carries no secrets. The in-memory
	// Snapshot returned by Take always carries the real values.
	RedactEnv bool

	// now is the clock used for snapshot IDs / CreatedAt. Injected by tests
	// for determinism; defaults to time.Now via NewFileSnapshotStore.
	now func() time.Time

	// remove deletes a snapshot file; os.Remove in production, overridable in
	// tests to simulate a single undeletable file (Go 1.25+ clears the
	// read-only attribute on Windows, so chmod tricks no longer fail there).
	remove func(string) error
}

// compile-time contract check.
var _ safeflow.Snapshotter = (*FileSnapshotStore)(nil)

// NewFileSnapshotStore returns a FileSnapshotStore rooted at dir. The
// directory (and parents) is created lazily on the first Take.
func NewFileSnapshotStore(dir string) *FileSnapshotStore {
	return &FileSnapshotStore{Dir: dir, now: time.Now, remove: os.Remove}
}

// Take deep-copies inspect, validates the copy and persists it atomically
// (temp file + os.Rename within Dir). The deep copy is mandatory: upstream's
// recreate helpers mutate the inspect payload in place -
// GetCreateConfig strips image defaults from Config
// (pkg/container/container.go:283-348), GetCreateHostConfig rewrites Links
// (container.go:352-363) and GetNetworkConfig deletes container-ID aliases
// from EndpointSettings (pkg/container/client.go:226-246) - so a snapshot
// aliasing the caller's inspect would silently observe those mutations.
//
// An inspect that cannot produce a recreatable snapshot yields an error
// wrapping safeflow.ErrSnapshotInvalid and nothing is written to disk.
func (s *FileSnapshotStore) Take(ctx context.Context, inspect types.ContainerJSON) (safeflow.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return safeflow.Snapshot{}, fmt.Errorf("rollback: take snapshot: %w", err)
	}

	// The inspect name lives behind the embedded base pointer; keep the nil
	// case (an invalid payload) on the Validate path instead of panicking.
	var name string
	if inspect.ContainerJSONBase != nil {
		name = containerName(inspect.Name)
	}

	copied, err := deepCopyContainerJSON(inspect)
	if err != nil {
		return safeflow.Snapshot{}, fmt.Errorf("rollback: deep-copy inspect for %q: %w", name, err)
	}

	now := s.now()
	snap := safeflow.Snapshot{
		ID:            snapshotID(name, now),
		ContainerName: name,
		CreatedAt:     now,
		Inspect:       copied,
	}

	if err := snap.Validate(); err != nil {
		return safeflow.Snapshot{}, fmt.Errorf("rollback: take snapshot for %q: %w", name, err)
	}

	if err := s.persist(snap); err != nil {
		return safeflow.Snapshot{}, fmt.Errorf("rollback: persist snapshot %s: %w", snap.ID, err)
	}
	return snap, nil
}

// Latest returns the most recent snapshot recorded for containerName, ordered
// by CreatedAt (IDs break exact ties, keeping the ordering deterministic).
// It returns (zero, false, nil) when the store holds no snapshot for the
// name - absence is not an error. Individual unreadable/corrupt files are
// skipped with a log line instead of failing the lookup.
func (s *FileSnapshotStore) Latest(ctx context.Context, containerName string) (safeflow.Snapshot, bool, error) {
	if err := ctx.Err(); err != nil {
		return safeflow.Snapshot{}, false, fmt.Errorf("rollback: latest snapshot: %w", err)
	}

	snaps, err := s.listFor(containerName)
	if err != nil {
		return safeflow.Snapshot{}, false, fmt.Errorf("rollback: list snapshots for %q: %w", containerName, err)
	}
	if len(snaps) == 0 {
		return safeflow.Snapshot{}, false, nil
	}
	sortSnapshotsNewestFirst(snaps)
	return snaps[0], true, nil
}

// Prune keeps at most the newest keep snapshots for containerName and deletes
// the rest; keep <= 0 deletes every snapshot for that name. A failure to
// delete a single file is logged and does not fail the operation; only a
// failure to list the directory is returned as an error.
func (s *FileSnapshotStore) Prune(ctx context.Context, containerName string, keep int) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("rollback: prune snapshots: %w", err)
	}

	snaps, err := s.listFor(containerName)
	if err != nil {
		return fmt.Errorf("rollback: prune snapshots for %q: %w", containerName, err)
	}

	sortSnapshotsNewestFirst(snaps)
	var victims []safeflow.Snapshot
	switch {
	case keep <= 0:
		victims = snaps
	case keep < len(snaps):
		victims = snaps[keep:]
	}

	for _, victim := range victims {
		// The env sidecar (if any) must go with its snapshot, otherwise the
		// secret-bearing half outlives the snapshot it belongs to.
		for _, base := range []string{victim.ID + snapshotFileSuffix, victim.ID + envSidecarSuffix} {
			path := filepath.Join(s.Dir, base)
			if err := s.remove(path); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				// Log and continue: one undeletable file must not fail the prune.
				log.Printf("rollback: prune: failed to delete snapshot file %s: %v", path, err)
			}
		}
	}
	return nil
}

// persist writes the snapshot as JSON atomically: data lands in a temp file
// inside Dir (same filesystem, so os.Rename is atomic) and is then renamed to
// its final name. A crash mid-write can only leave a dot-prefixed temp file,
// never a half-written snapshot that Latest could pick up.
//
// When RedactEnv is on and the container declares environment variables, the
// persisted JSON carries placeholder values only; the real values are written
// to the 0600 sidecar FIRST (a failure there aborts with nothing on disk,
// rather than persisting a snapshot whose env could never be restored), and a
// failure writing the main file afterwards removes the sidecar again.
func (s *FileSnapshotStore) persist(snap safeflow.Snapshot) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}

	toWrite := snap
	var originalEnv []string
	if s.RedactEnv && snap.Inspect.Config != nil && len(snap.Inspect.Config.Env) > 0 {
		originalEnv = snap.Inspect.Config.Env
		redacted, err := deepCopyContainerJSON(snap.Inspect)
		if err != nil {
			return fmt.Errorf("redacting snapshot env: %w", err)
		}
		redactEnvValues(redacted.Config.Env)
		toWrite.Inspect = redacted
	}

	if originalEnv != nil {
		if err := s.persistEnvSidecar(snap.ID, originalEnv); err != nil {
			return fmt.Errorf("persist env sidecar: %w", err)
		}
	}

	data, err := json.Marshal(toWrite)
	if err != nil {
		s.removeEnvSidecar(snap.ID)
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	if err := s.writeAtomic(snap.ID+snapshotFileSuffix, data); err != nil {
		s.removeEnvSidecar(snap.ID)
		return err
	}
	return nil
}

// persistEnvSidecar stores the real environment strings of a snapshot in a
// separate 0600 file ("<id>.env") next to the snapshot JSON.
func (s *FileSnapshotStore) persistEnvSidecar(id string, env []string) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal env: %w", err)
	}
	return s.writeAtomic(id+envSidecarSuffix, data)
}

// removeEnvSidecar deletes the sidecar of id; failures are tolerated (the
// caller is already on an error path).
func (s *FileSnapshotStore) removeEnvSidecar(id string) {
	if err := s.remove(filepath.Join(s.Dir, id+envSidecarSuffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("rollback: removing env sidecar of snapshot %s failed: %v", id, err)
	}
}

// writeAtomic lands data in a 0600 temp file inside Dir and renames it to
// baseName (atomic on the same filesystem).
func (s *FileSnapshotStore) writeAtomic(baseName string, data []byte) error {
	tmp, err := os.CreateTemp(s.Dir, "."+baseName+".tmp")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", baseName, err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file for %s: %w", baseName, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file for %s: %w", baseName, err)
	}
	// os.CreateTemp already uses 0600; keep it explicit for readability.
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file for %s: %w", baseName, err)
	}
	if err := os.Rename(tmpName, filepath.Join(s.Dir, baseName)); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file for %s into place: %w", baseName, err)
	}
	return nil
}

// redactEnvValues replaces every value in the KEY=VALUE entries of env with
// redactedEnvPlaceholder (keys are kept). It mutates the slice in place and
// must only be called on a private deep copy.
func redactEnvValues(env []string) {
	for i, entry := range env {
		if key, _, ok := strings.Cut(entry, "="); ok {
			env[i] = key + "=" + redactedEnvPlaceholder
		} else {
			env[i] = redactedEnvPlaceholder
		}
	}
}

// listFor loads every parsable snapshot whose stored ContainerName equals
// containerName. Files are matched on the "<name>-" filename prefix plus the
// JSON payload's own ContainerName, so names that are prefixes of other names
// ("web" vs "web-2") never bleed into each other.
func (s *FileSnapshotStore) listFor(containerName string) ([]safeflow.Snapshot, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	prefix := containerName + "-"
	var snaps []safeflow.Snapshot
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		base := entry.Name()
		if !strings.HasPrefix(base, prefix) || !strings.HasSuffix(base, snapshotFileSuffix) {
			continue
		}

		data, err := os.ReadFile(filepath.Join(s.Dir, base))
		if err != nil {
			log.Printf("rollback: skipping unreadable snapshot file %s: %v", base, err)
			continue
		}
		var snap safeflow.Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			log.Printf("rollback: skipping corrupt snapshot file %s: %v", base, err)
			continue
		}
		if snap.ContainerName != containerName {
			continue
		}
		s.rejoinEnvSidecar(&snap, base)
		snaps = append(snaps, snap)
	}
	return snaps, nil
}

// rejoinEnvSidecar restores the real environment values into a snapshot
// loaded from disk when a sidecar exists for it (i.e. it was persisted with
// RedactEnv on). A missing sidecar is fine (snapshot written without
// redaction, or with an empty env); an unreadable/corrupt sidecar leaves the
// redacted placeholders in place with a warning, so a restore is still
// attempted rather than silently dropped.
func (s *FileSnapshotStore) rejoinEnvSidecar(snap *safeflow.Snapshot, baseFile string) {
	id := strings.TrimSuffix(baseFile, snapshotFileSuffix)
	data, err := os.ReadFile(filepath.Join(s.Dir, id+envSidecarSuffix))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("rollback: reading env sidecar of snapshot %s failed (env stays redacted): %v", id, err)
		}
		s.warnIfRedacted(snap, id)
		return
	}
	var env []string
	if err := json.Unmarshal(data, &env); err != nil {
		log.Printf("rollback: parsing env sidecar of snapshot %s failed (env stays redacted): %v", id, err)
		s.warnIfRedacted(snap, id)
		return
	}
	if snap.Inspect.Config != nil {
		snap.Inspect.Config.Env = env
	}
}

// warnIfRedacted logs when a loaded snapshot still carries placeholder env
// values (its sidecar is gone), because restoring it would recreate the
// container with placeholder secrets.
func (s *FileSnapshotStore) warnIfRedacted(snap *safeflow.Snapshot, id string) {
	if snap.Inspect.Config == nil {
		return
	}
	for _, entry := range snap.Inspect.Config.Env {
		if strings.HasSuffix(entry, "="+redactedEnvPlaceholder) || entry == redactedEnvPlaceholder {
			log.Printf("rollback: WARNING: snapshot %s carries redacted environment values without a sidecar; restoring it would recreate the container with placeholder secrets", id)
			return
		}
	}
}

// sortSnapshotsNewestFirst orders by CreatedAt descending, breaking exact
// ties by ID so the order stays deterministic.
func sortSnapshotsNewestFirst(snaps []safeflow.Snapshot) {
	sort.Slice(snaps, func(i, j int) bool {
		if !snaps[i].CreatedAt.Equal(snaps[j].CreatedAt) {
			return snaps[i].CreatedAt.After(snaps[j].CreatedAt)
		}
		return snaps[i].ID > snaps[j].ID
	})
}

// snapshotID builds the store-wide unique ID "<containerName>-<unixnano>",
// which doubles as the on-disk file base name.
func snapshotID(name string, now time.Time) string {
	return fmt.Sprintf("%s-%d", name, now.UnixNano())
}

// containerName strips the leading "/" the daemon prepends to inspect names
// ("/portainer" -> "portainer"). Bare names pass through unchanged.
func containerName(inspectName string) string {
	return strings.TrimPrefix(inspectName, "/")
}

// deepCopyContainerJSON returns a value copy that shares no pointer, slice or
// map with the original, via an encoding/json round-trip. types.ContainerJSON
// is plain exported data, so the round-trip is lossless for every field the
// recreate path consumes.
func deepCopyContainerJSON(src types.ContainerJSON) (types.ContainerJSON, error) {
	data, err := json.Marshal(src)
	if err != nil {
		return types.ContainerJSON{}, fmt.Errorf("marshal: %w", err)
	}
	var dst types.ContainerJSON
	if err := json.Unmarshal(data, &dst); err != nil {
		return types.ContainerJSON{}, fmt.Errorf("unmarshal: %w", err)
	}
	return dst, nil
}
