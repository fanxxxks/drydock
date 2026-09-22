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

// Package precheck implements safeflow.Prechecker, the pre-update policy
// gate that sits between staleness detection and the update decision in
// Drydock's safety loop (upstream insertion point: internal/actions/update.go
// after IsContainerStale, before the shouldUpdate decision).
//
// The gate answers one question per container: "may this update proceed?"
// using only data already available locally (the running container's image
// ref plus the freshly pulled image's inspect). It performs no I/O, reads no
// clock and touches no network, so Precheck is a pure function of
// (Config, PrecheckRequest) and fully table-testable.
//
// Decision order (first match wins):
//
//  1. per-container label bypass  - safeflow.LabelPrecheck parses false,
//  2. missing required HEALTHCHECK - the hardest block, evaluated before
//     any tag reasoning,
//  3. the semver decision table   - major bump / prerelease / downgrade,
//     or the UnknownTagPolicy when either tag is not conservative semver.
//
// Changelog evidence labels are surfaced as Verdict.Notes on every
// non-bypassed verdict; notes are report material only and never a block
// reason (v0.1 performs no network fetch).
package precheck

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// UnknownTagPolicy decides the verdict when the current or target tag does
// not parse as conservative semver (including empty refs, digest-pinned
// refs and floating tags such as "latest").
type UnknownTagPolicy string

const (
	// UnknownTagAllow lets the update proceed (Semver=false in the verdict).
	UnknownTagAllow UnknownTagPolicy = "allow"
	// UnknownTagBlock vetoes the update with safeflow.PrecheckBlockedUnknownTag.
	UnknownTagBlock UnknownTagPolicy = "block"
)

// Config carries the policy knobs shared with the CLI flags
// (--block-major, --block-prerelease, --precheck-unknown-tag,
// --require-healthcheck). The zero value is fail-closed: unknown tags are
// blocked unless UnknownTagAllow is set explicitly.
type Config struct {
	BlockMajor         bool
	BlockPrerelease    bool
	UnknownTagPolicy   UnknownTagPolicy
	RequireHealthcheck bool
}

// Checker is the deterministic, side-effect-free safeflow.Prechecker
// implementation. Construct once via New and reuse freely; it holds nothing
// but the config.
type Checker struct {
	cfg Config
}

// compile-time interface conformance check.
var _ safeflow.Prechecker = (*Checker)(nil)

// New returns a Checker evaluating cfg.
func New(cfg Config) *Checker {
	return &Checker{cfg: cfg}
}

// Precheck evaluates the update policy for one container. It always returns
// a nil error in v0.1 (the error return exists so later revisions can add
// network-backed evidence without changing the interface) and never reads
// anything beyond req.
func (c *Checker) Precheck(ctx context.Context, req safeflow.PrecheckRequest) (safeflow.PrecheckVerdict, error) {
	v := safeflow.PrecheckVerdict{
		CurrentTag: TagFromRef(req.CurrentImageRef),
		TargetTag:  TagFromRef(req.TargetImageRef),
	}

	// 1. Per-container opt-out. A label value that parses via
	// strconv.ParseBool to false bypasses every policy below; a missing
	// label (nil maps index safely) or an unparsable value keeps the gate
	// active. Mirrors upstream's label-driven veto philosophy.
	if bypassed(req.ContainerLabels) {
		v.Allow = true
		v.Reason = safeflow.PrecheckBypassed
		return v, nil
	}

	// Changelog evidence is report-only; gather it for every non-bypassed
	// verdict so blocked updates can still show their evidence.
	v.Notes = changelogNotes(req.TargetImageLabels)

	// 2. Hardest block: the target image defines no HEALTHCHECK while one
	// is required. Evaluated before any tag reasoning so it wins over both
	// the semver table and the UnknownTagPolicy.
	if c.cfg.RequireHealthcheck && !req.TargetHasHealthcheck {
		v.Allow = false
		v.Reason = safeflow.PrecheckBlockedNoHealthcheck
		v.Detail = fmt.Sprintf("target image %q defines no HEALTHCHECK while --require-healthcheck is enabled",
			req.TargetImageRef)
		return v, nil
	}

	// 3. Semver decision table.
	cur, curOK := ParseSemverTag(v.CurrentTag)
	tgt, tgtOK := ParseSemverTag(v.TargetTag)
	if !curOK || !tgtOK {
		// Fail-closed: only the explicit UnknownTagAllow policy lets an
		// unparseable tag pair through.
		if c.cfg.UnknownTagPolicy != UnknownTagAllow {
			v.Allow = false
			v.Reason = safeflow.PrecheckBlockedUnknownTag
			v.Detail = unknownTagDetail(req, v, curOK, tgtOK)
			return v, nil
		}
		v.Allow = true
		v.Reason = safeflow.PrecheckAllowed
		return v, nil
	}

	v.Semver = true
	v.MajorBump = tgt.Major > cur.Major

	if v.MajorBump && c.cfg.BlockMajor {
		v.Allow = false
		v.Reason = safeflow.PrecheckBlockedMajor
		v.Detail = fmt.Sprintf("major version bump %q -> %q vetoed by --block-major",
			v.CurrentTag, v.TargetTag)
		return v, nil
	}
	if tgt.IsPrerelease() && c.cfg.BlockPrerelease {
		v.Allow = false
		v.Reason = safeflow.PrecheckBlockedPrerelease
		v.Detail = fmt.Sprintf("target tag %q is a prerelease and prereleases are vetoed by --block-prerelease",
			v.TargetTag)
		return v, nil
	}

	v.Allow = true
	v.Reason = safeflow.PrecheckAllowed
	if CompareSemver(tgt, cur) < 0 {
		// Downgrades are allowed (an operator pinning back a bad release is
		// a legitimate move) but must be called out in the report.
		v.Detail = fmt.Sprintf("downgrade: target tag %q is older than current tag %q; allowed by policy",
			v.TargetTag, v.CurrentTag)
	}
	return v, nil
}

// bypassed reports whether the container carries safeflow.LabelPrecheck set
// to a strconv.ParseBool-false value ("false", "0", "f", "F", ...). A nil
// map, a missing key or an unparsable value all mean "gate stays active".
func bypassed(labels map[string]string) bool {
	raw, ok := labels[safeflow.LabelPrecheck]
	if !ok {
		return false
	}
	parsed, err := strconv.ParseBool(raw)
	return err == nil && !parsed
}

// changelogNoteKeys lists the OCI annotation labels Drydock surfaces as
// update evidence, in priority order (source first: it is the click-through
// link; version last: the tag usually already carries it).
var changelogNoteKeys = [][2]string{
	{"org.opencontainers.image.source", "source"},
	{"org.opencontainers.image.description", "description"},
	{"org.opencontainers.image.changelog.url", "changelog.url"},
	{"org.opencontainers.image.version", "version"},
}

// maxNotes caps the evidence list; with four keys it is a defensive bound.
const maxNotes = 4

// changelogNotes renders up to maxNotes "label: value" notes from the target
// image's OCI annotation labels, in the priority order of
// changelogNoteKeys. Keys holding empty values carry no evidence and are
// skipped; a nil/empty label map yields nil.
func changelogNotes(labels map[string]string) []string {
	if len(labels) == 0 {
		return nil
	}
	var notes []string
	for _, kv := range changelogNoteKeys {
		val := labels[kv[0]]
		if val == "" {
			continue
		}
		notes = append(notes, kv[1]+": "+val)
		if len(notes) == maxNotes {
			break
		}
	}
	return notes
}

// unknownTagDetail names the side(s) whose tag did not parse.
func unknownTagDetail(req safeflow.PrecheckRequest, v safeflow.PrecheckVerdict, curOK, tgtOK bool) string {
	var sides []string
	if !curOK {
		sides = append(sides, fmt.Sprintf("current image ref %q (tag %q)", req.CurrentImageRef, v.CurrentTag))
	}
	if !tgtOK {
		sides = append(sides, fmt.Sprintf("target image ref %q (tag %q)", req.TargetImageRef, v.TargetTag))
	}
	return fmt.Sprintf("no conservative semver tag for %s and unknown tags are vetoed by --precheck-unknown-tag=block",
		strings.Join(sides, " and "))
}
