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

package precheck

import (
	"strconv"
	"strings"

	"github.com/distribution/reference"
)

// Semver is the parsed, comparable form of an image tag accepted by Drydock's
// conservative semver parser. Everything in this file is pure: no I/O, no
// clock, no network - the same input always yields the same output.
type Semver struct {
	Major      uint64
	Minor      uint64
	Patch      uint64
	Prerelease string // original prerelease text without the leading '-'; "" when absent
	Build      string // original build text without the leading '+'; ignored by comparison
}

// IsPrerelease reports whether the version carries a prerelease suffix.
func (s Semver) IsPrerelease() bool { return s.Prerelease != "" }

// ParseSemverTag parses an image TAG (not a full reference; see TagFromRef)
// with a deliberately conservative subset of semver.org grammar:
//
//   - an optional single "v" or "V" prefix (common in Docker tags),
//   - a core of major[.minor[.patch]] where every segment is pure digits
//     with no leading zeros (except the literal "0"); missing minor/patch
//     default to 0,
//   - an optional "-prerelease" of dot/hyphen separated identifiers where
//     each identifier is non-empty alphanumeric ([0-9A-Za-z]+) and purely
//     numeric identifiers carry no leading zeros,
//   - an optional "+build" of dot separated non-empty alphanumeric+hyphen
//     identifiers; leading zeros are tolerated here because build metadata
//     is ignored when comparing (semver.org section 10).
//
// Hyphens act as identifier separators inside the prerelease in addition to
// dots. That is what keeps date-style tags such as "2026-09-21" OUT: the
// segment "09" is a purely numeric identifier with a leading zero. This is
// intentionally stricter than semver.org (which would read "09-21" as one
// alphanumeric identifier) - a conservative parser must prefer rejecting a
// plausible-looking version over accepting a non-version.
//
// Everything else returns false: the empty tag, "latest", digest fragments
// ("@sha256:..." or "sha256:..."), tags with more than three core segments
// ("1.2.3.4"), underscores, spaces, empty identifiers ("1.2.3-", "1..2"),
// leading zeros anywhere in the core, and numeric prerelease identifiers
// that overflow uint64.
func ParseSemverTag(tag string) (Semver, bool) {
	s := tag
	// Optional single v/V prefix.
	if s != "" && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	if s == "" {
		return Semver{}, false
	}

	var v Semver

	// Split off +build metadata first (it may itself contain hyphens).
	if i := strings.IndexByte(s, '+'); i >= 0 {
		build := s[i+1:]
		if !validBuild(build) {
			return Semver{}, false
		}
		v.Build = build
		s = s[:i]
		if s == "" {
			return Semver{}, false // "+build" or "v+build" carry no version core.
		}
	}

	// Split off -prerelease at the first hyphen; remaining hyphens are
	// identifier separators inside the prerelease.
	pre := ""
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
		if pre == "" {
			return Semver{}, false // "1.2.3-" carries an empty prerelease.
		}
		if !validPrerelease(pre) {
			return Semver{}, false
		}
	}
	if s == "" {
		return Semver{}, false // "-1.2.3" and friends.
	}

	// Core: 1 to 3 dot separated numeric segments without leading zeros.
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return Semver{}, false
	}
	for i, p := range parts {
		n, ok := parseCoreSegment(p)
		if !ok {
			return Semver{}, false
		}
		switch i {
		case 0:
			v.Major = n
		case 1:
			v.Minor = n
		case 2:
			v.Patch = n
		}
	}
	v.Prerelease = pre
	return v, true
}

// CompareSemver orders two versions by semver precedence and returns -1, 0
// or 1. Build metadata is ignored; a version without a prerelease outranks
// the same version with one; numeric identifiers compare numerically and
// rank below alphanumeric ones; otherwise identifiers compare byte-wise;
// when all shared identifiers are equal, the longer identifier list wins.
func CompareSemver(a, b Semver) int {
	if c := compareUint(a.Major, b.Major); c != 0 {
		return c
	}
	if c := compareUint(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := compareUint(a.Patch, b.Patch); c != 0 {
		return c
	}
	at := prereleaseIdentifiers(a.Prerelease)
	bt := prereleaseIdentifiers(b.Prerelease)
	if len(at) == 0 || len(bt) == 0 {
		// A release outranks any prerelease of the same core; equal when
		// neither side carries one.
		switch {
		case len(at) == len(bt):
			return 0
		case len(at) == 0:
			return 1
		default:
			return -1
		}
	}
	for i := 0; i < len(at) && i < len(bt); i++ {
		if c := compareIdentifier(at[i], bt[i]); c != 0 {
			return c
		}
	}
	return compareInt(len(at), len(bt))
}

// TagFromRef extracts the tag portion of an image reference using the same
// grammar the Docker daemon applies (github.com/distribution/reference,
// already an upstream dependency, go.mod:7). It returns "" when the
// reference is empty, unparsable, digest-pinned, or carries no explicit tag
// (a bare repository implies ":latest", which is not a semver tag).
func TagFromRef(ref string) string {
	if ref == "" {
		return ""
	}
	parsed, err := reference.Parse(ref)
	if err != nil {
		return ""
	}
	tagged, ok := parsed.(reference.Tagged)
	if !ok {
		return ""
	}
	return tagged.Tag()
}

// parseCoreSegment parses one core segment: pure digits, no leading zeros
// except the literal "0", and within uint64 range.
func parseCoreSegment(seg string) (uint64, bool) {
	if !isDigits(seg) || hasLeadingZero(seg) {
		return 0, false
	}
	n, err := strconv.ParseUint(seg, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// validPrerelease validates the prerelease text (without its leading '-'):
// identifiers are separated by '.' and '-', each identifier is a non-empty
// alphanumeric run, and purely numeric identifiers carry no leading zeros.
// Identifiers that are pure digits must also fit uint64 - rejecting absurd
// numeric identifiers keeps comparison overflow-free.
func validPrerelease(pre string) bool {
	for _, dotSeg := range strings.Split(pre, ".") {
		for _, id := range strings.Split(dotSeg, "-") {
			if id == "" || !isAlnum(id) {
				return false
			}
			if isDigits(id) {
				if hasLeadingZero(id) {
					return false
				}
				if _, err := strconv.ParseUint(id, 10, 64); err != nil {
					return false
				}
			}
		}
	}
	return true
}

// validBuild validates build metadata (without its leading '+'): dot
// separated non-empty identifiers of alphanumerics and hyphens. Leading
// zeros are allowed because build metadata never affects precedence.
func validBuild(build string) bool {
	if build == "" {
		return false
	}
	for _, seg := range strings.Split(build, ".") {
		if seg == "" {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '-') {
				return false
			}
		}
	}
	return true
}

// prereleaseIdentifiers re-splits stored prerelease text into comparison
// identifiers. For values produced by ParseSemverTag this is exactly the
// validation split; for hand-constructed Semvers it degrades gracefully
// (empty identifiers are dropped) so Compare never panics.
func prereleaseIdentifiers(pre string) []string {
	if pre == "" {
		return nil
	}
	var ids []string
	for _, dotSeg := range strings.Split(pre, ".") {
		for _, id := range strings.Split(dotSeg, "-") {
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// compareIdentifier orders two prerelease identifiers: numeric identifiers
// rank below alphanumeric ones, numeric pairs compare by value (length first
// works because leading zeros are banned, which also makes this
// overflow-proof for any input), everything else compares byte-wise.
func compareIdentifier(x, y string) int {
	xn, yn := isDigits(x), isDigits(y)
	switch {
	case xn && yn:
		if len(x) != len(y) {
			return compareInt(len(x), len(y))
		}
		return strings.Compare(x, y)
	case xn:
		return -1
	case yn:
		return 1
	default:
		return strings.Compare(x, y)
	}
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isAlnum(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
			return false
		}
	}
	return true
}

// hasLeadingZero reports whether s is multi-digit and starts with '0'.
func hasLeadingZero(s string) bool {
	return len(s) > 1 && s[0] == '0'
}

func compareUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
