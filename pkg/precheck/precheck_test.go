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
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// wellKnownEmptyDigest is the sha256 of the empty string; a syntactically
// valid digest for reference.Parse, carrying no network meaning.
const wellKnownEmptyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestParseSemverTag(t *testing.T) {
	type tc struct {
		name string
		tag  string
		want Semver
		ok   bool
	}
	cases := []tc{
		// --- valid: core shapes ---
		{"major only", "1", Semver{Major: 1}, true},
		{"major.minor", "1.2", Semver{Major: 1, Minor: 2}, true},
		{"major.minor.patch", "1.2.3", Semver{Major: 1, Minor: 2, Patch: 3}, true},
		{"v prefix", "v1.2.3", Semver{Major: 1, Minor: 2, Patch: 3}, true},
		{"uppercase V prefix", "V1.2.3", Semver{Major: 1, Minor: 2, Patch: 3}, true},
		{"zeros", "0.0.0", Semver{}, true},
		{"multi digit", "10.20.30", Semver{Major: 10, Minor: 20, Patch: 30}, true},
		{"uint64 max major", "18446744073709551615", Semver{Major: 18446744073709551615}, true},
		// --- valid: prerelease ---
		{"prerelease zero", "1.2.3-0", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "0"}, true},
		{"prerelease alpha", "1.2.3-alpha", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "alpha"}, true},
		{"prerelease alpha.1", "1.2.3-alpha.1", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "alpha.1"}, true},
		{"prerelease hyphen separator", "1.2.3-alpha-1", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "alpha-1"}, true},
		{"prerelease numeric chain", "1.2.3-0.3.7", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "0.3.7"}, true},
		{"prerelease mixed chain", "1.2.3-x.7.z.92", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "x.7.z.92"}, true},
		{"prerelease dotless numerics", "1.2.3-2026.9.21", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "2026.9.21"}, true},
		{"rc", "2.0.0-rc.1", Semver{Major: 2, Prerelease: "rc.1"}, true},
		// --- valid: build metadata ---
		{"build only", "1.2.3+build", Semver{Major: 1, Minor: 2, Patch: 3, Build: "build"}, true},
		{"build with hyphen and leading zero", "1.2.3+build.1-a.01", Semver{Major: 1, Minor: 2, Patch: 3, Build: "build.1-a.01"}, true},
		{"build hyphen", "1.2.3+build-1", Semver{Major: 1, Minor: 2, Patch: 3, Build: "build-1"}, true},
		{"prerelease plus build", "1.2.3-alpha+build", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "alpha", Build: "build"}, true},
		{"rc plus build", "1.2.3-rc.1+b.2", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc.1", Build: "b.2"}, true},
		// --- invalid ---
		{"empty tag", "", Semver{}, false},
		{"latest", "latest", Semver{}, false},
		{"v without core", "v", Semver{}, false},
		{"V without core", "V", Semver{}, false},
		{"double prefix", "vv1", Semver{}, false},
		{"leading zero major", "01", Semver{}, false},
		{"leading zero minor", "1.02.3", Semver{}, false},
		{"leading zero patch", "1.2.03", Semver{}, false},
		{"four core segments", "1.2.3.4", Semver{}, false},
		{"trailing dot", "1.", Semver{}, false},
		{"leading dot", ".1", Semver{}, false},
		{"double dot", "1..2", Semver{}, false},
		{"negative core", "-1.2.3", Semver{}, false},
		{"empty prerelease", "1.2.3-", Semver{}, false},
		{"empty build", "1.2.3+", Semver{}, false},
		{"empty prerelease identifier", "1.2.3-.", Semver{}, false},
		{"double dot prerelease", "1.2.3-a..b", Semver{}, false},
		{"underscore in prerelease", "1.2.3-a_b", Semver{}, false},
		{"space in tag", "1.2.3 a", Semver{}, false},
		{"date tag", "2026-09-21", Semver{}, false},
		{"date style prerelease", "1.2.3-2026-09-21", Semver{}, false},
		{"leading zero prerelease identifier", "1.2.3-01", Semver{}, false},
		{"leading zero dotted prerelease identifier", "1.2.3-alpha.01", Semver{}, false},
		{"uint64 overflow core", "18446744073709551616", Semver{}, false},
		{"uint64 overflow prerelease identifier", "1.2.3-99999999999999999999", Semver{}, false},
		{"digest fragment", "@sha256:abc", Semver{}, false},
		{"digest algorithm prefix", "sha256:abc", Semver{}, false},
		{"build without core", "+1", Semver{}, false},
		{"v prefix build without core", "v+1", Semver{}, false},
		{"second plus in build", "1.2.3-a+b+c", Semver{}, false},
		{"uppercase word", "LATEST", Semver{}, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseSemverTag(c.tag)
			if !c.ok {
				assert.False(t, ok, "expected %q to be rejected", c.tag)
				return
			}
			assert.True(t, ok, "expected %q to parse", c.tag)
			assert.Equal(t, c.want, got, "parsed value mismatch for %q", c.tag)
		})
	}
}

func TestCompareSemver(t *testing.T) {
	// The semver.org section 11 precedence chain, expressed with tags so
	// both parsing and comparison are exercised end to end.
	pairs := [][2]string{
		{"1.0.0-alpha", "1.0.0-alpha.1"},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta"},
		{"1.0.0-alpha.beta", "1.0.0-beta"},
		{"1.0.0-beta", "1.0.0-beta.2"},
		{"1.0.0-beta.2", "1.0.0-beta.11"},
		{"1.0.0-beta.11", "1.0.0-rc.1"},
		{"1.0.0-rc.1", "1.0.0"},
		{"1.0.0", "1.1.0"},
		{"1.1.0", "1.1.1"},
		{"1.9.9", "2.0.0"},
	}
	for _, p := range pairs {
		lo, okLo := ParseSemverTag(p[0])
		hi, okHi := ParseSemverTag(p[1])
		require.True(t, okLo && okHi, "pair members must parse: %q %q", p[0], p[1])
		assert.Equal(t, -1, CompareSemver(lo, hi), "%q must sort before %q", p[0], p[1])
		assert.Equal(t, 1, CompareSemver(hi, lo), "%q must sort after %q", p[1], p[0])
	}

	equals := [][2]string{
		{"1.0.0", "v1.0.0"},          // prefix is cosmetic
		{"1.2", "1.2.0"},             // missing patch defaults to 0
		{"1", "1.0.0"},               // missing minor+patch default to 0
		{"1.0.0+build", "1.0.0+any"}, // build metadata ignored
		{"1.0.0-alpha+1", "1.0.0-alpha+2"},
	}
	for _, p := range equals {
		a, okA := ParseSemverTag(p[0])
		b, okB := ParseSemverTag(p[1])
		require.True(t, okA && okB, "pair members must parse: %q %q", p[0], p[1])
		assert.Equal(t, 0, CompareSemver(a, b), "%q must equal %q", p[0], p[1])
	}

	numerics := [][2]string{
		{"1.0.0-2", "1.0.0-10"}, // numeric identifiers compare numerically
		{"2.0.0", "10.0.0"},     // majors compare numerically, not lexicographically
		{"1.9", "1.10"},
		{"1.2.3-alpha-1", "1.2.3-alpha-2"}, // hyphen-separated identifiers
	}
	for _, p := range numerics {
		lo, okLo := ParseSemverTag(p[0])
		hi, okHi := ParseSemverTag(p[1])
		require.True(t, okLo && okHi, "pair members must parse: %q %q", p[0], p[1])
		assert.Equal(t, -1, CompareSemver(lo, hi), "%q must sort before %q", p[0], p[1])
	}
}

func TestTagFromRef(t *testing.T) {
	cases := []struct {
		name string
		ref  string
		want string
	}{
		{"simple repo tag", "nginx:1.25.3", "1.25.3"},
		{"fully qualified", "docker.io/library/nginx:1.25.3", "1.25.3"},
		{"registry with port", "registry.example.com:5000/team/app:v2.0.0", "v2.0.0"},
		{"no tag implies latest which is absent", "nginx", ""},
		{"digest pinned", "nginx@" + wellKnownEmptyDigest, ""},
		{"tag plus digest keeps tag", "nginx:1.25.3@" + wellKnownEmptyDigest, "1.25.3"},
		{"empty ref", "", ""},
		{"uppercase repo is unparsable", "NGINX:1.2.3", ""},
		{"garbage", ":::", ""},
		{"date tag extracts fine", "nginx:2026-09-21", "2026-09-21"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, TagFromRef(c.ref))
		})
	}
}

// TestPrecheck is the acceptance table. It walks every behavior the precheck
// spec enumerates: label bypass, healthcheck-first blocking, the semver
// decision table (major/prerelease/downgrade), the unknown-tag policy,
// nil/empty boundary handling and changelog notes. Post-loop invariants
// (nil error, non-empty Detail on every block, at most 4 notes) are enforced
// for every row.
func TestPrecheck(t *testing.T) {
	type want struct {
		allow       bool
		reason      safeflow.PrecheckReason
		semver      bool
		majorBump   bool
		detailSub   string   // Detail must contain this substring
		detailEmpty bool     // Detail must be exactly ""
		notes       []string // nil means Notes must be nil
		checkTags   bool     // assert CurrentTag/TargetTag
		currentTag  string
		targetTag   string
	}
	cases := []struct {
		name string
		cfg  Config
		req  safeflow.PrecheckRequest
		want want
	}{
		// ---- label bypass: no policy evaluated afterwards ----
		{
			name: "bypass false value skips every policy",
			cfg:  Config{BlockMajor: true, BlockPrerelease: true, UnknownTagPolicy: UnknownTagBlock, RequireHealthcheck: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.0.0", TargetImageRef: "nginx:2.0.0-rc.1",
				ContainerLabels:      map[string]string{safeflow.LabelPrecheck: "false"},
				TargetImageLabels:    map[string]string{"org.opencontainers.image.source": "https://example.invalid/src"},
				TargetHasHealthcheck: false,
			},
			want: want{allow: true, reason: safeflow.PrecheckBypassed, detailEmpty: true},
		},
		{
			name: "bypass zero value",
			cfg:  Config{UnknownTagPolicy: UnknownTagBlock},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:latest", TargetImageRef: "nginx:nightly",
				ContainerLabels: map[string]string{safeflow.LabelPrecheck: "0"},
			},
			want: want{allow: true, reason: safeflow.PrecheckBypassed, detailEmpty: true},
		},
		{
			name: "bypass uppercase F value",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.0.0", TargetImageRef: "nginx:2.0.0",
				ContainerLabels: map[string]string{safeflow.LabelPrecheck: "F"},
			},
			want: want{allow: true, reason: safeflow.PrecheckBypassed, detailEmpty: true},
		},
		{
			name: "unparsable label value keeps gate active",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
				ContainerLabels: map[string]string{safeflow.LabelPrecheck: "yes please"},
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedMajor, semver: true, majorBump: true, detailSub: "block-major"},
		},
		{
			name: "label true keeps gate active",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
				ContainerLabels: map[string]string{safeflow.LabelPrecheck: "true"},
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedMajor, semver: true, majorBump: true, detailSub: "block-major"},
		},
		{
			name: "nil container labels keeps gate active",
			cfg:  Config{BlockMajor: true, UnknownTagPolicy: UnknownTagAllow},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
				ContainerLabels: nil,
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedMajor, semver: true, majorBump: true, detailSub: "block-major"},
		},
		// ---- required healthcheck: the hardest block, before tag reasoning ----
		{
			name: "missing healthcheck blocks even though semver would allow",
			cfg:  Config{RequireHealthcheck: true, UnknownTagPolicy: UnknownTagAllow},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
				TargetHasHealthcheck: false,
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedNoHealthcheck, detailSub: "HEALTHCHECK"},
		},
		{
			name: "missing healthcheck outranks unknown-tag block",
			cfg:  Config{RequireHealthcheck: true, UnknownTagPolicy: UnknownTagBlock},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "app:latest", TargetImageRef: "app:nightly",
				TargetHasHealthcheck: false,
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedNoHealthcheck, detailSub: "HEALTHCHECK"},
		},
		{
			name: "present healthcheck satisfies requirement",
			cfg:  Config{RequireHealthcheck: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
				TargetHasHealthcheck: true,
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true},
		},
		// ---- semver decision table ----
		{
			name: "major bump blocked",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedMajor, semver: true, majorBump: true, detailSub: "block-major"},
		},
		{
			name: "major bump allowed when not blocking",
			cfg:  Config{BlockMajor: false},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, majorBump: true, detailEmpty: true},
		},
		{
			name: "minor bump is not a major bump",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true},
		},
		{
			name: "patch bump allowed under strict config",
			cfg:  Config{BlockMajor: true, BlockPrerelease: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.25.4",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true},
		},
		{
			name: "same version allowed without downgrade note",
			cfg:  Config{},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.25.3",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true},
		},
		{
			name: "target prerelease blocked",
			cfg:  Config{BlockPrerelease: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0-rc.1",
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedPrerelease, semver: true, majorBump: true, detailSub: "prerelease"},
		},
		{
			name: "target prerelease allowed when not blocking",
			cfg:  Config{BlockPrerelease: false},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0-rc.1",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, majorBump: true, detailEmpty: true},
		},
		{
			name: "major block reported before prerelease block",
			cfg:  Config{BlockMajor: true, BlockPrerelease: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0-rc.1",
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedMajor, semver: true, majorBump: true, detailSub: "block-major"},
		},
		{
			name: "current prerelease is irrelevant",
			cfg:  Config{BlockPrerelease: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:2.0.0-rc.1", TargetImageRef: "nginx:2.0.0",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true},
		},
		{
			name: "downgrade allowed but flagged in detail",
			cfg:  Config{},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:2.5.0", TargetImageRef: "nginx:2.4.9",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailSub: "downgrade"},
		},
		{
			name: "downgrade allowed even with block-major",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:3.0.0", TargetImageRef: "nginx:2.0.0",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailSub: "downgrade"},
		},
		{
			name: "v prefix tags on both sides participate in semver",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "app:v1.9.0", TargetImageRef: "app:v2.0.0",
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedMajor, semver: true, majorBump: true, detailSub: "block-major"},
		},
		{
			name: "bare major segments compare",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "app:1", TargetImageRef: "app:2",
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedMajor, semver: true, majorBump: true, detailSub: "block-major"},
		},
		{
			name: "numeric minor comparison 1.9 to 1.10 is an upgrade not downgrade",
			cfg:  Config{},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "app:1.9", TargetImageRef: "app:1.10",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true},
		},
		// ---- unknown tag policy ----
		{
			name: "unknown current tag allowed by policy",
			cfg:  Config{UnknownTagPolicy: UnknownTagAllow},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:latest", TargetImageRef: "nginx:1.27.0",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, detailEmpty: true},
		},
		{
			name: "unknown target tag blocked by policy",
			cfg:  Config{UnknownTagPolicy: UnknownTagBlock},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:latest",
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedUnknownTag, detailSub: "target image ref"},
		},
		{
			name: "both tags unknown allowed",
			cfg:  Config{UnknownTagPolicy: UnknownTagAllow},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "app:snapshot", TargetImageRef: "app:nightly",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, detailEmpty: true},
		},
		{
			name: "both tags unknown blocked",
			cfg:  Config{UnknownTagPolicy: UnknownTagBlock},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "app:snapshot", TargetImageRef: "app:nightly",
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedUnknownTag, detailSub: "current image ref"},
		},
		{
			name: "empty refs blocked as unknown",
			cfg:  Config{UnknownTagPolicy: UnknownTagBlock},
			req:  safeflow.PrecheckRequest{},
			want: want{allow: false, reason: safeflow.PrecheckBlockedUnknownTag, detailSub: "current image ref"},
		},
		{
			name: "empty refs allowed by policy",
			cfg:  Config{UnknownTagPolicy: UnknownTagAllow},
			req:  safeflow.PrecheckRequest{},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, detailEmpty: true},
		},
		{
			name: "digest pinned current ref is unknown tag, allowed",
			cfg:  Config{UnknownTagPolicy: UnknownTagAllow},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx@" + wellKnownEmptyDigest, TargetImageRef: "nginx:1.27.0",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, detailEmpty: true, checkTags: true, currentTag: "", targetTag: "1.27.0"},
		},
		{
			name: "digest pinned target ref is unknown tag, blocked",
			cfg:  Config{UnknownTagPolicy: UnknownTagBlock},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx@" + wellKnownEmptyDigest,
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedUnknownTag, detailSub: "target image ref"},
		},
		{
			name: "date style target tag is unknown",
			cfg:  Config{UnknownTagPolicy: UnknownTagBlock},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "app:1.2.3", TargetImageRef: "app:2026-09-21",
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedUnknownTag, detailSub: "target image ref"},
		},
		{
			name: "zero value config is fail closed for unknown tags",
			cfg:  Config{},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "app:latest", TargetImageRef: "app:latest",
			},
			want: want{allow: false, reason: safeflow.PrecheckBlockedUnknownTag},
		},
		// ---- changelog evidence notes ----
		{
			name: "all four notes in priority order",
			cfg:  Config{},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
				TargetImageLabels: map[string]string{
					"org.opencontainers.image.source":        "https://github.com/nginx/nginx",
					"org.opencontainers.image.description":   "Reverse proxy and HTTP server",
					"org.opencontainers.image.changelog.url": "https://nginx.org/en/CHANGES",
					"org.opencontainers.image.version":       "1.26.0",
				},
			},
			want: want{
				allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true,
				notes: []string{
					"source: https://github.com/nginx/nginx",
					"description: Reverse proxy and HTTP server",
					"changelog.url: https://nginx.org/en/CHANGES",
					"version: 1.26.0",
				},
			},
		},
		{
			name: "empty label values skipped, subset in priority order",
			cfg:  Config{},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
				TargetImageLabels: map[string]string{
					"org.opencontainers.image.source":        "",
					"org.opencontainers.image.changelog.url": "https://example.invalid/CHANGES",
				},
			},
			want: want{
				allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true,
				notes: []string{"changelog.url: https://example.invalid/CHANGES"},
			},
		},
		{
			name: "nil target labels yield no notes",
			cfg:  Config{},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
				TargetImageLabels: nil,
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true},
		},
		{
			name: "notes never participate in blocking",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
				TargetImageLabels: map[string]string{
					"org.opencontainers.image.source":        "https://github.com/nginx/nginx",
					"org.opencontainers.image.description":   "Reverse proxy",
					"org.opencontainers.image.changelog.url": "https://nginx.org/en/CHANGES",
					"org.opencontainers.image.version":       "2.0.0",
				},
			},
			want: want{
				allow: false, reason: safeflow.PrecheckBlockedMajor, semver: true, majorBump: true, detailSub: "block-major",
				notes: []string{
					"source: https://github.com/nginx/nginx",
					"description: Reverse proxy",
					"changelog.url: https://nginx.org/en/CHANGES",
					"version: 2.0.0",
				},
			},
		},
		// ---- verdict tag fields ----
		{
			name: "tag fields carry the tag portion of both refs",
			cfg:  Config{},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "docker.io/library/nginx:1.25.3",
				TargetImageRef:  "docker.io/library/nginx:1.26.0",
			},
			want: want{allow: true, reason: safeflow.PrecheckAllowed, semver: true, detailEmpty: true,
				checkTags: true, currentTag: "1.25.3", targetTag: "1.26.0"},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			checker := New(c.cfg)
			got, err := checker.Precheck(context.Background(), c.req)

			// Precheck always returns a nil error in v0.1.
			require.NoError(t, err)

			assert.Equal(t, c.want.allow, got.Allow, "Allow")
			assert.Equal(t, c.want.reason, got.Reason, "Reason")
			assert.Equal(t, c.want.semver, got.Semver, "Semver")
			assert.Equal(t, c.want.majorBump, got.MajorBump, "MajorBump")

			if c.want.detailEmpty {
				assert.Empty(t, got.Detail, "Detail must be empty")
			}
			if c.want.detailSub != "" {
				assert.Contains(t, got.Detail, c.want.detailSub)
			}
			// Allow=false requires a non-empty human-readable detail.
			if !c.want.allow {
				assert.NotEmpty(t, got.Detail, "Detail must be non-empty whenever Allow=false")
			}
			if c.want.notes == nil {
				assert.Empty(t, got.Notes, "Notes must be empty")
			} else {
				assert.Equal(t, c.want.notes, got.Notes)
			}
			assert.LessOrEqual(t, len(got.Notes), maxNotes, "at most 4 evidence notes")
			if c.want.checkTags {
				assert.Equal(t, c.want.currentTag, got.CurrentTag, "CurrentTag")
				assert.Equal(t, c.want.targetTag, got.TargetTag, "TargetTag")
			}
		})
	}
}

// TestPrecheckDeterministic pins the purity requirement: identical inputs
// produce deeply identical verdicts, with no hidden state between calls.
func TestPrecheckDeterministic(t *testing.T) {
	cfg := Config{BlockMajor: true, BlockPrerelease: true, UnknownTagPolicy: UnknownTagBlock, RequireHealthcheck: true}
	req := safeflow.PrecheckRequest{
		ContainerID:     "abc123",
		ContainerName:   "web",
		CurrentImageRef: "docker.io/library/nginx:1.25.3",
		TargetImageRef:  "docker.io/library/nginx:1.27.0-rc.1",
		ContainerLabels: map[string]string{"foo": "bar"},
		TargetImageLabels: map[string]string{
			"org.opencontainers.image.source": "https://github.com/nginx/nginx",
		},
		TargetHasHealthcheck: true,
	}
	first, err1 := New(cfg).Precheck(context.Background(), req)
	second, err2 := New(cfg).Precheck(context.Background(), req)
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.True(t, reflect.DeepEqual(first, second), "verdicts must be deeply equal: %+v vs %+v", first, second)
}

// TestPrecheckNilContext verifies the contract that Precheck ignores ctx
// entirely (v0.1 is pure) and still returns a nil error.
func TestPrecheckNilContext(t *testing.T) {
	got, err := New(Config{UnknownTagPolicy: UnknownTagBlock}).
		Precheck(nil, safeflow.PrecheckRequest{CurrentImageRef: "nginx:1.0.0", TargetImageRef: "nginx:1.1.0"})
	require.NoError(t, err)
	assert.True(t, got.Allow)
	assert.Equal(t, safeflow.PrecheckAllowed, got.Reason)
}

// TestNewReturnsFreshChecker keeps the constructor honest: two checkers with
// different configs must not share state.
func TestNewReturnsFreshChecker(t *testing.T) {
	req := safeflow.PrecheckRequest{CurrentImageRef: "a:1.0.0", TargetImageRef: "a:2.0.0"}
	allowVerdict, err := New(Config{}).Precheck(context.Background(), req)
	require.NoError(t, err)
	blockVerdict, err := New(Config{BlockMajor: true}).Precheck(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, allowVerdict.Allow)
	assert.False(t, blockVerdict.Allow)
	assert.Equal(t, safeflow.PrecheckBlockedMajor, blockVerdict.Reason)
}
