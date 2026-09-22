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

// Hardening tests complementing precheck_test.go. Everything here is
// table-driven and hermetic: the package under test performs no I/O, reads no
// clock and touches no network (precheck.go:23-25), so no docker daemon, no
// stubbed transport and no faked clock are required. Changelog evidence is
// injected through PrecheckRequest.TargetImageLabels - that is the package's
// v0.1 injection seam (the package imports no net/http at all), exercised
// here with adversarial label payloads.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drydock-updater/drydock/pkg/safeflow"
)

// Interface conformance is pinned in production (precheck.go:80); pin it from
// the test side too so a refactor that drops the method fails here first.
var _ safeflow.Prechecker = (*Checker)(nil)

// TestBypassedLabelValueMatrix walks the full strconv.ParseBool surface for
// the per-container label. Every value that parses false must bypass all
// policies; every value that parses true, and every unparsable value, must
// keep the gate active (precheck.go:171-178, safeflow.go:57-60).
func TestBypassedLabelValueMatrix(t *testing.T) {
	cases := []struct {
		label  string
		bypass bool
	}{
		{"false", true},
		{"FALSE", true},
		{"False", true},
		{"0", true},
		{"f", true},
		{"F", true},
		{"true", false},
		{"TRUE", false},
		{"True", false},
		{"1", false},
		{"t", false},
		{"T", false},
		{"", false},       // unparsable -> gate active
		{"yes", false},    // unparsable
		{"no", false},     // looks negative but is unparsable
		{"2", false},      // unparsable
		{"01", false},     // unparsable
		{" false", false}, // leading space -> unparsable
	}
	// A request that every active policy would block, so an active gate is
	// observable as PrecheckBlockedNoHealthcheck (the hardest block).
	kitchenSinkCfg := Config{
		BlockMajor:         true,
		BlockPrerelease:    true,
		UnknownTagPolicy:   UnknownTagBlock,
		RequireHealthcheck: true,
	}
	blockingReq := safeflow.PrecheckRequest{
		CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0-rc.1",
		TargetHasHealthcheck: false,
	}
	for _, c := range cases {
		c := c
		t.Run("label="+c.label, func(t *testing.T) {
			req := blockingReq
			req.ContainerLabels = map[string]string{safeflow.LabelPrecheck: c.label}
			got, err := New(kitchenSinkCfg).Precheck(context.Background(), req)
			require.NoError(t, err)
			if c.bypass {
				assert.True(t, got.Allow, "label %q must bypass", c.label)
				assert.Equal(t, safeflow.PrecheckBypassed, got.Reason)
			} else {
				assert.False(t, got.Allow, "label %q must keep the gate active", c.label)
				assert.Equal(t, safeflow.PrecheckBlockedNoHealthcheck, got.Reason)
			}
		})
	}
	// Other labels in the map must not interfere with the bypass lookup.
	t.Run("unrelated labels do not bypass", func(t *testing.T) {
		got, err := New(Config{BlockMajor: true}).Precheck(context.Background(), safeflow.PrecheckRequest{
			CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
			ContainerLabels: map[string]string{"com.example.other": "false", "foo": "0"},
		})
		require.NoError(t, err)
		assert.False(t, got.Allow)
		assert.Equal(t, safeflow.PrecheckBlockedMajor, got.Reason)
	})
}

// TestPrecheckDecisionOrder pins the documented first-match-wins order
// (precheck.go:27-33): bypass > missing healthcheck > semver table, and
// inside the semver table major > prerelease. Each row feeds a request that
// would trigger several blocks simultaneously and asserts which one wins.
func TestPrecheckDecisionOrder(t *testing.T) {
	allBlocking := Config{
		BlockMajor:         true,
		BlockPrerelease:    true,
		UnknownTagPolicy:   UnknownTagBlock,
		RequireHealthcheck: true,
	}
	cases := []struct {
		name string
		cfg  Config
		req  safeflow.PrecheckRequest
		want safeflow.PrecheckReason
	}{
		{
			name: "bypass outranks missing healthcheck, unknown tags, major and prerelease",
			cfg:  allBlocking,
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:latest", TargetImageRef: "nginx:2.0.0-rc.1",
				ContainerLabels:      map[string]string{safeflow.LabelPrecheck: "false"},
				TargetHasHealthcheck: false,
			},
			want: safeflow.PrecheckBypassed,
		},
		{
			name: "missing healthcheck outranks major and prerelease blocks",
			cfg:  allBlocking,
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0-rc.1",
				TargetHasHealthcheck: false,
			},
			want: safeflow.PrecheckBlockedNoHealthcheck,
		},
		{
			name: "missing healthcheck outranks unknown tag block",
			cfg:  allBlocking,
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:latest", TargetImageRef: "nginx:nightly",
				TargetHasHealthcheck: false,
			},
			want: safeflow.PrecheckBlockedNoHealthcheck,
		},
		{
			name: "unknown tag outranks major and prerelease blocks",
			cfg:  allBlocking,
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:latest", TargetImageRef: "nginx:9.9.9-rc.1",
				TargetHasHealthcheck: true,
			},
			want: safeflow.PrecheckBlockedUnknownTag,
		},
		{
			name: "major block outranks prerelease block",
			cfg:  allBlocking,
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0-rc.1",
				TargetHasHealthcheck: true,
			},
			want: safeflow.PrecheckBlockedMajor,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got, err := New(c.cfg).Precheck(context.Background(), c.req)
			require.NoError(t, err)
			assert.Equal(t, c.want, got.Reason)
			assert.Equal(t, c.want == safeflow.PrecheckBypassed, got.Allow)
			if got.Allow {
				assert.Empty(t, got.Detail)
			} else {
				assert.NotEmpty(t, got.Detail)
			}
		})
	}
}

// TestPrecheckBlockedVerdictDetailContent asserts each of the four block
// reasons produces a Detail that names the offending evidence (the ref, the
// tag or the policy flag), so reports stay actionable (verdict contract:
// Detail non-empty whenever Allow=false, safeflow.go:119).
func TestPrecheckBlockedVerdictDetailContent(t *testing.T) {
	cases := []struct {
		name      string
		cfg       Config
		req       safeflow.PrecheckRequest
		reason    safeflow.PrecheckReason
		detailHas []string
	}{
		{
			name: "no healthcheck names the target ref and the flag",
			cfg:  Config{RequireHealthcheck: true, UnknownTagPolicy: UnknownTagAllow},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
				TargetHasHealthcheck: false,
			},
			reason:    safeflow.PrecheckBlockedNoHealthcheck,
			detailHas: []string{"nginx:1.26.0", "--require-healthcheck"},
		},
		{
			name: "major block names both tags and the flag",
			cfg:  Config{BlockMajor: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
			},
			reason:    safeflow.PrecheckBlockedMajor,
			detailHas: []string{`"1.9.0"`, `"2.0.0"`, "--block-major"},
		},
		{
			name: "prerelease block names the tag and the flag",
			cfg:  Config{BlockPrerelease: true},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:2.0.0", TargetImageRef: "nginx:2.1.0-rc.1",
			},
			reason:    safeflow.PrecheckBlockedPrerelease,
			detailHas: []string{`"2.1.0-rc.1"`, "--block-prerelease"},
		},
		{
			name: "unknown tag block names the unparsable side and the flag",
			cfg:  Config{UnknownTagPolicy: UnknownTagBlock},
			req: safeflow.PrecheckRequest{
				CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:latest",
			},
			reason:    safeflow.PrecheckBlockedUnknownTag,
			detailHas: []string{"nginx:latest", `"latest"`, "--precheck-unknown-tag=block"},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got, err := New(c.cfg).Precheck(context.Background(), c.req)
			require.NoError(t, err)
			assert.False(t, got.Allow)
			assert.Equal(t, c.reason, got.Reason)
			for _, sub := range c.detailHas {
				assert.Contains(t, got.Detail, sub)
			}
		})
	}
}

// TestPrecheckContextIndependence is the timeout/cancellation boundary for
// this stage: v0.1 Precheck is pure and must not consult ctx (precheck.go:
// 87-90), so an already-cancelled or deadline-exceeded context can neither
// change the verdict nor manufacture an error. Every context flavor must
// yield the same verdict as context.Background for both an allowed and a
// blocked request.
func TestPrecheckContextIndependence(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	expired, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer cancelDeadline()
	require.True(t, expired.Err() != nil, "deadline must already be exceeded")

	allowedReq := safeflow.PrecheckRequest{CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0"}
	blockedReq := safeflow.PrecheckRequest{CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0"}
	blockCfg := Config{BlockMajor: true}

	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"background", context.Background()},
		{"todo", context.TODO()},
		{"cancelled", cancelled},
		{"deadline exceeded", expired},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotAllow, err := New(Config{}).Precheck(tc.ctx, allowedReq)
			require.NoError(t, err)
			assert.True(t, gotAllow.Allow)
			assert.Equal(t, safeflow.PrecheckAllowed, gotAllow.Reason)

			gotBlock, err := New(blockCfg).Precheck(tc.ctx, blockedReq)
			require.NoError(t, err)
			assert.False(t, gotBlock.Allow)
			assert.Equal(t, safeflow.PrecheckBlockedMajor, gotBlock.Reason)
			assert.NotEmpty(t, gotBlock.Detail)
		})
	}
}

// TestPrecheckPathologicalInputsNeverError is the error-propagation
// contract: v0.1 never returns an error, however mangled the request
// (precheck.go:88-90; safeflow.go:127-130 reserves the error for v0.2 network
// evidence). Degenerate input must degrade to a verdict - typically the
// fail-closed unknown-tag block - never to an error or an Allow=false
// verdict without a Detail, under every policy configuration.
func TestPrecheckPathologicalInputsNeverError(t *testing.T) {
	longTag := strings.Repeat("a", 129) // one byte past the 128-char tag grammar limit
	cases := []struct {
		name string
		req  safeflow.PrecheckRequest
	}{
		{"zero value request", safeflow.PrecheckRequest{}},
		{"ids without refs", safeflow.PrecheckRequest{ContainerID: "abc", ContainerName: "web"}},
		{"empty refs with labels", safeflow.PrecheckRequest{
			ContainerLabels:   map[string]string{safeflow.LabelPrecheck: "maybe"},
			TargetImageLabels: map[string]string{"org.opencontainers.image.version": ""},
		}},
		{"unparsable current ref", safeflow.PrecheckRequest{CurrentImageRef: ":::", TargetImageRef: "nginx:1.2.3"}},
		{"unparsable target ref", safeflow.PrecheckRequest{CurrentImageRef: "nginx:1.2.3", TargetImageRef: "nginx:"}},
		{"space in ref", safeflow.PrecheckRequest{CurrentImageRef: "n ginx:1.2.3", TargetImageRef: "nginx:1.3.0"}},
		{"invalid tag characters", safeflow.PrecheckRequest{CurrentImageRef: "nginx:1.2.3", TargetImageRef: "nginx:1.2.3!!!"}},
		{"overlong tag falls off the tag grammar", safeflow.PrecheckRequest{CurrentImageRef: "nginx:" + longTag, TargetImageRef: "nginx:1.2.3"}},
		{"unicode label values", safeflow.PrecheckRequest{
			CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
			TargetImageLabels: map[string]string{
				"org.opencontainers.image.description": "反向代理服务器 — über proxy",
				"org.opencontainers.image.source":      "https://example.invalid/源码",
			},
		}},
		{"oversized label map of unknown keys", safeflow.PrecheckRequest{
			CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
			TargetImageLabels: hugeLabelMap(64),
		}},
		{"empty non-nil container labels", safeflow.PrecheckRequest{
			CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0",
			ContainerLabels: map[string]string{},
		}},
	}
	configs := []Config{
		{},                                  // zero value (fail closed)
		{UnknownTagPolicy: UnknownTagAllow}, // fail open
		{BlockMajor: true, BlockPrerelease: true, RequireHealthcheck: true}, // strictest
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			for ci, cfg := range configs {
				got, err := New(cfg).Precheck(context.Background(), c.req)
				require.NoError(t, err, "config #%d: v0.1 Precheck must never error", ci)
				assert.Contains(t, []safeflow.PrecheckReason{
					safeflow.PrecheckAllowed,
					safeflow.PrecheckBlockedMajor,
					safeflow.PrecheckBlockedPrerelease,
					safeflow.PrecheckBlockedUnknownTag,
					safeflow.PrecheckBlockedNoHealthcheck,
					safeflow.PrecheckBypassed,
				}, got.Reason, "config #%d: Reason must stay a defined constant", ci)
				if !got.Allow {
					assert.NotEmpty(t, got.Detail, "config #%d: every veto carries a detail", ci)
				}
				assert.LessOrEqual(t, len(got.Notes), maxNotes, "config #%d", ci)
			}
		})
	}
	// The error return must not carry a safeflow sentinel either: precheck
	// owns none of them (they belong to the later loop stages).
	t.Run("no sentinel leaks", func(t *testing.T) {
		_, err := New(Config{}).Precheck(context.Background(), safeflow.PrecheckRequest{})
		require.NoError(t, err)
		for _, sentinel := range []error{
			safeflow.ErrHealthTimeout, safeflow.ErrUnhealthy,
			safeflow.ErrSnapshotInvalid, safeflow.ErrRollbackImageMissing,
		} {
			assert.False(t, errors.Is(err, sentinel))
		}
	})
}

// TestChangelogNotes is the changelog-injection seam. v0.1 surfaces evidence
// exclusively from the injected TargetImageLabels (precheck.go:107-109 and
// 197-213): no network fetch exists to stub, unknown keys are ignored so a
// noisy or hostile image cannot smuggle extra notes in, and output order is
// the fixed priority order, immune to Go's randomized map iteration.
func TestChangelogNotes(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
		want   []string
	}{
		{"nil labels", nil, nil},
		{"empty labels", map[string]string{}, nil},
		{"all evidence values empty", map[string]string{
			"org.opencontainers.image.source":        "",
			"org.opencontainers.image.description":   "",
			"org.opencontainers.image.changelog.url": "",
			"org.opencontainers.image.version":       "",
		}, nil},
		{"unknown keys ignored", map[string]string{
			"org.opencontainers.image.title":    "nginx",
			"org.opencontainers.image.licenses": "Apache-2.0",
			"com.example.custom":                "boom",
		}, nil},
		{"source only", map[string]string{
			"org.opencontainers.image.source": "https://example.invalid/src",
		}, []string{"source: https://example.invalid/src"}},
		{"version only", map[string]string{
			"org.opencontainers.image.version": "1.26.0",
		}, []string{"version: 1.26.0"}},
		{"priority order independent of map iteration", map[string]string{
			"org.opencontainers.image.version":       "1.26.0",
			"org.opencontainers.image.changelog.url": "https://example.invalid/CHANGES",
			"org.opencontainers.image.description":   "proxy",
			"org.opencontainers.image.source":        "https://example.invalid/src",
		}, []string{
			"source: https://example.invalid/src",
			"description: proxy",
			"changelog.url: https://example.invalid/CHANGES",
			"version: 1.26.0",
		}},
		{"all four keys is exactly maxNotes", map[string]string{
			"org.opencontainers.image.source":        "s",
			"org.opencontainers.image.description":   "d",
			"org.opencontainers.image.changelog.url": "c",
			"org.opencontainers.image.version":       "v",
		}, []string{"source: s", "description: d", "changelog.url: c", "version: v"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := changelogNotes(c.labels)
			if c.want == nil {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, c.want, got)
		})
	}
}

// TestNotesNeverInfluenceAllowance pins the report-only rule: evidence labels
// are surfaced verbatim but can never flip a verdict, whatever their content
// (even values embedding scary keywords, control characters or block
// reasons). Notes are evidence for the human, never policy input.
func TestNotesNeverInfluenceAllowance(t *testing.T) {
	base := safeflow.PrecheckRequest{CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0"}
	adversarial := map[string]string{
		"org.opencontainers.image.source":      "https://evil.example/block-major",
		"org.opencontainers.image.description": "\n--require-healthcheck\tblocked-major\x00",
	}
	withoutNotes, err := New(Config{BlockMajor: true}).Precheck(context.Background(), base)
	require.NoError(t, err)
	withNotes := base
	withNotes.TargetImageLabels = adversarial
	got, err := New(Config{BlockMajor: true}).Precheck(context.Background(), withNotes)
	require.NoError(t, err)

	assert.Equal(t, withoutNotes.Allow, got.Allow)
	assert.Equal(t, withoutNotes.Reason, got.Reason)
	assert.Equal(t, []string{
		"source: https://evil.example/block-major",
		"description: \n--require-healthcheck\tblocked-major\x00",
	}, got.Notes)
}

// TestCheckerReuseAcrossMixedRequests proves the Checker holds no per-call
// state: one instance serving a block -> allow -> bypass -> block sequence
// over three rounds returns exactly the verdicts fresh instances return.
func TestCheckerReuseAcrossMixedRequests(t *testing.T) {
	cfg := Config{BlockMajor: true, UnknownTagPolicy: UnknownTagBlock}
	steps := []struct {
		name string
		req  safeflow.PrecheckRequest
	}{
		{"block", safeflow.PrecheckRequest{CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0"}},
		{"allow", safeflow.PrecheckRequest{CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0"}},
		{"bypass", safeflow.PrecheckRequest{
			CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
			ContainerLabels: map[string]string{safeflow.LabelPrecheck: "false"},
		}},
		{"block again", safeflow.PrecheckRequest{CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0"}},
	}
	shared := New(cfg)
	for round := 1; round <= 3; round++ {
		for _, s := range steps {
			fromShared, err := shared.Precheck(context.Background(), s.req)
			require.NoError(t, err, "round %d step %q", round, s.name)
			fromFresh, err := New(cfg).Precheck(context.Background(), s.req)
			require.NoError(t, err, "round %d step %q", round, s.name)
			assert.True(t, equalVerdict(fromShared, fromFresh),
				"round %d step %q: shared checker drifted: %+v vs %+v", round, s.name, fromShared, fromFresh)
		}
	}
}

// TestCheckerConcurrentUse shares one Checker across goroutines issuing mixed
// verdicts; every goroutine must observe exactly the single-threaded verdict
// (the type is documented "construct once, reuse freely", precheck.go:72-77).
// Run with -race to make this a real data-race guard.
func TestCheckerConcurrentUse(t *testing.T) {
	cfg := Config{BlockMajor: true, BlockPrerelease: true, UnknownTagPolicy: UnknownTagBlock}
	requests := []safeflow.PrecheckRequest{
		{CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0"},
		{CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0"},
		{CurrentImageRef: "nginx:1.25.3", TargetImageRef: "nginx:1.26.0-rc.1"},
		{CurrentImageRef: "app:latest", TargetImageRef: "app:nightly"},
		{CurrentImageRef: "nginx:1.9.0", TargetImageRef: "nginx:2.0.0",
			ContainerLabels: map[string]string{safeflow.LabelPrecheck: "false"}},
	}
	expected := make([]safeflow.PrecheckVerdict, len(requests))
	for i, req := range requests {
		v, err := New(cfg).Precheck(context.Background(), req)
		require.NoError(t, err)
		expected[i] = v
	}

	shared := New(cfg)
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < 25; iter++ {
				idx := (w + iter) % len(requests)
				got, err := shared.Precheck(context.Background(), requests[idx])
				if err != nil {
					errs <- fmt.Errorf("worker %d: unexpected error: %w", w, err)
					return
				}
				if !equalVerdict(got, expected[idx]) {
					errs <- fmt.Errorf("worker %d iter %d: verdict drift on request %d: %+v vs %+v",
						w, iter, idx, got, expected[idx])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestTagFromRefExtraEdges adds reference-grammar edges beyond the base
// table in precheck_test.go: empty tag after colon, whitespace, invalid tag
// characters, nested repository paths and the 128/129 tag-length boundary
// (the Docker tag grammar is [\w][\w.-]{0,127}). All boundaries were probed
// against github.com/distribution/reference v0.5.0 before being pinned.
func TestTagFromRefExtraEdges(t *testing.T) {
	tag128 := strings.Repeat("a", 128)
	tag129 := strings.Repeat("a", 129)
	cases := []struct {
		name string
		ref  string
		want string
	}{
		{"empty tag after colon", "nginx:", ""},
		{"whitespace in repository", "n ginx:1.2.3", ""},
		{"exclamation in tag", "nginx:1.2.3!!!", ""},
		{"nested repository path with port", "registry.example.com:5000/team/app/module:1.2.3", "1.2.3"},
		{"tag at the 128 byte grammar limit", "nginx:" + tag128, tag128},
		{"tag one byte past the grammar limit", "nginx:" + tag129, ""},
		{"bare fully qualified repository", "docker.io/library/nginx", ""},
		{"colon only", ":", ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, TagFromRef(c.ref))
		})
	}
}

// TestParseSemverTagExtraEdges adds parser edges beyond the base table:
// double hyphens, bare-prerelease cores, mixed case and build corner cases.
func TestParseSemverTagExtraEdges(t *testing.T) {
	cases := []struct {
		name string
		tag  string
		want Semver
		ok   bool
	}{
		{"bare zero", "0", Semver{}, true},
		{"zero minor and patch", "0.0", Semver{}, true},
		{"core with bare numeric prerelease", "1-2", Semver{Major: 1, Prerelease: "2"}, true},
		{"double hyphen prerelease is empty identifier", "1.2.3--a", Semver{}, false},
		{"trailing hyphen in prerelease", "1.2.3-a-", Semver{}, false},
		{"uppercase prerelease identifiers", "1.2.3-Alpha", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "Alpha"}, true},
		{"numeric zero build identifier", "1.2.3+0", Semver{Major: 1, Minor: 2, Patch: 3, Build: "0"}, true},
		{"build with only hyphens", "1.2.3+a-b-c", Semver{Major: 1, Minor: 2, Patch: 3, Build: "a-b-c"}, true},
		{"build with dot separated empties", "1.2.3+a..b", Semver{}, false},
		{"prerelease with trailing dot", "1.2.3-alpha.", Semver{}, false},
		{"three leading zeros", "000", Semver{}, false},
		{"v prefix with leading zero", "v01.2.3", Semver{}, false},
		{"core segment overflow on minor", "1.18446744073709551616.0", Semver{}, false},
		{"plus inside prerelease is not build metadata", "1.2.3-a+b", Semver{Major: 1, Minor: 2, Patch: 3, Prerelease: "a", Build: "b"}, true},
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
			assert.Equal(t, c.want, got)
		})
	}
}

// TestCompareSemverHandConstructed exercises the documented graceful
// degradation for hand-built Semver values the parser would reject
// (semver.go:246-248): comparison stays total, panic-free, and drops empty
// prerelease identifiers instead of choking on them.
func TestCompareSemverHandConstructed(t *testing.T) {
	assert.Equal(t, 0, CompareSemver(Semver{}, Semver{}))
	assert.Equal(t, -1, CompareSemver(Semver{Major: 2}, Semver{Major: 10}))                 // numeric, not lexicographic
	assert.Equal(t, -1, CompareSemver(Semver{Major: 1, Prerelease: "x"}, Semver{Major: 1})) // prerelease ranks below release
	assert.Equal(t, 1, CompareSemver(Semver{Major: 1}, Semver{Major: 1, Prerelease: "x"}))  // and release above prerelease
	// Empty identifiers are dropped, so "alpha." compares equal to "alpha".
	assert.Equal(t, 0, CompareSemver(
		Semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha."},
		Semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"}))
	assert.Equal(t, 0, CompareSemver(
		Semver{Major: 1, Prerelease: "a.--b"},
		Semver{Major: 1, Prerelease: "a.b"}))
	// uint64 extremes compare by value without overflow.
	max := Semver{Major: 18446744073709551615}
	assert.Equal(t, 0, CompareSemver(max, max))
	assert.Equal(t, -1, CompareSemver(Semver{Major: 18446744073709551614}, max))
}

// --- small helpers ---------------------------------------------------------

// equalVerdict compares verdicts field by field (PrecheckVerdict contains a
// slice, so == is not available).
func equalVerdict(a, b safeflow.PrecheckVerdict) bool {
	if a.Allow != b.Allow || a.Reason != b.Reason || a.Detail != b.Detail ||
		a.CurrentTag != b.CurrentTag || a.TargetTag != b.TargetTag ||
		a.Semver != b.Semver || a.MajorBump != b.MajorBump || len(a.Notes) != len(b.Notes) {
		return false
	}
	for i := range a.Notes {
		if a.Notes[i] != b.Notes[i] {
			return false
		}
	}
	return true
}

// hugeLabelMap builds a map of size n whose keys are all unknown to the
// evidence whitelist.
func hugeLabelMap(n int) map[string]string {
	m := make(map[string]string, n)
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("com.example.noise.%d.%s", i, strings.Repeat("x", 1+i%7))] = "noise"
	}
	return m
}
