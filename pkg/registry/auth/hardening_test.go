// Copyright Drydock Contributors.
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

package auth

import (
	"net/http"
	"strings"
	"testing"

	ref "github.com/distribution/reference"
)

func mustRef(t *testing.T, name string) ref.Named {
	t.Helper()
	r, err := ref.ParseNormalizedNamed(name)
	if err != nil {
		t.Fatalf("ParseNormalizedNamed(%q): %v", name, err)
	}
	return r
}

// TestGetAuthURLRealmValidation pins the SSRF/credential-exfiltration guard
// on the registry-chosen realm URL. The realm arrives in the
// WWW-Authenticate header of a challenge response, i.e. the registry (or a
// MITM on a mis-terminated hop) authors it; these are the addresses a
// hostile realm must never be allowed to aim the credentialed token request
// at. All values below are dummy placeholders, no real credentials.
func TestGetAuthURLRealmValidation(t *testing.T) {
	cases := []struct {
		label    string
		realm    string
		imageRef string
		wantErr  string // "" means must succeed
	}{
		{"public realm is accepted", "https://ghcr.io/token", "containrrr/watchtower", ""},
		{"hub realm differs from registry host but is public", "https://auth.docker.io/token", "containrrr/watchtower", ""},
		{"plaintext realm is refused", "http://ghcr.io/token", "containrrr/watchtower", "must use https"},
		{"loopback IPv4 realm is refused", "https://127.0.0.1/token", "containrrr/watchtower", "loopback"},
		{"loopback IPv6 realm is refused", "https://[::1]/token", "containrrr/watchtower", "loopback"},
		{"cloud metadata realm is refused", "https://169.254.169.254/latest/meta-data", "containrrr/watchtower", "link-local"},
		{"private realm is refused", "https://10.1.2.3/token", "containrrr/watchtower", "private"},
		{"private realm is refused (RFC1918 192.168/16)", "https://192.168.1.10:5000/token", "containrrr/watchtower", "private"},
		{"localhost name is refused", "https://localhost/token", "containrrr/watchtower", "localhost"},
		{"unspecified address is refused", "https://0.0.0.0/token", "containrrr/watchtower", "unspecified"},
		{"private realm on the operator's own registry host is allowed",
			"https://192.168.1.10:5000/token", "192.168.1.10:5000/team/app", ""},
		{"localhost realm on a localhost-run registry is allowed",
			"https://localhost:5000/token", "localhost:5000/app", ""},
		{"private realm on a DIFFERENT private host than the registry is refused",
			"https://10.9.9.9/token", "192.168.1.10:5000/team/app", "private"},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			challenge := `bearer realm="` + tc.realm + `",service="registry-service"`
			u, err := GetAuthURL(challenge, mustRef(t, tc.imageRef))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("GetAuthURL(realm=%q) failed: %v", tc.realm, err)
				}
				if u == nil || u.Host == "" {
					t.Fatalf("GetAuthURL(realm=%q) returned no usable URL: %v", tc.realm, u)
				}
				return
			}
			if err == nil {
				t.Fatalf("GetAuthURL(realm=%q) = %v, want error containing %q", tc.realm, u, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("GetAuthURL(realm=%q) error = %q, want it to mention %q", tc.realm, err, tc.wantErr)
			}
		})
	}
}

// TestGetAuthURLGarbageRealm checks unparseable or absent realm strings are
// reported instead of silently producing a request to a bogus location.
func TestGetAuthURLGarbageRealm(t *testing.T) {
	for _, realm := range []string{
		"https://[::1:bad/port", // invalid URL: url.Parse must error
		"",                      // missing realm altogether
	} {
		challenge := `bearer realm="` + realm + `",service="registry-service"`
		if realm == "" {
			challenge = `bearer service="registry-service"`
		}
		u, err := GetAuthURL(challenge, mustRef(t, "containrrr/watchtower"))
		if err == nil {
			t.Fatalf("GetAuthURL(realm=%q) = %v, want error", realm, u)
		}
	}
}

func redirectReq(t *testing.T, raw string, via ...string) (*http.Request, []*http.Request) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q): %v", raw, err)
	}
	viaReqs := make([]*http.Request, 0, len(via))
	for _, v := range via {
		vr, err := http.NewRequest(http.MethodGet, v, nil)
		if err != nil {
			t.Fatalf("NewRequest(%q): %v", v, err)
		}
		viaReqs = append(viaReqs, vr)
	}
	return req, viaReqs
}

// TestCheckAuthRedirectPolicy pins the redirect guard: hops that leave
// https or the original host are refused, and the hop count is capped, so
// the Authorization header can never be pivoted to another origin.
func TestCheckAuthRedirectPolicy(t *testing.T) {
	// Same-host https hop: allowed.
	req, via := redirectReq(t, "https://ghcr.io/token?service=x", "https://ghcr.io/token-hop1")
	if err := checkAuthRedirect(req, via); err != nil {
		t.Fatalf("same-host https redirect refused: %v", err)
	}

	// Scheme downgrade: refused even on the same host.
	req, via = redirectReq(t, "http://ghcr.io/token", "https://ghcr.io/token-hop1")
	if err := checkAuthRedirect(req, via); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("scheme downgrade not refused: %v", err)
	}

	// Cross-host https hop: refused (credential exfiltration guard).
	req, via = redirectReq(t, "https://evil.example/token", "https://ghcr.io/token-hop1")
	if err := checkAuthRedirect(req, via); err == nil || !strings.Contains(err.Error(), "cross-host") {
		t.Fatalf("cross-host redirect not refused: %v", err)
	}

	// Cross-host hop to an internal address: refused by the same guard.
	req, via = redirectReq(t, "https://127.0.0.1:8080/x", "https://ghcr.io/token")
	if err := checkAuthRedirect(req, via); err == nil || !strings.Contains(err.Error(), "cross-host") {
		t.Fatalf("redirect to internal address not refused: %v", err)
	}

	// Hop budget: three prior hops is one too many (maxRedirects == 3).
	req, via = redirectReq(t, "https://ghcr.io/token",
		"https://ghcr.io/1", "https://ghcr.io/2", "https://ghcr.io/3")
	if err := checkAuthRedirect(req, via); err == nil || !strings.Contains(err.Error(), "stopped after 3 redirects") {
		t.Fatalf("redirect budget not enforced: %v", err)
	}
}

// TestLimitedHTTPClientConfiguration asserts the hardened client's
// observable configuration: bounded timeout and a redirect policy installed.
func TestLimitedHTTPClientConfiguration(t *testing.T) {
	c := limitedHTTPClient()
	if c.Timeout != httpTimeout {
		t.Fatalf("limited client timeout = %v, want %v", c.Timeout, httpTimeout)
	}
	if c.CheckRedirect == nil {
		t.Fatal("limited client has no CheckRedirect policy")
	}
}
