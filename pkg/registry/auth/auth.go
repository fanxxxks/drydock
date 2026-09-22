package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/drydock-updater/drydock/pkg/registry/helpers"
	"github.com/drydock-updater/drydock/pkg/types"
	ref "github.com/distribution/reference"
	"github.com/sirupsen/logrus"
)

// ChallengeHeader is the HTTP Header containing challenge instructions
const ChallengeHeader = "WWW-Authenticate"

// Outbound-request guardrails (Drydock hardening over upstream watchtower).
// The registry auth flow is one of the two places Drydock performs outbound
// HTTP (the other being the digest HEAD request), and a compromised or
// hijacked registry controls parts of it: it answers the challenge request
// and dictates the bearer-token realm URL. These limits keep such a registry
// from hanging the update loop forever, exhausting memory via a huge token
// response, or exfiltrating the Basic credentials to an arbitrary host.
const (
	// httpTimeout bounds each auth request end to end.
	httpTimeout = 30 * time.Second

	// maxAuthResponseBytes caps how many bytes of a token response are read
	// before the request is aborted (token payloads are a few KiB; 1 MiB is
	// a generous ceiling).
	maxAuthResponseBytes = 1 << 20

	// maxRedirects is the redirect hop budget for auth requests.
	maxRedirects = 3
)

// limitedHTTPClient returns the hardened client shared by every auth
// request. Redirects are followed only when they stay on https and on the
// exact host of the original request, so neither a registry redirect nor a
// realm URL can pivot a credentialed request to another origin (the Go
// stdlib would forward the Authorization header to same-host targets, and
// relying on that subtlety is more fragile than refusing cross-host hops).
func limitedHTTPClient() *http.Client {
	return &http.Client{
		Timeout:         httpTimeout,
		CheckRedirect:   checkAuthRedirect,
	}
}

// checkAuthRedirect is the redirect policy for every registry-auth request:
// at most maxRedirects hops, never away from https, never to a different
// host. The Authorization header carries the registry credentials, so a hop
// to another origin is a credential-exfiltration primitive.
func checkAuthRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("registry auth: stopped after %d redirects", maxRedirects)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("registry auth: refused redirect to non-https URL %q", req.URL.Redacted())
	}
	if len(via) > 0 && req.URL.Host != via[0].URL.Host {
		return fmt.Errorf("registry auth: refused cross-host redirect from %q to %q (credential exfiltration guard)",
			via[0].URL.Host, req.URL.Host)
	}
	return nil
}

// GetToken fetches a token for the registry hosting the provided image
func GetToken(container types.Container, registryAuth string) (string, error) {
	normalizedRef, err := ref.ParseNormalizedNamed(container.ImageName())
	if err != nil {
		return "", err
	}

	URL := GetChallengeURL(normalizedRef)
	logrus.WithField("URL", URL.String()).Debug("Built challenge URL")

	var req *http.Request
	if req, err = GetChallengeRequest(URL); err != nil {
		return "", err
	}

	client := limitedHTTPClient()
	var res *http.Response
	if res, err = client.Do(req); err != nil {
		return "", err
	}
	defer res.Body.Close()
	v := res.Header.Get(ChallengeHeader)

	logrus.WithFields(logrus.Fields{
		"status": res.Status,
		"header": v,
	}).Debug("Got response to challenge request")

	challenge := strings.ToLower(v)
	if strings.HasPrefix(challenge, "basic") {
		if registryAuth == "" {
			return "", fmt.Errorf("no credentials available")
		}

		return fmt.Sprintf("Basic %s", registryAuth), nil
	}
	if strings.HasPrefix(challenge, "bearer") {
		return GetBearerHeader(challenge, normalizedRef, registryAuth)
	}

	return "", errors.New("unsupported challenge type from registry")
}

// GetChallengeRequest creates a request for getting challenge instructions
func GetChallengeRequest(URL url.URL) (*http.Request, error) {
	req, err := http.NewRequest("GET", URL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "Watchtower (Docker)")
	return req, nil
}

// GetBearerHeader tries to fetch a bearer token from the registry based on the challenge instructions
func GetBearerHeader(challenge string, imageRef ref.Named, registryAuth string) (string, error) {
	client := limitedHTTPClient()
	authURL, err := GetAuthURL(challenge, imageRef)

	if err != nil {
		return "", err
	}

	var r *http.Request
	if r, err = http.NewRequest("GET", authURL.String(), nil); err != nil {
		return "", err
	}

	if registryAuth != "" {
		logrus.Debug("Credentials found.")
		// CREDENTIAL: Uncomment to log registry credentials
		// logrus.Tracef("Credentials: %v", registryAuth)
		r.Header.Add("Authorization", fmt.Sprintf("Basic %s", registryAuth))
	} else {
		logrus.Debug("No credentials found.")
	}

	var authResponse *http.Response
	if authResponse, err = client.Do(r); err != nil {
		return "", err
	}
	defer authResponse.Body.Close()

	if authResponse.StatusCode < 200 || authResponse.StatusCode > 299 {
		return "", fmt.Errorf("registry auth request to %q failed with status %q",
			authURL.Redacted(), authResponse.Status)
	}

	// Cap the response body before reading: a hostile token endpoint must not
	// be able to OOM the process (which holds the docker socket).
	body, err := io.ReadAll(io.LimitReader(authResponse.Body, maxAuthResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading registry auth response: %w", err)
	}
	if len(body) > maxAuthResponseBytes {
		return "", fmt.Errorf("registry auth response exceeds the %d byte limit", maxAuthResponseBytes)
	}

	tokenResponse := &types.TokenResponse{}
	if err := json.Unmarshal(body, tokenResponse); err != nil {
		return "", err
	}

	return fmt.Sprintf("Bearer %s", tokenResponse.Token), nil
}

// GetAuthURL from the instructions in the challenge
func GetAuthURL(challenge string, imageRef ref.Named) (*url.URL, error) {
	loweredChallenge := strings.ToLower(challenge)
	raw := strings.TrimPrefix(loweredChallenge, "bearer")

	pairs := strings.Split(raw, ",")
	values := make(map[string]string, len(pairs))

	for _, pair := range pairs {
		trimmed := strings.Trim(pair, " ")
		if key, val, ok := strings.Cut(trimmed, "="); ok {
			values[key] = strings.Trim(val, `"`)
		}
	}
	logrus.WithFields(logrus.Fields{
		"realm":   values["realm"],
		"service": values["service"],
	}).Debug("Checking challenge header content")
	if values["realm"] == "" || values["service"] == "" {

		return nil, fmt.Errorf("challenge header did not include all values needed to construct an auth url")
	}

	authURL, err := url.Parse(values["realm"])
	if err != nil {
		return nil, fmt.Errorf("challenge realm %q is not a valid URL: %w", values["realm"], err)
	}
	// The realm is attacker-influenceable input (a compromised registry
	// authors the WWW-Authenticate header). The challenge exchange itself ran
	// over https, so a plaintext realm would be both a downgrade and an
	// exfiltration channel for the Basic credentials sent to it; an empty
	// host is never routable legitimately.
	if authURL.Scheme != "https" {
		return nil, fmt.Errorf("challenge realm %q must use https, got scheme %q", values["realm"], authURL.Scheme)
	}
	if authURL.Host == "" {
		return nil, fmt.Errorf("challenge realm %q carries no host", values["realm"])
	}
	if bad, why := forbiddenRealmHost(authURL.Hostname(), imageRef); bad {
		return nil, fmt.Errorf("challenge realm %q points at a %s address; refusing to send credentials there",
			values["realm"], why)
	}

	q := authURL.Query()
	q.Add("service", values["service"])

	scopeImage := ref.Path(imageRef)

	scope := fmt.Sprintf("repository:%s:pull", scopeImage)
	logrus.WithFields(logrus.Fields{"scope": scope, "image": imageRef.Name()}).Debug("Setting scope for auth token")
	q.Add("scope", scope)

	authURL.RawQuery = q.Encode()
	return authURL, nil
}

// forbiddenRealmHost reports whether the bearer realm's host must not
// receive the credentialed token request, and why. The realm is chosen by
// the registry through the WWW-Authenticate header, so it is attacker
// influenceable whenever the registry is hostile or a TLS hop is
// mis-terminated; pointing the client at loopback/link-local/private/
// reserved addresses is the classic SSRF pivot (cloud metadata endpoints,
// internal admin panels). The one exemption is the host the operator
// themselves aimed Drydock at: a self-hosted registry on a private address
// may legitimately run its token service on that same address.
//
// DNS names are not resolved here: a public-looking name that resolves to a
// private address (DNS rebinding) is out of scope for v0.1 and tracked in
// FOLLOWUPS.md. The challenge URL itself is exempt from this check because
// its host always comes from the operator's own image reference, never from
// registry-controlled data.
func forbiddenRealmHost(realmHost string, imageRef ref.Named) (bool, string) {
	host := strings.ToLower(strings.TrimSpace(realmHost))
	if host == "" {
		return true, "empty"
	}
	if rh, err := helpers.GetRegistryAddress(imageRef.Name()); err == nil {
		if host == strings.ToLower(hostOnly(rh)) {
			return false, "" // the operator-directed registry host itself
		}
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true, "localhost"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false, "" // plain DNS name; nothing to classify without resolution
	}
	switch {
	case addr.IsLoopback():
		return true, "loopback"
	case addr.IsPrivate():
		return true, "private"
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		return true, "link-local"
	case addr.IsUnspecified():
		return true, "unspecified"
	case addr.IsMulticast():
		return true, "multicast"
	}
	return false, ""
}

// hostOnly strips an eventual port from a host[:port] string, tolerating a
// bare host (net.SplitHostPort errors on those).
func hostOnly(hostWithPort string) string {
	if h, _, err := net.SplitHostPort(hostWithPort); err == nil {
		return h
	}
	return hostWithPort
}

// GetChallengeURL returns the URL to check auth requirements
// for access to a given image
func GetChallengeURL(imageRef ref.Named) url.URL {
	host, _ := helpers.GetRegistryAddress(imageRef.Name())

	URL := url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/v2/",
	}
	return URL
}
