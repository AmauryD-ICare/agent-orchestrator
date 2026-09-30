package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aoagents/agent-orchestrator/backend/internal/ports"
)

// TestAttackerHostRejectedBeforeCredentialAttachment verifies that
// gitlab.attacker.example (not in the allowlist) is rejected before any HTTP
// request is made to it — no credential attached. The provider must refuse to
// build a client for a host that is neither gitlab.com nor in the configured
// allowlist (review Item 5).
func TestAttackerHostRejectedBeforeCredentialAttachment(t *testing.T) {
	var attackerHits int32
	attackerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attackerHits, 1)
		// Return a plausible MR response so a client that did get built would
		// succeed — the test's assertion is that this handler is never reached.
		fmt.Fprint(w, `{"iid":1,"title":"x","state":"opened"}`)
	}))
	t.Cleanup(attackerSrv.Close)

	// Allowed host is a test server we control; attacker host points at a
	// separate test server that should never be contacted.
	allowedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[]`)
	}))
	t.Cleanup(allowedSrv.Close)

	allowedHost := hostFromURL(t, allowedSrv.URL)

	p, err := NewProvider(ProviderOptions{
		Token:              StaticTokenSource("secret-gitlab-token"),
		SkipTokenPreflight: true,
		AllowedHosts:       []string{allowedHost},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Override the default client's transport so even the empty-host fallback
	// routes to the allowed server (keeps the test deterministic).
	p.client = NewClient(ClientOptions{
		Token:    StaticTokenSource("secret-gitlab-token"),
		RESTBase: allowedSrv.URL + "/api/v4",
	})
	p.hostClientCfg.HTTPClient = &http.Client{Transport: &rewriteTransport{target: allowedSrv.URL}}

	// ParseRepository for the attacker host must return false — the host is
	// not in the allowlist and is not gitlab.com.
	repo, ok := p.ParseRepository("https://gitlab.attacker.example/group/repo.git")
	if ok {
		t.Fatalf("ParseRepository accepted gitlab.attacker.example (repo=%+v); want rejection — host is not in the allowlist", repo)
	}

	// FetchPullRequests against the attacker host must also fail before any
	// request reaches the attacker server.
	attackerRepo := ports.SCMRepo{Provider: "gitlab", Host: "gitlab.attacker.example", Owner: "group", Name: "repo", Repo: "group/repo"}
	ref := ports.SCMPRRef{Repo: attackerRepo, Number: 1, URL: "https://gitlab.attacker.example/group/repo/-/merge_requests/1"}
	if _, err := p.FetchPullRequests(context.Background(), []ports.SCMPRRef{ref}); err == nil {
		t.Fatal("FetchPullRequests: error = nil, want error for attacker host")
	}

	if got := atomic.LoadInt32(&attackerHits); got != 0 {
		t.Errorf("attacker server received %d requests; want 0 — credential must not be attached to non-allowlisted hosts", got)
	}
}

// TestPerHostCredentialIsolation verifies that the gitlab.com token is not
// attached to a self-managed host that has its own token, and vice versa.
// The per-host TokenSource map selects the correct token per host (review
// Item 5).
func TestPerHostCredentialIsolation(t *testing.T) {
	type tokenRecord struct {
		host  string
		token string
	}
	mu := make(chan tokenRecord, 16)

	// gitlab.com test server — expects the gitlab.com token.
	comSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu <- tokenRecord{host: "gitlab.com", token: r.Header.Get("Authorization")}
		json.NewEncoder(w).Encode([]any{})
	}))
	t.Cleanup(comSrv.Close)

	// self-managed test server — expects its own token, NOT the gitlab.com one.
	selfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu <- tokenRecord{host: "self-managed", token: r.Header.Get("Authorization")}
		json.NewEncoder(w).Encode([]any{})
	}))
	t.Cleanup(selfSrv.Close)

	selfHost := hostFromURL(t, selfSrv.URL)

	p, err := NewProvider(ProviderOptions{
		Token:              StaticTokenSource("com-secret"), // default token → gitlab.com
		SkipTokenPreflight: true,
		AllowedHosts:       []string{selfHost},
		HostTokens: map[string]TokenSource{
			selfHost: StaticTokenSource("self-secret"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Wire the default client at the gitlab.com test server.
	p.client = NewClient(ClientOptions{
		Token:    StaticTokenSource("com-secret"),
		RESTBase: comSrv.URL + "/api/v4",
	})
	p.hostClientCfg.HTTPClient = &http.Client{Transport: &hostRoutingTransport{
		routes: map[string]string{selfHost: selfSrv.URL},
	}}

	// List PRs on the self-managed host — should use self-secret, NOT com-secret.
	selfRepo := ports.SCMRepo{Provider: "gitlab", Host: selfHost, Owner: "eng", Name: "widget", Repo: "eng/widget"}
	if _, err := p.ListPRsByRepo(context.Background(), selfRepo, time.Time{}); err != nil {
		t.Fatalf("ListPRsByRepo(self-managed): %v", err)
	}

	// List PRs on gitlab.com — should use com-secret.
	comRepo := ports.SCMRepo{Provider: "gitlab", Host: "gitlab.com", Owner: "myorg", Name: "myrepo", Repo: "myorg/myrepo"}
	if _, err := p.ListPRsByRepo(context.Background(), comRepo, time.Time{}); err != nil {
		t.Fatalf("ListPRsByRepo(gitlab.com): %v", err)
	}

	close(mu)
	var records []tokenRecord
	for r := range mu {
		records = append(records, r)
	}

	// Verify the self-managed request carried self-secret, not com-secret.
	var selfTok string
	var comTok string
	for _, r := range records {
		if r.host == "self-managed" {
			selfTok = r.token
		}
		if r.host == "gitlab.com" {
			comTok = r.token
		}
	}
	if selfTok != "Bearer self-secret" {
		t.Errorf("self-managed host Authorization = %q, want %q (gitlab.com token must NOT leak to self-managed host)", selfTok, "Bearer self-secret")
	}
	if comTok != "Bearer com-secret" {
		t.Errorf("gitlab.com host Authorization = %q, want %q (self-managed token must NOT leak to gitlab.com)", comTok, "Bearer com-secret")
	}
}

// TestSelfManagedCustomPortRESTBase verifies that a self-managed instance on a
// custom port (https://gitlab.internal:8443) derives the API base as
// https://gitlab.internal:8443/api/v4 (review Item 5 / S1).
func TestSelfManagedCustomPortRESTBase(t *testing.T) {
	var seenPath string
	var seenHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenHost = r.Host
		json.NewEncoder(w).Encode([]any{})
	}))
	t.Cleanup(srv.Close)

	// The host as seen by the provider includes :8443. The rewriteTransport
	// transparently routes the derived https://gitlab.internal:8443/api/v4
	// to the test server.
	const customPortHost = "gitlab.internal:8443"

	p, err := NewProvider(ProviderOptions{
		Token:              StaticTokenSource("tok"),
		SkipTokenPreflight: true,
		AllowedHosts:       []string{customPortHost},
		HostTokens: map[string]TokenSource{
			customPortHost: StaticTokenSource("tok"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.client = NewClient(ClientOptions{
		Token:    StaticTokenSource("tok"),
		RESTBase: srv.URL + "/api/v4",
	})
	p.hostClientCfg.HTTPClient = &http.Client{Transport: &rewriteTransport{target: srv.URL}}

	repo := ports.SCMRepo{Provider: "gitlab", Host: customPortHost, Owner: "eng", Name: "widget", Repo: "eng/widget"}
	if _, err := p.ListPRsByRepo(context.Background(), repo, time.Time{}); err != nil {
		t.Fatalf("ListPRsByRepo: %v", err)
	}

	// The request must carry the /api/v4 path prefix, proving the REST base was
	// derived as https://<host>:<port>/api/v4 (port preserved).
	if !strings.HasPrefix(seenPath, "/api/v4/") {
		t.Errorf("request path = %q, want /api/v4/... prefix (REST base must include port)", seenPath)
	}
	if seenHost == "gitlab.com" {
		t.Errorf("request host = gitlab.com, want the custom-port self-managed host (port must be preserved)")
	}
}

// TestSSHPortIsTransportOnly verifies the SSH port never becomes part of the
// web/API authority: ssh://git@gitlab.internal:2200/group/repo.git parses to
// Host "gitlab.internal" (the same repo as https://gitlab.internal/...), while
// an https:// port is the web port and is preserved.
func TestSSHPortIsTransportOnly(t *testing.T) {
	p, err := NewProvider(ProviderOptions{
		Token:              StaticTokenSource("tok"),
		SkipTokenPreflight: true,
		AllowedHosts:       []string{"gitlab.internal", "gitlab.web:8443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, remote, wantHost string
	}{
		{"ssh custom port dropped", "ssh://git@gitlab.internal:2200/group/repo.git", "gitlab.internal"},
		{"ssh no port", "ssh://git@gitlab.internal/group/repo.git", "gitlab.internal"},
		{"scp-like", "git@gitlab.internal:group/repo.git", "gitlab.internal"},
		{"https default port", "https://gitlab.internal/group/repo.git", "gitlab.internal"},
		{"https custom port kept", "https://gitlab.web:8443/group/repo.git", "gitlab.web:8443"},
		{"ssh port does not select https port", "ssh://git@gitlab.web:2200/group/repo.git", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, ok := p.ParseRepository(tc.remote)
			if tc.wantHost == "" {
				if ok {
					t.Fatalf("ParseRepository(%q) = %+v, want rejection (gitlab.web is only allowlisted as :8443)", tc.remote, repo)
				}
				return
			}
			if !ok {
				t.Fatalf("ParseRepository(%q) = false, want true", tc.remote)
			}
			if repo.Host != tc.wantHost || repo.Repo != "group/repo" {
				t.Errorf("ParseRepository(%q) = %+v, want host %q repo group/repo", tc.remote, repo, tc.wantHost)
			}
		})
	}
}

// TestHostBaseURLOverrideDrivesRESTBase verifies the optional per-host web base
// override (non-standard port and/or subpath) and that the default stays
// https://<host>/api/v4, independent of any SSH port.
func TestHostBaseURLOverrideDrivesRESTBase(t *testing.T) {
	for _, tc := range []struct {
		name, host, override, want string
	}{
		{"default", "gitlab.internal", "", "https://gitlab.internal/api/v4"},
		{"https port host", "gitlab.internal:8443", "", "https://gitlab.internal:8443/api/v4"},
		{"port override", "gitlab.internal", "https://gitlab.internal:8443", "https://gitlab.internal:8443/api/v4"},
		{"subpath override", "gitlab.internal", "https://corp.example/gitlab/", "https://corp.example/gitlab/api/v4"},
		{"http override", "gitlab.internal", "http://gitlab.internal:8080", "http://gitlab.internal:8080/api/v4"},
	} {
		if got := RESTBaseForHost(tc.host, tc.override); got != tc.want {
			t.Errorf("%s: RESTBaseForHost(%q, %q) = %q, want %q", tc.name, tc.host, tc.override, got, tc.want)
		}
	}

	p, err := NewProvider(ProviderOptions{
		Token:              StaticTokenSource("tok"),
		SkipTokenPreflight: true,
		AllowedHosts:       []string{"Gitlab.Internal", "plain.internal"},
		HostBaseURLs:       map[string]string{"gitlab.internal": "https://corp.example/gitlab"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.clientForHost("gitlab.internal").restBase; got != "https://corp.example/gitlab/api/v4" {
		t.Errorf("override client restBase = %q", got)
	}
	if got := p.clientForHost("plain.internal").restBase; got != "https://plain.internal/api/v4" {
		t.Errorf("non-overridden client restBase = %q", got)
	}
}

// TestGitLabComAlwaysAllowed verifies that gitlab.com is always accepted by
// ParseRepository even with an empty allowlist (review Item 5, 11c).
func TestGitLabComAlwaysAllowed(t *testing.T) {
	p, err := NewProvider(ProviderOptions{
		Token:              StaticTokenSource("tok"),
		SkipTokenPreflight: true,
		// No AllowedHosts — gitlab.com must still be accepted.
	})
	if err != nil {
		t.Fatal(err)
	}

	repo, ok := p.ParseRepository("git@gitlab.com:myorg/myrepo.git")
	if !ok {
		t.Fatal("ParseRepository(gitlab.com) = false, want true (gitlab.com always allowed)")
	}
	if repo.Host != "gitlab.com" {
		t.Errorf("Host = %q, want gitlab.com", repo.Host)
	}
}

// TestSelfManagedHostNotInAllowlistRejected verifies that a self-managed host
// (one that contains "gitlab" but is not gitlab.com) is rejected by
// ParseRepository when it is not in the allowlist (review Item 5).
func TestSelfManagedHostNotInAllowlistRejected(t *testing.T) {
	p, err := NewProvider(ProviderOptions{
		Token:              StaticTokenSource("tok"),
		SkipTokenPreflight: true,
		// Empty allowlist — only gitlab.com should be accepted.
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := p.ParseRepository("git@gitlab.mycompany.com:team/project.git"); ok {
		t.Error("ParseRepository(gitlab.mycompany.com) = true, want false (host not in allowlist)")
	}
}

// TestAllowlistedSelfManagedHostAccepted verifies that a self-managed host in
// the allowlist is accepted by ParseRepository (review Item 5).
func TestAllowlistedSelfManagedHostAccepted(t *testing.T) {
	p, err := NewProvider(ProviderOptions{
		Token:              StaticTokenSource("tok"),
		SkipTokenPreflight: true,
		AllowedHosts:       []string{"gitlab.mycompany.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	repo, ok := p.ParseRepository("git@gitlab.mycompany.com:team/project.git")
	if !ok {
		t.Fatal("ParseRepository(allowlisted self-managed) = false, want true")
	}
	if repo.Host != "gitlab.mycompany.com" {
		t.Errorf("Host = %q, want gitlab.mycompany.com", repo.Host)
	}
}

// hostFromURL extracts the host (with port if present) from a URL string.
func hostFromURL(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Host
}

// hostRoutingTransport routes requests to different host:port targets based on
// the request's Host header. This lets a single test verify per-host
// credential selection without standing up per-host DNS.
type hostRoutingTransport struct {
	routes map[string]string // host[:port] → target server base URL
}

func (t *hostRoutingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, ok := t.routes[req.URL.Host]
	if !ok {
		// Fall back to the default transport (will fail for unknown hosts,
		// which is the intended behavior for attacker-host tests).
		return http.DefaultTransport.RoundTrip(req)
	}
	req2 := req.Clone(req.Context())
	u, err := url.Parse(target + req2.URL.Path)
	if err != nil {
		return nil, err
	}
	u.RawQuery = req2.URL.RawQuery
	req2.URL = u
	return http.DefaultTransport.RoundTrip(req2)
}

// TestSSHPortOriginResolvesMRsOnWebAuthority is the end-to-end regression for
// remotes whose SSH and HTTPS ports differ (ssh://...:2200, web on 443): the MR
// listing must hit https://<host>/api/v4, never <host>:2200, and a configured
// base URL override must redirect it to the non-standard web port.
func TestSSHPortOriginResolvesMRsOnWebAuthority(t *testing.T) {
	const origin = "ssh://git@gitlab.icareweb.com:2200/group/repo.git"
	for _, tc := range []struct {
		name         string
		baseURLs     map[string]string
		wantAuthUsed string // req.URL.Host the provider dialed
	}{
		{"default web authority", nil, "gitlab.icareweb.com"},
		{"override web port", map[string]string{"gitlab.icareweb.com": "https://gitlab.icareweb.com:8443"}, "gitlab.icareweb.com:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seenPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenPath = r.URL.Path
				json.NewEncoder(w).Encode([]any{})
			}))
			t.Cleanup(srv.Close)

			p, err := NewProvider(ProviderOptions{
				Token:              StaticTokenSource("tok"),
				SkipTokenPreflight: true,
				AllowedHosts:       []string{"gitlab.icareweb.com"},
				HostBaseURLs:       tc.baseURLs,
			})
			if err != nil {
				t.Fatal(err)
			}
			// Only the expected authority is routable; any other (e.g. :2200)
			// falls through to the real network and fails the call.
			p.hostClientCfg.HTTPClient = &http.Client{Transport: &hostRoutingTransport{
				routes: map[string]string{tc.wantAuthUsed: srv.URL},
			}}

			repo, ok := p.ParseRepository(origin)
			if !ok {
				t.Fatalf("ParseRepository(%q) = false", origin)
			}
			if repo.Host != "gitlab.icareweb.com" || repo.Repo != "group/repo" {
				t.Fatalf("repo = %+v, want host gitlab.icareweb.com without the SSH port", repo)
			}
			if _, err := p.ListPRsByRepo(context.Background(), repo, time.Time{}); err != nil {
				t.Fatalf("ListPRsByRepo: %v", err)
			}
			if !strings.HasPrefix(seenPath, "/api/v4/projects/group/repo/merge_requests") {
				t.Errorf("request path = %q, want the group/repo merge_requests endpoint", seenPath)
			}
		})
	}
}
