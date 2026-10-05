package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
)

const embeddedTestPassword = "test-only-owner-password-32-characters-long"
const embeddedTestVerifier = "0123456789012345678901234567890123456789012345678901234567890123"

func embeddedTestSetup(t *testing.T) (*EmbeddedOAuth, EmbeddedOAuthConfig) {
	t.Helper()
	dir := t.TempDir()
	c := EmbeddedOAuthConfig{
		PublicURL: "https://bridge.example", ClientID: "loop-chatgpt-client",
		RedirectURI:       "https://chatgpt.com/connector/oauth/test-callback",
		OwnerPasswordFile: filepath.Join(dir, "owner-password"), StateFile: filepath.Join(dir, "oauth-state.json"),
	}
	if err := os.WriteFile(c.OwnerPasswordFile, []byte(embeddedTestPassword+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o, err := NewEmbeddedOAuth(c)
	if err != nil {
		t.Fatal(err)
	}
	return o, c
}

func embeddedTestQuery(c EmbeddedOAuthConfig) url.Values {
	challenge := sha256.Sum256([]byte(embeddedTestVerifier))
	return url.Values{
		"client_id": {c.ClientID}, "redirect_uri": {c.RedirectURI}, "resource": {c.PublicURL},
		"response_type": {"code"}, "scope": {embeddedScope}, "state": {"test-client-state-0123456789"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"},
	}
}

func embeddedTestStart(t *testing.T, o *EmbeddedOAuth, c EmbeddedOAuthConfig) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	o.ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.PublicURL+"/oauth/authorize?"+embeddedTestQuery(c).Encode(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("authorization page failed: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("consent must preserve the same-origin native form Origin")
	}
	match := regexp.MustCompile(`name="flow" value="([A-Za-z0-9_-]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("consent form omitted flow")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("consent cookie missing security attributes")
	}
	return match[1], cookies[0]
}

func embeddedTestPost(o *EmbeddedOAuth, c EmbeddedOAuthConfig, path string, form url.Values, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, c.PublicURL+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	o.ServeHTTP(w, r)
	return w
}

func embeddedTestCode(t *testing.T, o *EmbeddedOAuth, c EmbeddedOAuthConfig) string {
	t.Helper()
	flow, cookie := embeddedTestStart(t, o, c)
	w := embeddedTestPost(o, c, "/oauth/authorize", url.Values{
		"flow": {flow}, "password": {embeddedTestPassword}, "decision": {"allow"},
	}, cookie, c.PublicURL)
	if w.Code != http.StatusSeeOther && w.Code != http.StatusFound {
		t.Fatalf("consent failed: %d %s", w.Code, w.Body.String())
	}
	redirect, err := url.Parse(w.Header().Get("Location"))
	if err != nil || redirect.Query().Get("code") == "" || redirect.Query().Get("state") != "test-client-state-0123456789" || redirect.Query().Get("iss") != c.PublicURL {
		t.Fatal("authorization redirect missing code/state/issuer")
	}
	if strings.Contains(w.Header().Get("Location"), embeddedTestPassword) {
		t.Fatal("password leaked into redirect")
	}
	return redirect.Query().Get("code")
}

func embeddedTestExchange(o *EmbeddedOAuth, c EmbeddedOAuthConfig, code, verifier string) *httptest.ResponseRecorder {
	return embeddedTestPost(o, c, "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {c.ClientID}, "resource": {c.PublicURL},
		"redirect_uri": {c.RedirectURI}, "code": {code}, "code_verifier": {verifier},
	}, nil, "")
}

func embeddedTestTokens(t *testing.T, w *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.AccessToken == "" || body.RefreshToken == "" || body.ExpiresIn > 900 {
		t.Fatalf("token exchange failed: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("tokens may be cached")
	}
	return body.AccessToken, body.RefreshToken
}

func embeddedTestAuthenticate(o *EmbeddedOAuth, c EmbeddedOAuthConfig, token string) (string, error) {
	r := httptest.NewRequest(http.MethodPost, c.PublicURL+"/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return o.Authenticate(r)
}

func TestEmbeddedOAuthConsentExchangeAndRestart(t *testing.T) {
	o, c := embeddedTestSetup(t)
	w := httptest.NewRecorder()
	o.ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.PublicURL+"/.well-known/oauth-authorization-server", nil))
	var metadata map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &metadata) != nil || metadata["issuer"] != c.PublicURL || metadata["authorization_response_iss_parameter_supported"] != true {
		t.Fatal("invalid OAuth discovery metadata")
	}
	code := embeddedTestCode(t, o, c)
	access, refresh := embeddedTestTokens(t, embeddedTestExchange(o, c, code, embeddedTestVerifier))
	owner, err := embeddedTestAuthenticate(o, c, access)
	if err != nil || !o.AuthorizedOwner(owner) {
		t.Fatalf("valid access token rejected: %v", err)
	}
	if _, err := embeddedTestAuthenticate(o, c, refresh); err == nil {
		t.Fatal("refresh token accepted as an access token")
	}
	duplicate := httptest.NewRequest(http.MethodPost, c.PublicURL+"/mcp", nil)
	duplicate.Header.Add("Authorization", "Bearer "+access)
	duplicate.Header.Add("Authorization", "Bearer "+access)
	if _, err := o.Authenticate(duplicate); err == nil {
		t.Fatal("duplicate authorization headers accepted")
	}
	if _, err := o.Authenticate(nil); err == nil {
		t.Fatal("nil request accepted")
	}
	restarted, err := NewEmbeddedOAuth(c)
	if err != nil {
		t.Fatal(err)
	}
	if restoredOwner, err := embeddedTestAuthenticate(restarted, c, access); err != nil || restoredOwner != owner || !restarted.AuthorizedOwner(owner) {
		t.Fatal("durable grant lost after restart")
	}
	raw, err := os.ReadFile(c.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{embeddedTestPassword, access, refresh, code, embeddedTestVerifier} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("persistent OAuth state contains a raw password, code, verifier, or bearer token")
		}
	}
	if replay := embeddedTestExchange(restarted, c, code, embeddedTestVerifier); replay.Code == http.StatusOK {
		t.Fatal("authorization code reused")
	}
	if restarted.AuthorizedOwner(owner) {
		t.Fatal("code reuse did not revoke affected subscription owner")
	}
}

func TestEmbeddedOAuthRefreshAndRevocation(t *testing.T) {
	o, c := embeddedTestSetup(t)
	access, refresh := embeddedTestTokens(t, embeddedTestExchange(o, c, embeddedTestCode(t, o, c), embeddedTestVerifier))
	owner, err := embeddedTestAuthenticate(o, c, access)
	if err != nil {
		t.Fatal(err)
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "resource": {c.PublicURL}, "refresh_token": {refresh}}
	newAccess, newRefresh := embeddedTestTokens(t, embeddedTestPost(o, c, "/oauth/token", refreshForm, nil, ""))
	if newAccess == access || newRefresh == refresh {
		t.Fatal("tokens did not rotate")
	}
	if newOwner, err := embeddedTestAuthenticate(o, c, newAccess); err != nil || newOwner != owner {
		t.Fatal("rotated token lost grant identity")
	}
	if replay := embeddedTestPost(o, c, "/oauth/token", refreshForm, nil, ""); replay.Code == http.StatusOK {
		t.Fatal("refresh token replay accepted")
	}
	if _, err := embeddedTestAuthenticate(o, c, newAccess); err == nil || o.AuthorizedOwner(owner) {
		t.Fatal("refresh replay did not revoke the token family")
	}
	access2, refresh2 := embeddedTestTokens(t, embeddedTestExchange(o, c, embeddedTestCode(t, o, c), embeddedTestVerifier))
	owner2, _ := embeddedTestAuthenticate(o, c, access2)
	revoke := embeddedTestPost(o, c, "/oauth/revoke", url.Values{"client_id": {c.ClientID}, "token": {refresh2}, "token_type_hint": {"refresh_token"}}, nil, "")
	if revoke.Code != http.StatusOK || o.AuthorizedOwner(owner2) {
		t.Fatalf("revocation failed: %d %s", revoke.Code, revoke.Body.String())
	}
}

func TestEmbeddedOAuthRejectsUnsafeRequests(t *testing.T) {
	o, c := embeddedTestSetup(t)
	for name, change := range map[string]func(url.Values){
		"wrong redirect":     func(q url.Values) { q.Set("redirect_uri", "https://other.example/callback") },
		"wrong resource":     func(q url.Values) { q.Set("resource", "https://other.example") },
		"wrong client":       func(q url.Values) { q.Set("client_id", "other") },
		"missing scope":      func(q url.Values) { q.Del("scope") },
		"plain PKCE":         func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"missing challenge":  func(q url.Values) { q.Del("code_challenge") },
		"duplicate redirect": func(q url.Values) { q.Add("redirect_uri", c.RedirectURI) },
		"implicit flow":      func(q url.Values) { q.Set("response_type", "token") },
		"request URI":        func(q url.Values) { q.Set("request_uri", "https://other.example/request") },
	} {
		t.Run(name, func(t *testing.T) {
			q := embeddedTestQuery(c)
			change(q)
			w := httptest.NewRecorder()
			o.ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.PublicURL+"/oauth/authorize?"+q.Encode(), nil))
			if w.Code != http.StatusBadRequest || len(w.Result().Cookies()) != 0 || w.Header().Get("Location") != "" {
				t.Fatal("unsafe authorization request reached consent or redirect")
			}
		})
	}
	for _, kind := range []string{"wrong origin", "null origin", "missing origin", "missing cookie", "wrong cookie", "wrong flow", "wrong password", "expired flow"} {
		t.Run(kind, func(t *testing.T) {
			flow, cookie := embeddedTestStart(t, o, c)
			form := url.Values{"flow": {flow}, "password": {embeddedTestPassword}, "decision": {"allow"}}
			origin := c.PublicURL
			switch kind {
			case "wrong origin":
				origin = "https://other.example"
			case "null origin":
				origin = "null"
			case "missing origin":
				origin = ""
			case "wrong cookie":
				cookie.Value = "wrong"
			case "missing cookie":
				cookie = nil
			case "wrong flow":
				form.Set("flow", "wrong")
			case "wrong password":
				form.Set("password", "incorrect")
			case "expired flow":
				pending := o.pending[flow]
				pending.expires = time.Now().Add(-time.Minute)
				o.pending[flow] = pending
			}
			w := embeddedTestPost(o, c, "/oauth/authorize", form, cookie, origin)
			if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
				t.Fatal("invalid consent accepted")
			}
		})
	}
	code := embeddedTestCode(t, o, c)
	if w := embeddedTestExchange(o, c, code, "a-wrong-verifier-that-is-long-enough-for-pkce-0123456789"); w.Code == http.StatusOK {
		t.Fatal("wrong PKCE verifier accepted")
	}
	if _, err := embeddedTestAuthenticate(o, c, "invalid"); err == nil {
		t.Fatal("invalid bearer accepted")
	}
	r := httptest.NewRequest(http.MethodPost, c.PublicURL+"/mcp?access_token=invalid", nil)
	if _, err := o.Authenticate(r); err == nil {
		t.Fatal("query-string bearer accepted")
	}
	oversize := embeddedTestPost(o, c, "/oauth/token", url.Values{"code": {strings.Repeat("a", embeddedMaxFormSize+1)}}, nil, "")
	if oversize.Code == http.StatusOK {
		t.Fatal("oversized request accepted")
	}
}

func TestEmbeddedOAuthPasswordRotation(t *testing.T) {
	o, c := embeddedTestSetup(t)
	access, _ := embeddedTestTokens(t, embeddedTestExchange(o, c, embeddedTestCode(t, o, c), embeddedTestVerifier))
	owner, _ := embeddedTestAuthenticate(o, c, access)
	if err := os.WriteFile(c.OwnerPasswordFile, []byte("replacement-test-password-that-is-32-bytes-long"), 0600); err != nil {
		t.Fatal(err)
	}
	rotated, err := NewEmbeddedOAuth(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := embeddedTestAuthenticate(rotated, c, access); err == nil || rotated.AuthorizedOwner(owner) {
		t.Fatal("password rotation did not invalidate prior access")
	}
}

func TestEmbeddedOAuthRateLimitAndMethod(t *testing.T) {
	o, c := embeddedTestSetup(t)
	o.logins = embeddedRate{start: time.Now(), count: 10}
	flow, cookie := embeddedTestStart(t, o, c)
	w := embeddedTestPost(o, c, "/oauth/authorize", url.Values{"flow": {flow}, "password": {embeddedTestPassword}, "decision": {"allow"}}, cookie, c.PublicURL)
	if w.Code != http.StatusTooManyRequests {
		t.Fatal("login rate limit ignored")
	}
	w = httptest.NewRecorder()
	o.ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.PublicURL+"/oauth/token", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("token GET accepted")
	}
	w = httptest.NewRecorder()
	o.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://wrong-host.example/.well-known/oauth-authorization-server", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatal("unconfigured host accepted")
	}
}

func TestEmbeddedOAuthGrantDeadline(t *testing.T) {
	o, c := embeddedTestSetup(t)
	access, refresh := embeddedTestTokens(t, embeddedTestExchange(o, c, embeddedTestCode(t, o, c), embeddedTestVerifier))
	_, ar, err := o.provider.IntrospectToken(t.Context(), access, fosite.AccessToken, &fosite.DefaultSession{}, embeddedScope)
	if err != nil {
		t.Fatal(err)
	}
	session := ar.GetSession().(*fosite.DefaultSession)
	deadline, err := time.Parse(time.RFC3339, session.Extra["grant_expires_at"].(string))
	if err != nil || deadline.After(time.Now().Add(embeddedRefreshTTL)) {
		t.Fatal("unbounded refresh grant")
	}
	newAccess, _ := embeddedTestTokens(t, embeddedTestPost(o, c, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "resource": {c.PublicURL}, "refresh_token": {refresh}}, nil, ""))
	_, rotated, err := o.provider.IntrospectToken(t.Context(), newAccess, fosite.AccessToken, &fosite.DefaultSession{}, embeddedScope)
	if err != nil {
		t.Fatal(err)
	}
	rotatedSession := rotated.GetSession().(*fosite.DefaultSession)
	if rotatedSession.Extra["grant_expires_at"] != session.Extra["grant_expires_at"] || rotatedSession.GetExpiresAt(fosite.RefreshToken).After(deadline) {
		t.Fatal("refresh rotation extended the absolute grant deadline")
	}
}

func TestEmbeddedOAuthDenialIssuerAndOneUse(t *testing.T) {
	o, c := embeddedTestSetup(t)
	flow, cookie := embeddedTestStart(t, o, c)
	form := url.Values{"flow": {flow}, "decision": {"deny"}}
	w := embeddedTestPost(o, c, "/oauth/authorize", form, cookie, c.PublicURL)
	u, err := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusSeeOther || err != nil || u.Query().Get("error") != "access_denied" || u.Query().Get("iss") != c.PublicURL {
		t.Fatal("denial did not preserve error/state/issuer semantics")
	}
	form.Set("decision", "allow")
	form.Set("password", embeddedTestPassword)
	if replay := embeddedTestPost(o, c, "/oauth/authorize", form, cookie, c.PublicURL); replay.Code != http.StatusForbidden {
		t.Fatal("consent state replay accepted")
	}
}

func TestEmbeddedOAuthExpiredSessions(t *testing.T) {
	o, c := embeddedTestSetup(t)
	access, refresh := embeddedTestTokens(t, embeddedTestExchange(o, c, embeddedTestCode(t, o, c), embeddedTestVerifier))
	o.store.mu.Lock()
	o.store.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	o.store.mu.Unlock()
	if _, err := embeddedTestAuthenticate(o, c, access); err == nil {
		t.Fatal("expired access session accepted")
	}
	o.store.mu.Lock()
	o.store.now = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
	o.store.mu.Unlock()
	w := embeddedTestPost(o, c, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "resource": {c.PublicURL}, "refresh_token": {refresh}}, nil, "")
	if w.Code == http.StatusOK {
		t.Fatal("expired refresh session accepted")
	}
}

func TestEmbeddedCallbackCSPOrigin(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://chatgpt.com/callback", "https://chatgpt.com"},
		{"https://CLIENT.Example:8443/callback;param?next=https://other.example/a;form-action=*", "https://client.example:8443"},
		{"https://127.0.0.1:12345/callback", "https://127.0.0.1:12345"},
		{"https://xn--bcher-kva.example/callback", "https://xn--bcher-kva.example"},
	} {
		got, err := embeddedCallbackOrigin(tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("callback %q: got %q, %v; want %q", tc.raw, got, err, tc.want)
		}
	}
	for _, raw := range []string{
		"https://client.example;form-action/callback", "https://client.example,evil.example/callback",
		"https://*.example/callback", "https://client.example'unsafe-inline'/callback",
		"https://[::1]/callback", "https://bücher.example/callback", "https://client.example:*/callback",
		"http://client.example/callback", "https://user@client.example/callback",
	} {
		if got, err := embeddedCallbackOrigin(raw); err == nil {
			t.Errorf("unsafe CSP callback %q accepted as %q", raw, got)
		}
	}
	o, c := embeddedTestSetup(t)
	w := httptest.NewRecorder()
	o.ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.PublicURL+"/oauth/authorize?"+embeddedTestQuery(c).Encode(), nil))
	want := "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://chatgpt.com; frame-ancestors 'none'; base-uri 'none'"
	if w.Header().Get("Content-Security-Policy") != want {
		t.Fatal("consent callback CSP is not restricted to registered origin")
	}
	// Non-HTML endpoints keep the original no-referrer policy.
	w = httptest.NewRecorder()
	o.ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.PublicURL+"/.well-known/oauth-authorization-server", nil))
	if w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("non-consent referrer policy changed")
	}
}
