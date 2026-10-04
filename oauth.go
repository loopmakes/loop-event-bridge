package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxAccessTokenBytes = 16 << 10
	embeddedScope       = "events:read"
	embeddedAccessTTL   = 15 * time.Minute
	embeddedRefreshTTL  = 30 * 24 * time.Hour
	embeddedConsentTTL  = 5 * time.Minute
	embeddedCookieName  = "__Host-loop-consent"
	embeddedMaxFormSize = 16 << 10
)

var errInvalidAccessToken = errors.New("invalid or missing access token")

func authHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && raw == strings.TrimSpace(raw) && u.Scheme == "https" &&
		u.Hostname() != "" && u.User == nil && u.Fragment == "" && !strings.Contains(raw, "#") && u.Opaque == ""
}

// EmbeddedOAuthConfig sets up one pre-registered public OAuth client. The
// operator supplies a strong owner password file and an exact client redirect.
// StateFile belongs on the private persistent data volume, outside any web root.
type EmbeddedOAuthConfig struct {
	PublicURL, ClientID, RedirectURI, OwnerPasswordFile, StateFile string
}

type embeddedConsent struct {
	query     url.Values
	cookieSum [32]byte
	expires   time.Time
}

type embeddedRate struct {
	start time.Time
	count int
}

func (r *embeddedRate) allow(now time.Time, limit int, window time.Duration) bool {
	if r.start.IsZero() || now.Sub(r.start) >= window {
		r.start, r.count = now, 0
	}
	if r.count >= limit {
		return false
	}
	r.count++
	return true
}

// EmbeddedOAuth uses Fosite for OAuth code/PKCE/token/refresh/revocation
// mechanics. Browser owner authentication and consent are intentionally local.
// This implementation is single-process; do not share StateFile across replicas.
type EmbeddedOAuth struct {
	mu           sync.Mutex // serializes multi-step Fosite storage operations
	config       EmbeddedOAuthConfig
	host         string
	owner        string
	passwordHash []byte
	provider     fosite.OAuth2Provider
	store        *oauthStore
	pending      map[string]embeddedConsent
	pages        embeddedRate
	logins       embeddedRate
	tokens       embeddedRate
}

func NewEmbeddedOAuth(c EmbeddedOAuthConfig) (*EmbeddedOAuth, error) {
	u, err := url.Parse(c.PublicURL)
	if err != nil || !authHTTPSURL(c.PublicURL) || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("PUBLIC_URL must be an HTTPS origin without a path or query")
	}
	if !authHTTPSURL(c.RedirectURI) {
		return nil, errors.New("OAuth redirect URI must be the exact HTTPS callback from client setup")
	}
	if c.ClientID == "" || len(c.ClientID) > 512 || strings.TrimSpace(c.ClientID) != c.ClientID || strings.ContainsAny(c.ClientID, "\r\n\t") {
		return nil, errors.New("an explicit OAuth public client ID is required")
	}
	if c.StateFile == "" || c.OwnerPasswordFile == "" {
		return nil, errors.New("OAuth state and owner password files are required")
	}
	f, err := os.Open(c.OwnerPasswordFile)
	if err != nil {
		return nil, errors.New("owner password file cannot be read")
	}
	password, readErr := io.ReadAll(io.LimitReader(f, 129))
	_ = f.Close()
	if readErr != nil || len(password) > 128 {
		return nil, errors.New("owner password file is invalid")
	}
	password = []byte(strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r"))
	if len(password) < 32 || len(password) > 72 {
		return nil, errors.New("owner password must contain 32–72 bytes; use a strong randomly generated value")
	}
	for _, b := range password {
		if b < 0x20 || b > 0x7e {
			return nil, errors.New("owner password must contain printable ASCII characters")
		}
	}
	// A configuration/password change deliberately invalidates every grant.
	bindingHash := sha256.New()
	_, _ = bindingHash.Write([]byte(c.PublicURL + "\x00" + c.ClientID + "\x00" + c.RedirectURI + "\x00"))
	_, _ = bindingHash.Write(password)
	binding := hex.EncodeToString(bindingHash.Sum(nil))
	passwordHash, err := bcrypt.GenerateFromPassword(password, 12)
	clear(password)
	if err != nil {
		return nil, errors.New("owner password cannot be initialized")
	}
	client := &fosite.DefaultClient{
		ID: c.ClientID, Public: true, RedirectURIs: []string{c.RedirectURI},
		GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"},
		Scopes: []string{embeddedScope}, Audience: []string{c.PublicURL},
	}
	store, err := NewOAuthStore(c.StateFile, client, binding)
	if err != nil {
		return nil, err
	}
	fc := &fosite.Config{
		AccessTokenLifespan: embeddedAccessTTL, RefreshTokenLifespan: embeddedRefreshTTL,
		AuthorizeCodeLifespan: time.Minute, GlobalSecret: store.Secret(),
		EnforcePKCE: true, EnforcePKCEForPublicClients: true, EnablePKCEPlainChallengeMethod: false,
		ScopeStrategy: fosite.ExactScopeStrategy, RefreshTokenScopes: []string{embeddedScope},
		TokenURL: c.PublicURL + "/oauth/token", AccessTokenIssuer: c.PublicURL,
		SendDebugMessagesToClients: false,
	}
	provider := compose.Compose(fc, store, compose.NewOAuth2HMACStrategy(fc),
		compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory, compose.OAuth2TokenRevocationFactory)
	return &EmbeddedOAuth{
		config: c, host: u.Host, owner: "owner-" + binding, passwordHash: passwordHash,
		provider: provider, store: store, pending: make(map[string]embeddedConsent),
	}, nil
}

func (o *EmbeddedOAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if !strings.EqualFold(r.Host, o.host) || len(r.URL.RawQuery) > embeddedMaxFormSize {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		if r.Method != http.MethodGet {
			embeddedMethodError(w, "GET")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": o.config.PublicURL, "authorization_endpoint": o.config.PublicURL + "/oauth/authorize",
			"token_endpoint": o.config.PublicURL + "/oauth/token", "revocation_endpoint": o.config.PublicURL + "/oauth/revoke",
			"response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"},
			"grant_types_supported": []string{"authorization_code", "refresh_token"}, "scopes_supported": []string{embeddedScope},
			"token_endpoint_auth_methods_supported": []string{"none"}, "revocation_endpoint_auth_methods_supported": []string{"none"},
			"code_challenge_methods_supported": []string{"S256"}, "authorization_response_iss_parameter_supported": true,
		})
	case "/oauth/authorize":
		switch r.Method {
		case http.MethodGet:
			o.startConsent(w, r)
		case http.MethodPost:
			o.finishConsent(w, r)
		default:
			embeddedMethodError(w, "GET, POST")
		}
	case "/oauth/token", "/oauth/revoke":
		if r.Method != http.MethodPost {
			embeddedMethodError(w, "POST")
			return
		}
		if !o.tokens.allow(time.Now(), 120, time.Minute) {
			embeddedRateError(w)
			return
		}
		o.tokenEndpoint(w, r)
	default:
		http.NotFound(w, r)
	}
}

func embeddedMethodError(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func embeddedRateError(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	http.Error(w, "Too many requests; try again later", http.StatusTooManyRequests)
}

func embeddedSingleValues(v url.Values) bool {
	for _, values := range v {
		if len(values) != 1 {
			return false
		}
	}
	return true
}

func embeddedParsePost(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, embeddedMaxFormSize)
	if r.ParseForm() != nil || !embeddedSingleValues(r.PostForm) {
		return false
	}
	return true
}

func (o *EmbeddedOAuth) startConsent(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	if !o.pages.allow(now, 30, time.Minute) {
		embeddedRateError(w)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !embeddedSingleValues(query) || query.Get("client_id") != o.config.ClientID ||
		query.Get("redirect_uri") != o.config.RedirectURI || query.Get("resource") != o.config.PublicURL ||
		query.Get("response_type") != "code" || query.Get("scope") != embeddedScope ||
		query.Get("code_challenge_method") != "S256" || query.Get("request") != "" || query.Get("request_uri") != "" ||
		query.Get("audience") != "" || (query.Get("response_mode") != "" && query.Get("response_mode") != "query") {
		http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		return
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(query.Get("code_challenge"))
	if err != nil || len(challenge) != sha256.Size || base64.RawURLEncoding.EncodeToString(challenge) != query.Get("code_challenge") {
		http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		return
	}
	// Fosite validates the registered client, redirect, state, and scope before
	// we display any password prompt. Issuance happens only after consent.
	if _, err := o.provider.NewAuthorizeRequest(r.Context(), r); err != nil {
		http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		return
	}
	for key, pending := range o.pending {
		if !now.Before(pending.expires) {
			delete(o.pending, key)
		}
	}
	if len(o.pending) >= 128 {
		embeddedRateError(w)
		return
	}
	flow, err := embeddedRandom()
	if err != nil {
		http.Error(w, "Authorization unavailable", http.StatusServiceUnavailable)
		return
	}
	cookie, err := embeddedRandom()
	if err != nil {
		http.Error(w, "Authorization unavailable", http.StatusServiceUnavailable)
		return
	}
	o.pending[flow] = embeddedConsent{query: query, cookieSum: sha256.Sum256([]byte(cookie)), expires: now.Add(embeddedConsentTTL)}
	http.SetCookie(w, &http.Cookie{Name: embeddedCookieName, Value: cookie, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(embeddedConsentTTL.Seconds())})
	// Native form POSTs under no-referrer carry Origin: null. Preserve the
	// same-origin Origin required by finishConsent without cross-origin referrers.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = embeddedConsentPage.Execute(w, struct{ Flow, Client, Resource string }{flow, o.config.ClientID, o.config.PublicURL})
}

func embeddedRandom() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func (o *EmbeddedOAuth) finishConsent(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != o.config.PublicURL || !embeddedParsePost(w, r) {
		http.Error(w, "Authorization denied; restart the connection", http.StatusForbidden)
		return
	}
	flow := r.PostForm.Get("flow")
	pending, ok := o.pending[flow]
	delete(o.pending, flow) // every attempt is single-use, including a failed login
	cookie, err := r.Cookie(embeddedCookieName)
	if !ok || err != nil || !time.Now().Before(pending.expires) {
		http.Error(w, "Authorization denied; restart the connection", http.StatusForbidden)
		return
	}
	actualCookie := sha256.Sum256([]byte(cookie.Value))
	if subtle.ConstantTimeCompare(actualCookie[:], pending.cookieSum[:]) != 1 {
		http.Error(w, "Authorization denied; restart the connection", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: embeddedCookieName, Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	// Never pass password/form consent fields to Fosite or persistent storage.
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, o.config.PublicURL+"/oauth/authorize?"+pending.query.Encode(), nil)
	ar, err := o.provider.NewAuthorizeRequest(r.Context(), req)
	if err != nil {
		http.Error(w, "Authorization denied; restart the connection", http.StatusForbidden)
		return
	}
	if r.PostForm.Get("decision") == "deny" {
		o.provider.WriteAuthorizeError(r.Context(), embeddedIssuerWriter{w, o.config.PublicURL}, ar, fosite.ErrAccessDenied)
		return
	}
	if !o.logins.allow(time.Now(), 10, time.Minute) {
		embeddedRateError(w)
		return
	}
	password := r.PostForm.Get("password")
	if r.PostForm.Get("decision") != "allow" || len(password) > 72 || bcrypt.CompareHashAndPassword(o.passwordHash, []byte(password)) != nil {
		http.Error(w, "Authorization denied; restart the connection", http.StatusForbidden)
		return
	}
	ar.SetRequestedAudience(fosite.Arguments{o.config.PublicURL})
	ar.GrantAudience(o.config.PublicURL)
	ar.GrantScope(embeddedScope)
	session := &fosite.DefaultSession{Subject: o.owner, Extra: map[string]any{"grant_expires_at": time.Now().Add(embeddedRefreshTTL).UTC().Format(time.RFC3339)}}
	response, err := o.provider.NewAuthorizeResponse(r.Context(), ar, session)
	if err != nil {
		o.provider.WriteAuthorizeError(r.Context(), embeddedIssuerWriter{w, o.config.PublicURL}, ar, err)
		return
	}
	response.AddParameter("iss", o.config.PublicURL)
	o.provider.WriteAuthorizeResponse(r.Context(), w, ar, response)
}

// Fosite owns error formatting/redirect validation. Add RFC 9207's issuer to
// its error redirects as well as success redirects before headers are sent.
type embeddedIssuerWriter struct {
	http.ResponseWriter
	issuer string
}

func (w embeddedIssuerWriter) WriteHeader(status int) {
	if location := w.Header().Get("Location"); location != "" {
		if u, err := url.Parse(location); err == nil {
			q := u.Query()
			q.Set("iss", w.issuer)
			u.RawQuery = q.Encode()
			w.Header().Set("Location", u.String())
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (o *EmbeddedOAuth) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	if !embeddedParsePost(w, r) || r.PostForm.Get("client_id") != o.config.ClientID ||
		r.Header.Get("Authorization") != "" || r.PostForm.Get("client_secret") != "" ||
		r.PostForm.Get("client_assertion") != "" || r.PostForm.Get("client_assertion_type") != "" {
		o.provider.WriteAccessError(r.Context(), w, nil, fosite.ErrInvalidRequest)
		return
	}
	if r.URL.Path == "/oauth/revoke" {
		err := o.provider.NewRevocationRequest(r.Context(), r)
		o.provider.WriteRevocationResponse(r.Context(), w, err)
		return
	}
	if r.PostForm.Get("resource") != o.config.PublicURL || r.PostForm.Get("audience") != "" {
		o.provider.WriteAccessError(r.Context(), w, nil, fosite.ErrInvalidRequest)
		return
	}
	grant := r.PostForm.Get("grant_type")
	if grant != "authorization_code" && grant != "refresh_token" {
		o.provider.WriteAccessError(r.Context(), w, nil, fosite.ErrUnsupportedGrantType)
		return
	}
	if grant == "authorization_code" && r.PostForm.Get("redirect_uri") != o.config.RedirectURI {
		o.provider.WriteAccessError(r.Context(), w, nil, fosite.ErrInvalidGrant)
		return
	}
	ar, err := o.provider.NewAccessRequest(r.Context(), r, &fosite.DefaultSession{})
	if err != nil {
		o.provider.WriteAccessError(r.Context(), w, ar, err)
		return
	}
	// Fosite restores the approved request's requested scopes/audience here;
	// its code handler restores granted values during NewAccessResponse.
	if ar.GetSession().GetSubject() != o.owner || !ar.GetRequestedScopes().ExactOne(embeddedScope) || !ar.GetRequestedAudience().ExactOne(o.config.PublicURL) {
		o.provider.WriteAccessError(r.Context(), w, ar, fosite.ErrInvalidGrant)
		return
	}
	session, ok := ar.GetSession().(*fosite.DefaultSession)
	if !ok {
		o.provider.WriteAccessError(r.Context(), w, ar, fosite.ErrInvalidGrant)
		return
	}
	deadline, _ := session.Extra["grant_expires_at"].(string)
	expires, err := time.Parse(time.RFC3339, deadline)
	if err != nil || !time.Now().Before(expires) {
		o.provider.WriteAccessError(r.Context(), w, ar, fosite.ErrInvalidGrant)
		return
	}
	// Refresh rotation never extends the original owner's 30-day consent.
	for _, tokenType := range []fosite.TokenType{fosite.AccessToken, fosite.RefreshToken} {
		if session.GetExpiresAt(tokenType).After(expires) {
			session.SetExpiresAt(tokenType, expires)
		}
	}
	response, err := o.provider.NewAccessResponse(r.Context(), ar)
	if err != nil {
		o.provider.WriteAccessError(r.Context(), w, ar, err)
		return
	}
	if !ar.GetGrantedScopes().ExactOne(embeddedScope) || !ar.GetGrantedAudience().ExactOne(o.config.PublicURL) {
		_ = o.store.RevokeAccessToken(r.Context(), ar.GetID())
		_ = o.store.RevokeRefreshToken(r.Context(), ar.GetID())
		o.provider.WriteAccessError(r.Context(), w, ar, fosite.ErrInvalidGrant)
		return
	}
	o.provider.WriteAccessResponse(r.Context(), w, ar, response)
}

// Authenticate returns an opaque owner/grant identity used to bind subscriptions.
func (o *EmbeddedOAuth) Authenticate(r *http.Request) (string, error) {
	if r == nil {
		return "", errInvalidAccessToken
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > maxAccessTokenBytes+16 {
		return "", errInvalidAccessToken
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > maxAccessTokenBytes || strings.ContainsAny(token, " \r\n\t") {
		return "", errInvalidAccessToken
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	use, request, err := o.provider.IntrospectToken(r.Context(), token, fosite.AccessToken, &fosite.DefaultSession{}, embeddedScope)
	if err != nil || use != fosite.AccessToken || request.GetSession().GetSubject() != o.owner ||
		request.GetClient().GetID() != o.config.ClientID || !request.GetGrantedAudience().ExactOne(o.config.PublicURL) {
		return "", errInvalidAccessToken
	}
	return o.owner + ":" + request.GetID(), nil
}

// AuthorizedOwner is checked immediately before webhook delivery. A revoked
// grant, refresh-token reuse, expired consent, or changed bootstrap password
// invalidates its subscriptions without relying on the original access token.
func (o *EmbeddedOAuth) AuthorizedOwner(owner string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	subject, requestID, ok := strings.Cut(owner, ":")
	return ok && subject == o.owner && requestID != "" && o.store.HasActiveGrant(subject, requestID, time.Now())
}

var embeddedConsentPage = template.Must(template.New("owner-consent").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Loop event bridge</title>
<style>body{font:17px system-ui;max-width:38rem;margin:8vh auto;padding:1.5rem;background:#f7f7f3;color:#16251a}main{background:white;border:1px solid #d8ddd8;border-radius:12px;padding:2rem}input{box-sizing:border-box;width:100%;font:inherit;margin:.6rem 0 1rem;padding:.7rem}button{font:inherit;padding:.7rem 1rem;margin:.4rem .3rem .4rem 0}small{display:block;color:#506055;overflow-wrap:anywhere}</style>
<main><h1>Connect your event bridge</h1><p>Allow this client to read your configured events and manage event subscriptions for 30 days.</p>
<small>Client: {{.Client}}</small><small>Service: {{.Resource}}</small>
<p>Enter the owner password you mounted when deploying this service. It is sent only to this service over HTTPS.</p>
<form method="post" action="/oauth/authorize"><input type="hidden" name="flow" value="{{.Flow}}">
<label for="password">Owner password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="72" required>
<button type="submit" name="decision" value="allow">Allow connection</button><button type="submit" name="decision" value="deny" formnovalidate>Cancel</button>
</form></main></html>`))
