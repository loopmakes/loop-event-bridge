package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
)

const (
	oauthStoreVersion         = 1
	oauthStoreMaxRecords      = 16384
	oauthStoreMaxBytes        = 32 << 20
	oauthStoreMaxRequestBytes = 64 << 10
	// The server caps refresh grants at 30 days. Retain replay evidence beyond
	// that cap, including codes whose short exchange lifetime has elapsed.
	oauthStoreRetention = 31 * 24 * time.Hour
)

// oauthStore is a single-process, single-owner store. Its callers must serialize
// complete Fosite endpoint operations: each individual storage operation is
// atomic, but a sequence of Fosite calls is not a database transaction.
// Persist failure latches the store closed until the process is restarted.
type oauthStore struct {
	mu     sync.Mutex
	path   string
	client *fosite.DefaultClient
	data   oauthStoreData
	failed error
	now    func() time.Time
}

type oauthStoreData struct {
	Version int                         `json:"version"`
	Binding string                      `json:"binding"`
	Secret  []byte                      `json:"secret"`
	Codes   map[string]oauthStoreRecord `json:"codes"`
	Access  map[string]oauthStoreRecord `json:"access"`
	Refresh map[string]oauthStoreRecord `json:"refresh"`
	PKCE    map[string]oauthStoreRecord `json:"pkce"`
	JTIs    map[string]time.Time        `json:"jtis"`
}

type oauthStoreRecord struct {
	Request         oauthStoredRequest `json:"request"`
	Active          bool               `json:"active"`
	CreatedAt       time.Time          `json:"created_at"`
	RetainUntil     time.Time          `json:"retain_until"`
	AccessSignature string             `json:"access_signature,omitempty"`
}

// Use concrete, deliberately small structures rather than serializing Fosite
// interface values. Client configuration always comes from operator config.
type oauthStoredRequest struct {
	ID                string                 `json:"id"`
	ClientID          string                 `json:"client_id"`
	RequestedAt       time.Time              `json:"requested_at"`
	RequestedScope    fosite.Arguments       `json:"requested_scope"`
	GrantedScope      fosite.Arguments       `json:"granted_scope"`
	RequestedAudience fosite.Arguments       `json:"requested_audience"`
	GrantedAudience   fosite.Arguments       `json:"granted_audience"`
	Form              url.Values             `json:"form"`
	Session           *fosite.DefaultSession `json:"session"`
}

var (
	_ fosite.ClientManager          = (*oauthStore)(nil)
	_ oauth2.CoreStorage            = (*oauthStore)(nil)
	_ oauth2.TokenRevocationStorage = (*oauthStore)(nil)
	_ pkce.PKCERequestStorage       = (*oauthStore)(nil)
)

// NewOAuthStore opens durable state or creates it at runtime. Changing owner
// binding or any client configuration rotates the key and discards all grants.
// ownerBinding must be an opaque configuration/password fingerprint, never a
// password. Only a second hash of it is persisted.
func NewOAuthStore(path string, client *fosite.DefaultClient, ownerBinding string) (*oauthStore, error) {
	if path == "" || ownerBinding == "" || client == nil || client.ID == "" || !client.Public || len(client.Secret) != 0 || len(client.RotatedSecrets) != 0 {
		return nil, errors.New("OAuth store requires a path, owner binding, and one public client without secrets")
	}
	config, err := json.Marshal(struct {
		Binding string
		Client  *fosite.DefaultClient
	}{ownerBinding, client})
	if err != nil {
		return nil, fmt.Errorf("encode OAuth store binding: %w", err)
	}
	digest := sha256.Sum256(config)
	binding := hex.EncodeToString(digest[:])
	s := &oauthStore{path: path, client: cloneOAuthClient(client), now: time.Now}
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("OAuth store must be a regular private file (0600)")
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return nil, fmt.Errorf("open OAuth store: %w", openErr)
		}
		encoded, readErr := io.ReadAll(io.LimitReader(f, oauthStoreMaxBytes+1))
		closeErr := f.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read OAuth store: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close OAuth store: %w", closeErr)
		}
		if len(encoded) > oauthStoreMaxBytes {
			return nil, errors.New("OAuth store exceeds size limit")
		}
		if err = decodeOAuthJSON(encoded, &s.data); err != nil {
			return nil, fmt.Errorf("invalid OAuth store: %w", err)
		}
		if err = s.validateData(binding); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect OAuth store: %w", err)
	}
	if err != nil || s.data.Binding != binding {
		s.data = oauthStoreData{Version: oauthStoreVersion, Binding: binding, Secret: make([]byte, 32), Codes: map[string]oauthStoreRecord{}, Access: map[string]oauthStoreRecord{}, Refresh: map[string]oauthStoreRecord{}, PKCE: map[string]oauthStoreRecord{}, JTIs: map[string]time.Time{}}
		if _, err = rand.Read(s.data.Secret); err != nil {
			return nil, fmt.Errorf("initialize OAuth signing key: %w", err)
		}
		if err = s.persist(s.data); err != nil {
			return nil, err
		}
	} else if pruneOAuthData(&s.data, s.now()) {
		if err = s.persist(s.data); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *oauthStore) Secret() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return nil
	}
	return append([]byte(nil), s.data.Secret...)
}

func cloneOAuthClient(c *fosite.DefaultClient) *fosite.DefaultClient {
	x := *c
	x.Secret = append([]byte(nil), c.Secret...)
	x.RotatedSecrets = make([][]byte, len(c.RotatedSecrets))
	for i := range c.RotatedSecrets {
		x.RotatedSecrets[i] = append([]byte(nil), c.RotatedSecrets[i]...)
	}
	x.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	x.GrantTypes = append([]string(nil), c.GrantTypes...)
	x.ResponseTypes = append([]string(nil), c.ResponseTypes...)
	x.Scopes = append([]string(nil), c.Scopes...)
	x.Audience = append([]string(nil), c.Audience...)
	return &x
}

func decodeOAuthJSON(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func oauthAllowedFormField(k string) bool {
	switch k {
	case "grant_type", "response_type", "scope", "client_id", "redirect_uri", "code_challenge", "code_challenge_method":
		return true
	}
	return false
}

func (s *oauthStore) snapshot(req fosite.Requester) (oauthStoredRequest, error) {
	var out oauthStoredRequest
	if req == nil || req.GetClient() == nil || req.GetClient().GetID() != s.client.ID {
		return out, errors.New("invalid OAuth request client")
	}
	sess, ok := req.GetSession().(*fosite.DefaultSession)
	if !ok || sess == nil || sess.Subject == "" {
		return out, errors.New("OAuth store requires a default session with a subject")
	}
	form := url.Values{}
	for k, v := range req.GetRequestForm() {
		if oauthAllowedFormField(k) {
			form[k] = append([]string(nil), v...)
		}
	}
	out = oauthStoredRequest{ID: req.GetID(), ClientID: s.client.ID, RequestedAt: req.GetRequestedAt(), RequestedScope: req.GetRequestedScopes(), GrantedScope: req.GetGrantedScopes(), RequestedAudience: req.GetRequestedAudience(), GrantedAudience: req.GetGrantedAudience(), Form: form, Session: sess}
	encoded, err := json.Marshal(out)
	if err != nil {
		return oauthStoredRequest{}, errors.New("OAuth session is not JSON serializable")
	}
	if len(encoded) > oauthStoreMaxRequestBytes {
		return oauthStoredRequest{}, errors.New("OAuth session exceeds size limit")
	}
	// Round-tripping also detaches nested session Extra maps/slices.
	out = oauthStoredRequest{}
	if err = decodeOAuthJSON(encoded, &out); err != nil {
		return oauthStoredRequest{}, err
	}
	if out.ID == "" || out.RequestedAt.IsZero() {
		return oauthStoredRequest{}, errors.New("OAuth request is missing identity or issue time")
	}
	return out, nil
}

func (s *oauthStore) hydrate(req oauthStoredRequest) (fosite.Requester, error) {
	encoded, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var clone oauthStoredRequest
	if err = decodeOAuthJSON(encoded, &clone); err != nil {
		return nil, err
	}
	return &fosite.Request{ID: clone.ID, RequestedAt: clone.RequestedAt, Client: cloneOAuthClient(s.client), RequestedScope: clone.RequestedScope, GrantedScope: clone.GrantedScope, RequestedAudience: clone.RequestedAudience, GrantedAudience: clone.GrantedAudience, Form: clone.Form, Session: clone.Session}, nil
}

func (s *oauthStore) validateData(expectedBinding string) error {
	d := &s.data
	if d.Version != oauthStoreVersion || len(d.Secret) != 32 || len(d.Binding) != 64 || d.Codes == nil || d.Access == nil || d.Refresh == nil || d.PKCE == nil || d.JTIs == nil || oauthRecordCount(*d) > oauthStoreMaxRecords {
		return errors.New("invalid OAuth store header or capacity")
	}
	if _, err := hex.DecodeString(d.Binding); err != nil {
		return errors.New("invalid OAuth store binding")
	}
	storedClientID := ""
	for kind, records := range map[string]map[string]oauthStoreRecord{"code": d.Codes, "access": d.Access, "refresh": d.Refresh, "pkce": d.PKCE} {
		for key, r := range records {
			if !validOAuthKey(key) || r.Request.ID == "" || r.Request.ClientID == "" || r.Request.RequestedAt.IsZero() || r.Request.Session == nil || r.Request.Session.Subject == "" || r.CreatedAt.IsZero() || !r.RetainUntil.After(r.CreatedAt) || r.RetainUntil.After(r.CreatedAt.Add(oauthStoreRetention)) || (r.AccessSignature != "" && !validOAuthKey(r.AccessSignature)) {
				return errors.New("invalid OAuth store record")
			}
			if storedClientID == "" {
				storedClientID = r.Request.ClientID
			}
			if r.Request.ClientID != storedClientID || (d.Binding == expectedBinding && r.Request.ClientID != s.client.ID) {
				return errors.New("invalid OAuth store client binding")
			}
			exp := r.Request.Session.ExpiresAt[oauthRecordToken(kind)]
			if !exp.After(r.CreatedAt) || exp.After(r.CreatedAt.Add(oauthStoreRetention)) || (r.Active && !r.RetainUntil.Equal(exp)) || (!r.Active && kind != "code" && kind != "refresh") {
				return errors.New("invalid OAuth store record expiration or active state")
			}
			for k := range r.Request.Form {
				if !oauthAllowedFormField(k) {
					return errors.New("unsafe OAuth store request field")
				}
			}
			encoded, err := json.Marshal(r.Request)
			if err != nil || len(encoded) > oauthStoreMaxRequestBytes {
				return errors.New("invalid OAuth store request size")
			}
		}
	}
	for key, exp := range d.JTIs {
		if !validOAuthKey(key) || exp.IsZero() {
			return errors.New("invalid OAuth store assertion record")
		}
	}
	return nil
}

func validOAuthKey(key string) bool { return len(key) > 0 && len(key) <= 512 }
func oauthRecordCount(d oauthStoreData) int {
	return len(d.Codes) + len(d.Access) + len(d.Refresh) + len(d.PKCE) + len(d.JTIs)
}
func cloneOAuthRecords(in map[string]oauthStoreRecord) map[string]oauthStoreRecord {
	out := make(map[string]oauthStoreRecord, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func cloneOAuthData(d oauthStoreData) oauthStoreData {
	d.Codes = cloneOAuthRecords(d.Codes)
	d.Access = cloneOAuthRecords(d.Access)
	d.Refresh = cloneOAuthRecords(d.Refresh)
	d.PKCE = cloneOAuthRecords(d.PKCE)
	jtis := make(map[string]time.Time, len(d.JTIs))
	for k, v := range d.JTIs {
		jtis[k] = v
	}
	d.JTIs = jtis
	return d
}
func pruneOAuthData(d *oauthStoreData, now time.Time) bool {
	changed := false
	for _, records := range []map[string]oauthStoreRecord{d.Codes, d.Access, d.Refresh, d.PKCE} {
		for key, r := range records {
			if !r.RetainUntil.After(now) {
				delete(records, key)
				changed = true
			}
		}
	}
	for key, exp := range d.JTIs {
		if !exp.After(now) {
			delete(d.JTIs, key)
			changed = true
		}
	}
	return changed
}

// Called with the lock held. State is installed only after a durable write.
func (s *oauthStore) mutate(ctx context.Context, fn func(*oauthStoreData) error) error {
	if s.failed != nil {
		return s.failed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	next := cloneOAuthData(s.data)
	pruneOAuthData(&next, s.now())
	if err := fn(&next); err != nil {
		return err
	}
	if oauthRecordCount(next) > oauthStoreMaxRecords {
		return errors.New("OAuth store is at capacity")
	}
	if err := s.persist(next); err != nil {
		s.failed = fmt.Errorf("OAuth store unavailable after persistence failure: %w", err)
		return s.failed
	}
	s.data = next
	return nil
}

func (s *oauthStore) persist(data oauthStoreData) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode OAuth store: %w", err)
	}
	if len(encoded) > oauthStoreMaxBytes {
		return errors.New("OAuth store exceeds size limit")
	}
	dir := filepath.Dir(s.path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create OAuth state directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".oauth-state-*")
	if err != nil {
		return fmt.Errorf("create OAuth state temporary file: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(encoded)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write OAuth state: %w", err)
	}
	if err = os.Rename(name, s.path); err != nil {
		return fmt.Errorf("replace OAuth state: %w", err)
	}
	df, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open OAuth state directory: %w", err)
	}
	err = df.Sync()
	closeErr = df.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("sync OAuth state directory: %w", err)
	}
	return nil
}

func (s *oauthStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return nil, s.failed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id != s.client.ID {
		return nil, fosite.ErrNotFound
	}
	return cloneOAuthClient(s.client), nil
}
func (s *oauthStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return s.failed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validOAuthKey(jti) {
		return errors.New("invalid assertion identifier")
	}
	if s.data.JTIs[jti].After(s.now()) {
		return fosite.ErrJTIKnown
	}
	return nil
}
func (s *oauthStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutate(ctx, func(d *oauthStoreData) error {
		if !validOAuthKey(jti) || !exp.After(s.now()) || exp.After(s.now().Add(oauthStoreRetention)) {
			return errors.New("invalid assertion expiration or identifier")
		}
		if _, exists := d.JTIs[jti]; exists {
			return fosite.ErrJTIKnown
		}
		d.JTIs[jti] = exp
		return nil
	})
}

func oauthRecords(d *oauthStoreData, kind string) map[string]oauthStoreRecord {
	switch kind {
	case "code":
		return d.Codes
	case "access":
		return d.Access
	case "refresh":
		return d.Refresh
	default:
		return d.PKCE
	}
}
func oauthRecordToken(kind string) fosite.TokenType {
	switch kind {
	case "access":
		return fosite.AccessToken
	case "refresh":
		return fosite.RefreshToken
	default:
		return fosite.AuthorizeCode
	}
}
func (s *oauthStore) create(ctx context.Context, kind, key, access string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return s.failed
	}
	if !validOAuthKey(key) || (access != "" && !validOAuthKey(access)) {
		return errors.New("invalid OAuth token signature")
	}
	snapshot, err := s.snapshot(req)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	exp := snapshot.Session.GetExpiresAt(oauthRecordToken(kind))
	if !exp.After(now) || exp.After(now.Add(oauthStoreRetention)) {
		return errors.New("OAuth token must have a bounded future expiration")
	}
	return s.mutate(ctx, func(d *oauthStoreData) error {
		records := oauthRecords(d, kind)
		if _, exists := records[key]; exists {
			return errors.New("OAuth token signature already exists")
		}
		records[key] = oauthStoreRecord{Request: snapshot, Active: true, CreatedAt: now, RetainUntil: exp, AccessSignature: access}
		return nil
	})
}
func (s *oauthStore) get(ctx context.Context, kind, key string) (fosite.Requester, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return nil, s.failed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, ok := oauthRecords(&s.data, kind)[key]
	if !ok || !r.RetainUntil.After(s.now()) {
		return nil, fosite.ErrNotFound
	}
	req, err := s.hydrate(r.Request)
	if err != nil {
		return nil, err
	}
	if !r.Active && kind == "code" {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}
	if !r.Active && kind == "refresh" {
		return req, fosite.ErrInactiveToken
	}
	return req, nil
}
func (s *oauthStore) remove(ctx context.Context, kind, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutate(ctx, func(d *oauthStoreData) error { delete(oauthRecords(d, kind), key); return nil })
}
func (s *oauthStore) CreateAuthorizeCodeSession(ctx context.Context, key string, req fosite.Requester) error {
	return s.create(ctx, "code", key, "", req)
}
func (s *oauthStore) GetAuthorizeCodeSession(ctx context.Context, key string, _ fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, "code", key)
}
func (s *oauthStore) InvalidateAuthorizeCodeSession(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutate(ctx, func(d *oauthStoreData) error {
		r, ok := d.Codes[key]
		if !ok {
			return fosite.ErrNotFound
		}
		r.Active = false
		r.RetainUntil = r.CreatedAt.Add(oauthStoreRetention)
		d.Codes[key] = r
		return nil
	})
}
func (s *oauthStore) CreateAccessTokenSession(ctx context.Context, key string, req fosite.Requester) error {
	return s.create(ctx, "access", key, "", req)
}
func (s *oauthStore) GetAccessTokenSession(ctx context.Context, key string, _ fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, "access", key)
}
func (s *oauthStore) DeleteAccessTokenSession(ctx context.Context, key string) error {
	return s.remove(ctx, "access", key)
}
func (s *oauthStore) CreateRefreshTokenSession(ctx context.Context, key, access string, req fosite.Requester) error {
	return s.create(ctx, "refresh", key, access, req)
}
func (s *oauthStore) GetRefreshTokenSession(ctx context.Context, key string, _ fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, "refresh", key)
}
func (s *oauthStore) DeleteRefreshTokenSession(ctx context.Context, key string) error {
	return s.remove(ctx, "refresh", key)
}
func (s *oauthStore) CreatePKCERequestSession(ctx context.Context, key string, req fosite.Requester) error {
	return s.create(ctx, "pkce", key, "", req)
}
func (s *oauthStore) GetPKCERequestSession(ctx context.Context, key string, _ fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, "pkce", key)
}
func (s *oauthStore) DeletePKCERequestSession(ctx context.Context, key string) error {
	return s.remove(ctx, "pkce", key)
}
func revokeOAuthAccess(d *oauthStoreData, requestID string) {
	for key, r := range d.Access {
		if r.Request.ID == requestID {
			delete(d.Access, key)
		}
	}
}
func revokeOAuthRefresh(d *oauthStoreData, requestID string) {
	for key, r := range d.Refresh {
		if r.Request.ID == requestID {
			r.Active = false
			r.RetainUntil = r.CreatedAt.Add(oauthStoreRetention)
			d.Refresh[key] = r
		}
	}
}
func (s *oauthStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutate(ctx, func(d *oauthStoreData) error { revokeOAuthAccess(d, requestID); return nil })
}
func (s *oauthStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutate(ctx, func(d *oauthStoreData) error {
		revokeOAuthRefresh(d, requestID)
		revokeOAuthAccess(d, requestID)
		return nil
	})
}
func (s *oauthStore) RotateRefreshToken(ctx context.Context, requestID, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutate(ctx, func(d *oauthStoreData) error {
		r, ok := d.Refresh[signature]
		if !ok || r.Request.ID != requestID {
			return fosite.ErrNotFound
		}
		if !r.Active {
			return fosite.ErrInactiveToken
		}
		revokeOAuthRefresh(d, requestID)
		revokeOAuthAccess(d, requestID)
		return nil
	})
}

// HasActiveGrant lets persisted subscriptions stop delivering as soon as their
// authorizing grant is expired or revoked. Invalid store state fails closed.
func (s *oauthStore) HasActiveGrant(subject, requestID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil || subject == "" || requestID == "" {
		return false
	}
	for kind, records := range map[string]map[string]oauthStoreRecord{"access": s.data.Access, "refresh": s.data.Refresh} {
		for _, r := range records {
			if !r.Active || r.Request.ID != requestID || r.Request.Session == nil || r.Request.Session.Subject != subject || !r.RetainUntil.After(now) || !r.Request.Session.ExpiresAt[oauthRecordToken(kind)].After(now) {
				continue
			}
			if value, exists := r.Request.Session.Extra["grant_expires_at"]; exists {
				text, ok := value.(string)
				if !ok {
					continue
				}
				exp, err := time.Parse(time.RFC3339, text)
				if err != nil || !exp.After(now) {
					continue
				}
			}
			return true
		}
	}
	return false
}
