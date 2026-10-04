package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ory/fosite"
)

func storeFixtureClient() *fosite.DefaultClient {
	return &fosite.DefaultClient{ID: "fixture-public-client", Public: true, RedirectURIs: []string{"https://client.example/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, Scopes: []string{"events", "offline"}, Audience: []string{"https://bridge.example"}}
}

func newStoreFixture(t *testing.T) (*oauthStore, time.Time) {
	t.Helper()
	s, err := NewOAuthStore(filepath.Join(t.TempDir(), "oauth.json"), storeFixtureClient(), "fixture-owner-fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	return s, now
}

func storeFixtureRequest(now time.Time, id string) *fosite.Request {
	return &fosite.Request{ID: id, Client: storeFixtureClient(), RequestedAt: now, RequestedScope: fosite.Arguments{"events", "offline"}, GrantedScope: fosite.Arguments{"events", "offline"}, RequestedAudience: fosite.Arguments{"https://bridge.example"}, GrantedAudience: fosite.Arguments{"https://bridge.example"}, Form: url.Values{"redirect_uri": {"https://client.example/callback"}, "code_challenge": {"fixture-pkce-challenge"}, "code_challenge_method": {"S256"}}, Session: &fosite.DefaultSession{Subject: "fixture-owner", ExpiresAt: map[fosite.TokenType]time.Time{fosite.AuthorizeCode: now.Add(5 * time.Minute), fosite.AccessToken: now.Add(time.Hour), fosite.RefreshToken: now.Add(30 * 24 * time.Hour)}, Extra: map[string]interface{}{"grant_expires_at": now.Add(30 * 24 * time.Hour).Format(time.RFC3339), "nested": map[string]interface{}{"value": "original"}}}}
}

func requireStoreError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v; want %v", got, want)
	}
}

func TestOAuthStorePersistenceAndPrivacy(t *testing.T) {
	s, now := newStoreFixture(t)
	ctx := context.Background()
	req := storeFixtureRequest(now, "grant-1")
	req.Form.Set("password", "fixture-password-not-for-disk")
	req.Form.Set("code", "fixture-raw-code-not-for-disk")
	req.Form.Set("access_token", "fixture-raw-access-not-for-disk")
	req.Form.Set("refresh_token", "fixture-raw-refresh-not-for-disk")
	req.Form.Set("client_secret", "fixture-client-secret-not-for-disk")
	req.Form.Set("code_verifier", "fixture-pkce-verifier-not-for-disk")
	for _, create := range []func() error{
		func() error { return s.CreateAuthorizeCodeSession(ctx, "code-signature", req) },
		func() error { return s.CreatePKCERequestSession(ctx, "code-signature", req) },
		func() error { return s.CreateAccessTokenSession(ctx, "access-signature", req) },
		func() error { return s.CreateRefreshTokenSession(ctx, "refresh-signature", "access-signature", req) },
	} {
		if err := create(); err != nil {
			t.Fatal(err)
		}
	}
	secret := s.Secret()
	if len(secret) != 32 {
		t.Fatal("signing key length")
	}
	secret[0] ^= 255
	if bytes.Equal(secret, s.Secret()) {
		t.Fatal("secret accessor exposes mutable state")
	}
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v", info.Mode())
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"not-for-disk", "fixture-owner-fingerprint", "code_verifier", "password", "client_secret"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("persisted forbidden content: %s", forbidden)
		}
	}
	reopened, err := NewOAuthStore(s.path, storeFixtureClient(), "fixture-owner-fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Secret(), reopened.Secret()) {
		t.Fatal("key changed on restart")
	}
	for _, get := range []func() (fosite.Requester, error){
		func() (fosite.Requester, error) { return reopened.GetAuthorizeCodeSession(ctx, "code-signature", nil) },
		func() (fosite.Requester, error) { return reopened.GetPKCERequestSession(ctx, "code-signature", nil) },
		func() (fosite.Requester, error) { return reopened.GetAccessTokenSession(ctx, "access-signature", nil) },
		func() (fosite.Requester, error) {
			return reopened.GetRefreshTokenSession(ctx, "refresh-signature", nil)
		},
	} {
		loaded, err := get()
		if err != nil {
			t.Fatal(err)
		}
		if loaded.GetID() != "grant-1" || loaded.GetSession().GetSubject() != "fixture-owner" || !loaded.GetGrantedScopes().Exact("events offline") || loaded.GetRequestForm().Get("code_challenge") != "fixture-pkce-challenge" {
			t.Fatalf("incorrect restored request: %#v", loaded)
		}
	}
}

func TestOAuthStoreDefensiveClones(t *testing.T) {
	s, now := newStoreFixture(t)
	ctx := context.Background()
	req := storeFixtureRequest(now, "clone-grant")
	if err := s.CreateAccessTokenSession(ctx, "clone-signature", req); err != nil {
		t.Fatal(err)
	}
	req.GrantedScope[0] = "mutated"
	req.Form["redirect_uri"][0] = "https://mutated.example"
	req.Session.(*fosite.DefaultSession).Extra["nested"].(map[string]interface{})["value"] = "mutated"
	req.Session.SetExpiresAt(fosite.AccessToken, now.Add(-time.Hour))
	loaded, err := s.GetAccessTokenSession(ctx, "clone-signature", nil)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GetGrantedScopes()[0] != "events" || loaded.GetRequestForm().Get("redirect_uri") != "https://client.example/callback" || loaded.GetSession().(*fosite.DefaultSession).Extra["nested"].(map[string]interface{})["value"] != "original" || !loaded.GetSession().GetExpiresAt(fosite.AccessToken).After(now) {
		t.Fatal("input aliases retained")
	}
	loaded.GetSession().(*fosite.DefaultSession).Extra["nested"].(map[string]interface{})["value"] = "mutated-output"
	loaded.GetClient().(*fosite.DefaultClient).RedirectURIs[0] = "https://mutated-output.example"
	loaded.GetGrantedScopes()[0] = "mutated-output"
	again, err := s.GetAccessTokenSession(ctx, "clone-signature", nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.GetGrantedScopes()[0] != "events" || again.GetSession().(*fosite.DefaultSession).Extra["nested"].(map[string]interface{})["value"] != "original" {
		t.Fatal("output aliases retained")
	}
	client, err := s.GetClient(ctx, storeFixtureClient().ID)
	if err != nil {
		t.Fatal(err)
	}
	if client.GetRedirectURIs()[0] != "https://client.example/callback" {
		t.Fatal("client aliases retained")
	}
	client.(*fosite.DefaultClient).Scopes[0] = "mutated"
	client, _ = s.GetClient(ctx, storeFixtureClient().ID)
	if client.GetScopes()[0] != "events" {
		t.Fatal("GetClient aliases retained")
	}
}

func TestOAuthStoreBindingAndClientChangesResetGrants(t *testing.T) {
	for _, change := range []string{"owner", "client"} {
		t.Run(change, func(t *testing.T) {
			s, now := newStoreFixture(t)
			if err := s.CreateAccessTokenSession(context.Background(), "old-access", storeFixtureRequest(now, "old-grant")); err != nil {
				t.Fatal(err)
			}
			client, binding := storeFixtureClient(), "fixture-owner-fingerprint"
			if change == "owner" {
				binding = "changed-owner-fingerprint"
			} else {
				client.RedirectURIs = []string{"https://changed.example/callback"}
			}
			newStore, err := NewOAuthStore(s.path, client, binding)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(s.Secret(), newStore.Secret()) {
				t.Fatal("key not rotated")
			}
			_, err = newStore.GetAccessTokenSession(context.Background(), "old-access", nil)
			requireStoreError(t, err, fosite.ErrNotFound)
		})
	}
}

func TestOAuthStoreReplaySentinelsAndFamilyRevocation(t *testing.T) {
	s, now := newStoreFixture(t)
	ctx := context.Background()
	req := storeFixtureRequest(now, "family")
	if err := s.CreateAuthorizeCodeSession(ctx, "code", req); err != nil {
		t.Fatal(err)
	}
	if err := s.InvalidateAuthorizeCodeSession(ctx, "code"); err != nil {
		t.Fatal(err)
	}
	for _, sig := range []string{"access-1", "access-2"} {
		if err := s.CreateAccessTokenSession(ctx, sig, req); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req); err != nil {
		t.Fatal(err)
	}
	other := storeFixtureRequest(now, "other-family")
	if err := s.CreateAccessTokenSession(ctx, "other-access", other); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateRefreshToken(ctx, "family", "refresh-1"); err != nil {
		t.Fatal(err)
	}
	old, err := s.GetRefreshTokenSession(ctx, "refresh-1", nil)
	requireStoreError(t, err, fosite.ErrInactiveToken)
	if old == nil || old.GetID() != "family" {
		t.Fatal("refresh sentinel missing requester")
	}
	for _, sig := range []string{"access-1", "access-2"} {
		_, err := s.GetAccessTokenSession(ctx, sig, nil)
		requireStoreError(t, err, fosite.ErrNotFound)
	}
	if _, err := s.GetAccessTokenSession(ctx, "other-access", nil); err != nil {
		t.Fatal("revoked unrelated family")
	}
	if err := s.CreateAccessTokenSession(ctx, "access-3", req); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRefreshTokenSession(ctx, "refresh-2", "access-3", req); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeRefreshToken(ctx, old.GetID()); err != nil {
		t.Fatal(err)
	}
	_, err = s.GetRefreshTokenSession(ctx, "refresh-2", nil)
	requireStoreError(t, err, fosite.ErrInactiveToken)
	_, err = s.GetAccessTokenSession(ctx, "access-3", nil)
	requireStoreError(t, err, fosite.ErrNotFound)
	s.now = func() time.Time { return now.Add(10 * time.Minute) }
	code, err := s.GetAuthorizeCodeSession(ctx, "code", nil)
	requireStoreError(t, err, fosite.ErrInvalidatedAuthorizeCode)
	if code == nil || code.GetID() != "family" {
		t.Fatal("code sentinel lost after code expiry")
	}
	reopened, err := NewOAuthStore(s.path, storeFixtureClient(), "fixture-owner-fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	_, err = reopened.GetRefreshTokenSession(ctx, "refresh-2", nil)
	requireStoreError(t, err, fosite.ErrInactiveToken)
	_, err = reopened.GetAuthorizeCodeSession(ctx, "code", nil)
	requireStoreError(t, err, fosite.ErrInvalidatedAuthorizeCode)
}

func TestOAuthStoreGrantLiveness(t *testing.T) {
	s, now := newStoreFixture(t)
	ctx := context.Background()
	req := storeFixtureRequest(now, "live-grant")
	if err := s.CreateAccessTokenSession(ctx, "access", req); err != nil {
		t.Fatal(err)
	}
	if !s.HasActiveGrant("fixture-owner", "live-grant", now) {
		t.Fatal("live access grant missing")
	}
	if s.HasActiveGrant("wrong-owner", "live-grant", now) || s.HasActiveGrant("fixture-owner", "wrong-id", now) || s.HasActiveGrant("fixture-owner", "live-grant", now.Add(time.Hour)) {
		t.Fatal("incorrect grant accepted")
	}
	if err := s.CreateRefreshTokenSession(ctx, "refresh", "access", req); err != nil {
		t.Fatal(err)
	}
	if !s.HasActiveGrant("fixture-owner", "live-grant", now.Add(2*time.Hour)) {
		t.Fatal("live refresh grant missing")
	}
	if err := s.RevokeRefreshToken(ctx, "live-grant"); err != nil {
		t.Fatal(err)
	}
	if s.HasActiveGrant("fixture-owner", "live-grant", now) {
		t.Fatal("revoked family still live")
	}
	for i, value := range []interface{}{now.Add(-time.Second).Format(time.RFC3339), "malformed", float64(100)} {
		req := storeFixtureRequest(now, fmt.Sprintf("expired-%d", i))
		req.Session.(*fosite.DefaultSession).Extra["grant_expires_at"] = value
		if err := s.CreateAccessTokenSession(ctx, fmt.Sprintf("expired-%d", i), req); err != nil {
			t.Fatal(err)
		}
		if s.HasActiveGrant("fixture-owner", req.ID, now) {
			t.Fatal("invalid absolute grant expiration accepted")
		}
	}
}

func TestOAuthStoreExpiryCapacityAndAssertions(t *testing.T) {
	s, now := newStoreFixture(t)
	ctx := context.Background()
	if err := s.CreateAuthorizeCodeSession(ctx, "expired-code", storeFixtureRequest(now, "expires")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientAssertionJWT(ctx, "assertion-id", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	requireStoreError(t, s.ClientAssertionJWTValid(ctx, "assertion-id"), fosite.ErrJTIKnown)
	requireStoreError(t, s.SetClientAssertionJWT(ctx, "assertion-id", now.Add(time.Minute)), fosite.ErrJTIKnown)
	s.now = func() time.Time { return now.Add(10 * time.Minute) }
	_, err := s.GetAuthorizeCodeSession(ctx, "expired-code", nil)
	requireStoreError(t, err, fosite.ErrNotFound)
	if err := s.ClientAssertionJWTValid(ctx, "assertion-id"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientAssertionJWT(ctx, "new-assertion", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(s.data.Codes) != 0 || len(s.data.JTIs) != 1 {
		t.Fatal("expired records not pruned")
	}
	for i := 1; i < oauthStoreMaxRecords; i++ {
		s.data.JTIs[fmt.Sprintf("capacity-%d", i)] = now.Add(time.Hour)
	}
	if err := s.SetClientAssertionJWT(ctx, "overflow", now.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("capacity not enforced: %v", err)
	}
	if s.failed != nil {
		t.Fatal("capacity limit latched healthy store closed")
	}
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	if err := s.SetClientAssertionJWT(ctx, "recovered-capacity", now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(s.data.JTIs) != 1 {
		t.Fatal("expired capacity not recovered")
	}
}

func TestOAuthStoreCorruptionFailsClosed(t *testing.T) {
	for _, corruption := range []string{"malformed", "unknown-field", "trailing-data", "version", "secret", "missing-map", "record", "expiration", "client-binding"} {
		t.Run(corruption, func(t *testing.T) {
			s, now := newStoreFixture(t)
			if err := s.CreateAccessTokenSession(context.Background(), "access", storeFixtureRequest(now, "grant")); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(s.path)
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			switch corruption {
			case "malformed":
				data = []byte("{")
			case "unknown-field":
				raw["unexpected"] = true
				data, _ = json.Marshal(raw)
			case "trailing-data":
				data = append(data, []byte(" {}")...)
			case "version":
				raw["version"] = float64(500)
				data, _ = json.Marshal(raw)
			case "secret":
				raw["secret"] = "AA=="
				data, _ = json.Marshal(raw)
			case "missing-map":
				delete(raw, "access")
				data, _ = json.Marshal(raw)
			case "record":
				raw["access"].(map[string]interface{})["access"].(map[string]interface{})["request"].(map[string]interface{})["session"] = nil
				data, _ = json.Marshal(raw)
			case "expiration":
				raw["access"].(map[string]interface{})["access"].(map[string]interface{})["request"].(map[string]interface{})["session"].(map[string]interface{})["expires_at"] = map[string]interface{}{}
				data, _ = json.Marshal(raw)
			case "client-binding":
				raw["access"].(map[string]interface{})["access"].(map[string]interface{})["request"].(map[string]interface{})["client_id"] = "incorrect-client"
				data, _ = json.Marshal(raw)
			}
			if err := os.WriteFile(s.path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewOAuthStore(s.path, storeFixtureClient(), "fixture-owner-fingerprint"); err == nil {
				t.Fatal("corruption accepted")
			}
			if _, err := NewOAuthStore(s.path, storeFixtureClient(), "changed-binding"); err == nil && corruption != "client-binding" {
				t.Fatal("binding rotation concealed corruption")
			}
		})
	}
}

func TestOAuthStorePersistenceFailureLatchesClosed(t *testing.T) {
	s, now := newStoreFixture(t)
	ctx := context.Background()
	if err := s.CreateAccessTokenSession(ctx, "access", storeFixtureRequest(now, "grant")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAccessToken(ctx, "grant"); err == nil {
		t.Fatal("write failure hidden")
	}
	if _, err := s.GetAccessTokenSession(ctx, "access", nil); err == nil {
		t.Fatal("read succeeded after persistence failure")
	}
	if _, err := s.GetClient(ctx, storeFixtureClient().ID); err == nil {
		t.Fatal("client lookup succeeded after persistence failure")
	}
	if s.Secret() != nil || s.HasActiveGrant("fixture-owner", "grant", now) {
		t.Fatal("failed store still authorizes")
	}
	if err := s.CreateAccessTokenSession(ctx, "another", storeFixtureRequest(now, "grant")); err == nil {
		t.Fatal("write succeeded after persistence failure")
	}
}

func TestOAuthStoreRejectsUnsafeInitialization(t *testing.T) {
	for _, variant := range []string{"empty-path", "empty-binding", "nil-client", "confidential", "secret", "rotated-secret", "world-readable", "symlink"} {
		t.Run(variant, func(t *testing.T) {
			path, binding, client := filepath.Join(t.TempDir(), "oauth.json"), "binding", storeFixtureClient()
			switch variant {
			case "empty-path":
				path = ""
			case "empty-binding":
				binding = ""
			case "nil-client":
				client = nil
			case "confidential":
				client.Public = false
			case "secret":
				client.Secret = []byte("forbidden")
			case "rotated-secret":
				client.RotatedSecrets = [][]byte{[]byte("forbidden")}
			case "world-readable":
				if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("does-not-exist", path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewOAuthStore(path, client, binding); err == nil {
				t.Fatal("unsafe initialization accepted")
			}
		})
	}
}

func TestOAuthStoreRejectsUnboundedSessionsAndDuplicateKeys(t *testing.T) {
	s, now := newStoreFixture(t)
	ctx := context.Background()
	for _, exp := range []time.Time{{}, now, now.Add(-time.Minute), now.Add(32 * 24 * time.Hour)} {
		req := storeFixtureRequest(now, "grant")
		req.Session.SetExpiresAt(fosite.AccessToken, exp)
		if err := s.CreateAccessTokenSession(ctx, "invalid", req); err == nil {
			t.Fatal("invalid expiry accepted")
		}
	}
	req := storeFixtureRequest(now, "grant")
	if err := s.CreateAccessTokenSession(ctx, "valid", req); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccessTokenSession(ctx, "valid", req); err == nil {
		t.Fatal("duplicate replaced existing record")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	requireStoreError(t, s.CreateAccessTokenSession(canceled, "canceled", req), context.Canceled)
	_, err := s.GetAccessTokenSession(ctx, "canceled", nil)
	requireStoreError(t, err, fosite.ErrNotFound)
	if err := s.DeleteAccessTokenSession(ctx, "valid"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAccessTokenSession(ctx, "valid"); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthStoreConcurrentReadersAndWriters(t *testing.T) {
	s, now := newStoreFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("concurrent-%d", i)
			if err := s.CreateAccessTokenSession(ctx, id, storeFixtureRequest(now, id)); err != nil {
				t.Error(err)
				return
			}
			for j := 0; j < 10; j++ {
				loaded, err := s.GetAccessTokenSession(ctx, id, nil)
				if err != nil {
					t.Error(err)
					return
				}
				loaded.GetSession().(*fosite.DefaultSession).Extra["nested"].(map[string]interface{})["value"] = "local-change"
				if !s.HasActiveGrant("fixture-owner", id, now) {
					t.Error("grant missing")
				}
			}
		}(i)
	}
	wg.Wait()
}
