package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	proton "github.com/ProtonMail/go-proton-api"
)

func TestProtonCredentialFilePrecedenceAndNoFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	os.WriteFile(path, []byte("file-secret\n"), 0400)
	secret, err := protonCredential("env-secret", path)
	if err != nil || string(secret) != "file-secret" {
		t.Fatalf("file precedence failed: %v", err)
	}
	clear(secret)
	if _, err = protonCredential("env-secret", path+"-missing"); err == nil || strings.Contains(err.Error(), path) {
		t.Fatal("missing file fallback or disclosure")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, []byte("\n"), 0600)
	if _, err = protonCredential("env-secret", path); err == nil {
		t.Fatal("empty file fell back to env")
	}
	secret, err = protonCredential(" password with spaces ", "")
	if err != nil || string(secret) != " password with spaces " {
		t.Fatal("environment password whitespace changed")
	}
	clear(secret)
}
func bootstrapProtonAdapter(t *testing.T) (*ProtonAdapter, *int) {
	t.Helper()
	store, path, key := protonTestStore(t)
	store.close()
	a, err := NewProtonAdapter(ProtonConfig{SessionFile: path, SessionKeyFile: key, AppVersion: "test@1", Username: "operator", Password: "synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	requests := new(int)
	transport := &protonTransport{session: a.session, base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		*requests++
		switch request.URL.Path {
		case "/api/core/v4/users":
			return protonTestResponse(request, 200, `{"Code":1000,"User":{"ID":"account"}}`), nil
		case "/api/core/v4/events/latest":
			return protonTestResponse(request, 200, `{"Code":1000,"EventID":"latest"}`), nil
		case "/api/mail/v4/messages":
			return protonTestResponse(request, 200, `{"Code":1000,"Messages":[],"Stale":0}`), nil
		case "/api/auth/v4":
			return protonTestResponse(request, 200, `{"Code":1000}`), nil
		default:
			t.Errorf("unexpected bootstrap route: %s", request.URL.Path)
			return protonTestResponse(request, 500, `{"Code":1}`), nil
		}
	})}
	a.manager = proton.New(proton.WithTransport(transport), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
	a.transport = transport
	return a, requests
}
func TestProtonAbsentSessionBootstrapsOnceAndStoresNoPassword(t *testing.T) {
	a, _ := bootstrapProtonAdapter(t)
	logins := 0
	a.login = func(_ context.Context, username string, password []byte) (*proton.Client, proton.Auth, error) {
		logins++
		if username != "operator" || string(password) != "synthetic-password" {
			t.Fatal("credentials changed")
		}
		return a.manager.NewClient("session", "access", "refresh"), proton.Auth{UserID: "account", UID: "session", RefreshToken: "refresh"}, nil
	}
	batch, err := a.Poll(context.Background(), "")
	if err != nil || !batch.Baseline || batch.AccountID != "account" || logins != 1 {
		t.Fatalf("bootstrap failed: %+v %v", batch, err)
	}
	saved, err := a.session.load()
	if err != nil || saved.LoginHash != protonUsernameHash("operator") || saved.AccountID != "account" {
		t.Fatalf("bootstrap session invalid: %v", err)
	}
	raw, _ := os.ReadFile(a.config.SessionFile)
	if bytes.Contains(raw, []byte("operator")) || bytes.Contains(raw, []byte("synthetic-password")) || a.config.Password != "" {
		t.Fatal("bootstrap credentials retained")
	}
}
func TestProtonBootstrapFailuresLatchWithoutRepeatedLogin(t *testing.T) {
	for _, mode := range []string{"wrongpassword", "totp", "fido", "humanverification"} {
		t.Run(mode, func(t *testing.T) {
			a, _ := bootstrapProtonAdapter(t)
			logins := 0
			a.login = func(context.Context, string, []byte) (*proton.Client, proton.Auth, error) {
				logins++
				if mode == "wrongpassword" || mode == "humanverification" {
					return nil, proton.Auth{}, errors.New("SECRET_UPSTREAM_DETAIL")
				}
				auth := proton.Auth{UserID: "account", UID: "session", RefreshToken: "refresh", TwoFA: proton.TwoFAInfo{Enabled: proton.HasTOTP}}
				if mode == "fido" {
					auth.TwoFA.Enabled = proton.HasFIDO2
				}
				return a.manager.NewClient("session", "access", "refresh"), auth, nil
			}
			for i := 0; i < 2; i++ {
				batch, err := a.Poll(context.Background(), "")
				var required *ProtonAuthRequiredError
				if !errors.As(err, &required) || batch.Cursor != "" || strings.Contains(err.Error(), "SECRET") {
					t.Fatalf("unsafe error: %+v %v", batch, err)
				}
			}
			if logins != 1 {
				t.Fatalf("login attempts %d", logins)
			}
			if _, err := os.Stat(a.config.SessionFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed bootstrap wrote a session")
			}
		})
	}
}
func TestProtonBootstrapCannotReplaceExistingSession(t *testing.T) {
	store, path, key := protonTestStore(t)
	store.close()
	original := []byte("corrupt-private-existing-session")
	os.WriteFile(path, original, 0600)
	_, err := NewProtonAdapter(ProtonConfig{SessionFile: path, SessionKeyFile: key, AppVersion: "test@1", Username: "operator", Password: "synthetic"})
	if err == nil {
		t.Fatal("corrupt session allowed bootstrap")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("existing session overwritten")
	}
}
func TestProtonSavedSessionIgnoresMissingPasswordFile(t *testing.T) {
	store, path, key := protonTestStore(t)
	store.save(protonSavedSession{AccountID: "account", UID: "session", RefreshToken: "refresh", LoginHash: protonUsernameHash("operator")})
	store.close()
	a, err := NewProtonAdapter(ProtonConfig{SessionFile: path, SessionKeyFile: key, AppVersion: "test@1", Username: "operator", PasswordFile: "/definitely-missing-password"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.bootstrapPending || a.accountID != "account" {
		t.Fatal("saved session did not supply identity")
	}
	saved, err := a.session.load()
	if err != nil {
		t.Fatal(err)
	}
	if err = protonCheckConfiguredUsername(a.config, saved); err != nil {
		t.Fatal(err)
	}
	// A mismatched configured username must fail without a password or login.
	changed := a.config
	changed.Username = "someone-else"
	if err = protonCheckConfiguredUsername(changed, saved); err == nil {
		t.Fatal("configured username silently changed account")
	}
}
func TestProtonBootstrapHonorsPriorCheckpointAccount(t *testing.T) {
	a, requests := bootstrapProtonAdapter(t)
	a.login = func(context.Context, string, []byte) (*proton.Client, proton.Auth, error) {
		return a.manager.NewClient("session", "access", "refresh"), proton.Auth{UserID: "account", UID: "session", RefreshToken: "refresh"}, nil
	}
	otherCursor := strings.Replace(protonTestCursor("old"), `"account"`, `"other-account"`, 1)
	batch, err := a.Poll(context.Background(), otherCursor)
	if err == nil || batch.Cursor != "" || *requests != 2 {
		t.Fatalf("wrong account event access: %+v %v requests=%d", batch, err, *requests)
	}
	if _, err = os.Stat(a.config.SessionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong account saved against prior checkpoint")
	}
}
