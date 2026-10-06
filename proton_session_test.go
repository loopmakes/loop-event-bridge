package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
	"golang.org/x/sys/unix"
)

func protonTestStore(t *testing.T) (*protonSessionStore, string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{0x73}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := openProtonSessionStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)
	return store, path, key
}
func TestProtonEncryptedSessionRoundTripAndLock(t *testing.T) {
	store, path, key := protonTestStore(t)
	original := protonSavedSession{AccountID: "account", UID: "session", RefreshToken: "SYNTHETIC_PRIVATE_REFRESH"}
	if err := store.save(original); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{original.AccountID, original.UID, original.RefreshToken} {
		if bytes.Contains(ciphertext, []byte(value)) {
			t.Fatal("plaintext session leaked")
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("nonprivate ciphertext")
	}
	loaded, err := store.load()
	if err != nil || loaded != original {
		t.Fatalf("roundtrip: %v %v", loaded, err)
	}
	if second, err := openProtonSessionStore(path, key); err == nil {
		second.close()
		t.Fatal("concurrent session writer accepted")
	}
	store.close()
	reopened, err := openProtonSessionStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if loaded, err = reopened.load(); err != nil || loaded != original {
		t.Fatal("restart lost session")
	}
}
func TestProtonSessionRejectsTamperAndWrongKey(t *testing.T) {
	for _, mode := range []string{"ciphertext", "nonce", "key", "plain", "permissions", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			store, path, key := protonTestStore(t)
			if err := store.save(protonSavedSession{AccountID: "account", UID: "session", RefreshToken: "token"}); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "key":
				store.close()
				os.WriteFile(key, bytes.Repeat([]byte{1}, 32), 0600)
				var err error
				store, err = openProtonSessionStore(path, key)
				if err != nil {
					t.Fatal(err)
				}
				defer store.close()
			case "ciphertext", "nonce":
				raw, _ := os.ReadFile(path)
				var envelope protonSessionEnvelope
				json.Unmarshal(raw, &envelope)
				if mode == "ciphertext" {
					envelope.Ciphertext[0] ^= 1
				} else {
					envelope.Nonce = []byte{1}
				}
				raw, _ = json.Marshal(envelope)
				os.WriteFile(path, raw, 0600)
			case "plain":
				os.WriteFile(path, []byte(`{"refresh_token":"token"}`), 0600)
			case "permissions":
				os.Chmod(path, 0644)
			case "symlink":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			}
			if _, err := store.load(); err == nil {
				t.Fatalf("accepted %s", mode)
			}
		})
	}
}
func TestProtonRejectsUnsafeSessionKeys(t *testing.T) {
	for _, mode := range []string{"short", "long", "public", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			key := filepath.Join(dir, "key")
			data := bytes.Repeat([]byte{1}, 32)
			if mode == "short" {
				data = data[:31]
			}
			if mode == "long" {
				data = append(data, 1)
			}
			os.WriteFile(key, data, 0600)
			if mode == "public" {
				os.Chmod(key, 0644)
			}
			if mode == "symlink" {
				os.Rename(key, key+".real")
				os.Symlink(key+".real", key)
			}
			if store, err := openProtonSessionStore(filepath.Join(dir, "session"), key); err == nil {
				store.close()
				t.Fatal("unsafe key accepted")
			}
		})
	}
}
func TestProtonPersistenceFailureLatchesClosed(t *testing.T) {
	store, path, _ := protonTestStore(t)
	session := protonSavedSession{AccountID: "account", UID: "session", RefreshToken: "token"}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.save(session); err == nil {
		t.Fatal("directory target accepted")
	}
	os.Remove(path)
	if err := store.save(session); err == nil {
		t.Fatal("retried after failed credential persistence")
	}
	if err := store.check(); err == nil {
		t.Fatal("session remains usable")
	}
}
func TestProtonAuthRequiresTerminalBeforeNetworkOrFiles(t *testing.T) {
	input, err := os.CreateTemp(t.TempDir(), "not-terminal")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	err = RunProtonAuth(context.Background(), ProtonConfig{SessionFile: "unused", SessionKeyFile: "unused-key", AppVersion: "test@1"}, input, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("unexpected CLI failure: %v", err)
	}
}
func TestProtonLoginErrorsAreSanitized(t *testing.T) {
	for _, code := range []proton.Code{proton.HumanVerificationRequired, proton.PaidPlanRequired, proton.AppVersionBadCode, proton.PasswordWrong} {
		err := protonLoginError(&proton.APIError{Code: code, Message: "PRIVATE_PASSWORD", Details: []byte("PRIVATE_TOKEN")})
		if strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("upstream secret leaked")
		}
	}
}

type protonRoundTripFunc func(*http.Request) (*http.Response, error)

func (f protonRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func protonTestResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Request: r, Header: http.Header{"Content-Type": []string{"application/json"}, "Date": []string{time.Now().UTC().Format(http.TimeFormat)}}, Body: io.NopCloser(strings.NewReader(body))}
}
func TestProtonSDKRefreshIsPersistedAndAccountVerified(t *testing.T) {
	store, _, _ := protonTestStore(t)
	if err := store.save(protonSavedSession{AccountID: "account", UID: "session", RefreshToken: "initial"}); err != nil {
		t.Fatal(err)
	}
	refreshes, users := 0, 0
	transport := &protonTransport{session: store, base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/api/auth/v4/refresh":
			refreshes++
			token := "rotated-first"
			if refreshes > 1 {
				token = "rotated-second"
			}
			return protonTestResponse(request, 200, `{"Code":1000,"UID":"session","UserID":"account","AccessToken":"synthetic-access","RefreshToken":"`+token+`"}`), nil
		case "/api/core/v4/users":
			users++
			if users == 1 {
				return protonTestResponse(request, 401, `{"Code":10013,"Error":"synthetic expired access"}`), nil
			}
			return protonTestResponse(request, 200, `{"Code":1000,"User":{"ID":"account"}}`), nil
		case "/api/core/v4/events/latest":
			return protonTestResponse(request, 200, `{"Code":1000,"EventID":"latest"}`), nil
		case "/api/mail/v4/messages":
			return protonTestResponse(request, 200, `{"Code":1000,"Messages":[],"Stale":0}`), nil
		default:
			t.Errorf("unexpected API route %s", request.URL.Path)
			return protonTestResponse(request, 500, `{"Code":1}`), nil
		}
	})}
	manager := proton.New(proton.WithTransport(transport), proton.WithAppVersion("test@1"), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
	a := &ProtonAdapter{config: ProtonConfig{AccountID: "account"}, session: store, manager: manager, transport: transport}
	defer a.Close()
	batch, err := a.Poll(context.Background(), "")
	if err != nil || batch.AccountID != "account" || !batch.Baseline {
		t.Fatalf("SDK mock integration: %+v %v", batch, err)
	}
	saved, err := store.load()
	if err != nil || saved.RefreshToken != "rotated-second" || refreshes != 2 {
		t.Fatalf("rotated session not persisted: %v %d", err, refreshes)
	}
}
func TestProtonSDKRejectsDifferentAccount(t *testing.T) {
	store, _, _ := protonTestStore(t)
	store.save(protonSavedSession{AccountID: "account", UID: "session", RefreshToken: "initial"})
	transport := &protonTransport{session: store, base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/refresh") {
			return protonTestResponse(request, 200, `{"Code":1000,"UID":"session","AccessToken":"access","RefreshToken":"rotated"}`), nil
		}
		return protonTestResponse(request, 200, `{"Code":1000,"User":{"ID":"other-account"}}`), nil
	})}
	manager := proton.New(proton.WithTransport(transport), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
	a := &ProtonAdapter{config: ProtonConfig{AccountID: "account"}, session: store, manager: manager, transport: transport}
	defer a.Close()
	if batch, err := a.Poll(context.Background(), ""); err == nil || batch.Cursor != "" {
		t.Fatal("rebound wrong account")
	}
}

func TestProtonPrivateInputsRejectFIFOsWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"key", "username", "password", "session"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), kind)
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if kind == "username" || kind == "password" {
					_, err := protonCredential("synthetic-env-fallback", path)
					done <- err
				} else {
					_, err := protonReadPrivate(path, 64<<10)
					done <- err
				}
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO accepted as private input")
				}
			case <-time.After(time.Second):
				t.Fatal("FIFO blocked source initialization")
			}
		})
	}
}
