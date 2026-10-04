package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in: npm ci --prefix tests/browser && npx --prefix tests/browser playwright install chromium
// LOOP_BROWSER_TEST=1 go test -run TestEmbeddedOAuthBrowser -v .
func TestEmbeddedOAuthBrowser(t *testing.T) {
	if os.Getenv("LOOP_BROWSER_TEST") != "1" {
		t.Skip("set LOOP_BROWSER_TEST=1 with Playwright Chromium installed")
	}
	for _, scenario := range []string{"old-policy", "success", "wrong-password", "expired-flow", "missing-cookie", "wrong-cookie", "foreign-origin", "null-origin"} {
		t.Run(scenario, func(t *testing.T) {
			type observation struct {
				Origin string
				Status int
			}
			posts := make(chan observation, 2)
			callbacks := make(chan *http.Request, 2)
			callback := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callbacks <- r.Clone(context.Background())
				_, _ = w.Write([]byte("Synthetic callback reached"))
			}))
			defer callback.Close()
			var oauth *EmbeddedOAuth
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "expired-flow" && r.Method == http.MethodPost {
					oauth.mu.Lock()
					for key, pending := range oauth.pending {
						pending.expires = time.Now().Add(-time.Second)
						oauth.pending[key] = pending
					}
					oauth.mu.Unlock()
				}
				recorder := httptest.NewRecorder()
				oauth.ServeHTTP(recorder, r)
				if scenario == "old-policy" {
					recorder.Header().Set("Referrer-Policy", "no-referrer")
				}
				for key, values := range recorder.Header() {
					w.Header()[key] = values
				}
				w.WriteHeader(recorder.Code)
				_, _ = w.Write(recorder.Body.Bytes())
				if r.Method == http.MethodPost {
					posts <- observation{r.Header.Get("Origin"), recorder.Code}
				}
			}))
			server.StartTLS()
			defer server.Close()
			dir := t.TempDir()
			config := EmbeddedOAuthConfig{PublicURL: server.URL, ClientID: "synthetic-browser-client", RedirectURI: callback.URL + "/callback", OwnerPasswordFile: filepath.Join(dir, "password"), StateFile: filepath.Join(dir, "state.json")}
			if err := os.WriteFile(config.OwnerPasswordFile, []byte(embeddedTestPassword), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			oauth, err = NewEmbeddedOAuth(config)
			if err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(map[string]string{"origin": server.URL, "query": embeddedTestQuery(config).Encode(), "callback": config.RedirectURI, "password": embeddedTestPassword, "scenario": scenario})
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "node", "tests/browser/consent.mjs")
			cmd.Env = append(os.Environ(), "LOOP_BROWSER_INPUT="+string(input))
			output, runErr := cmd.CombinedOutput()
			t.Logf("browser: %s", output)
			select {
			case got := <-posts:
				expectedOrigin, expectedStatus := server.URL, http.StatusForbidden
				if scenario == "old-policy" || scenario == "null-origin" {
					expectedOrigin = "null"
				}
				if scenario == "foreign-origin" {
					expectedOrigin = "https://foreign.example"
				}
				if scenario == "success" {
					expectedStatus = http.StatusSeeOther
				}
				t.Logf("server-observed Origin=%q status=%d", got.Origin, got.Status)
				if got.Origin != expectedOrigin || got.Status != expectedStatus {
					t.Errorf("wanted Origin=%q status=%d", expectedOrigin, expectedStatus)
				}
			default:
				t.Error("no native consent POST reached server")
			}
			if runErr != nil {
				t.Fatalf("browser failed: %v", runErr)
			}
			select {
			case request := <-callbacks:
				if scenario != "success" {
					t.Fatal("denied consent reached callback")
				}
				q := request.URL.Query()
				if q.Get("state") != "test-client-state-0123456789" || q.Get("iss") != server.URL || q.Get("code") == "" || q.Get("error") != "" {
					t.Fatal("invalid callback code/state/issuer")
				}
				if request.Referer() != "" {
					t.Fatal("cross-origin callback leaked referrer")
				}
				embeddedTestTokens(t, embeddedTestExchange(oauth, config, q.Get("code"), embeddedTestVerifier))
			default:
				if scenario == "success" {
					t.Fatal("browser did not follow callback redirect")
				}
			}
		})
	}
}
