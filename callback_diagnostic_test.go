package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubscriptionCallbackDiagnostic(t *testing.T) {
	// These tests temporarily capture the process logger and must not run in parallel.
	var logs bytes.Buffer
	output, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() { log.SetOutput(output); log.SetFlags(flags); log.SetPrefix(prefix) })
	for _, tc := range []struct {
		name, url, host string
		hosts           map[string]bool
	}{
		{"empty allowlist", "https://callback.example/private-path?token=query-secret", "callback.example", nil},
		{"unlisted host", "https://other.example/private-path?token=query-secret", "other.example", map[string]bool{"callback.example": true}},
		{"userinfo and fragment", "https://private-user:private-password@callback.example/private-path?token=query-secret#private-fragment", "callback.example", nil},
		{"malformed escape", "https://callback.example/%zz-private-path?token=query-secret", "", nil},
		{"control character", "https://callback.example/\nprivate-path?token=query-secret", "", nil},
		{"relative URL", "/private-path?token=query-secret", "", nil},
		{"HTTPS still required", "http://callback.example/private-path?token=query-secret", "callback.example", map[string]bool{"callback.example": true}},
		{"port still restricted", "https://callback.example:8443/private-path?token=query-secret", "callback.example", map[string]bool{"callback.example": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := fixture(t)
			b.hosts = tc.hosts
			b.callbacks.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("denied callback contacted")
				return nil, errors.New("unexpected request")
			})
			for _, authenticated := range []bool{false, true} {
				logs.Reset()
				b.auth = func(r *http.Request) (string, error) {
					if !authenticated {
						return "", errors.New("denied")
					}
					return "owner", nil
				}
				r, q := transportFixture(t, "events/subscribe", map[string]any{"name": "bridge.test", "arguments": map[string]any{}, "delivery": Delivery{Mode: "webhook", URL: tc.url, Secret: testSecret()}})
				raw, err := json.Marshal(q)
				if err != nil {
					t.Fatal(err)
				}
				r.Body = io.NopCloser(bytes.NewReader(raw))
				r.Header.Set("Authorization", "Bearer header-secret")
				w := httptest.NewRecorder()
				b.ServeHTTP(w, r)
				if !authenticated {
					if w.Code != http.StatusUnauthorized || logs.Len() != 0 {
						t.Fatalf("unauthenticated diagnostic: status=%d logs=%q", w.Code, logs.String())
					}
					continue
				}
				want := fmt.Sprintf("events/subscribe callback denied: requestedHost=%q\n", tc.host)
				if logs.String() != want {
					t.Fatalf("diagnostic = %q, want %q", logs.String(), want)
				}
				var response struct {
					Error *rpcError `json:"error"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Error == nil || response.Error.Code != -32602 {
					t.Fatalf("callback not refused: %s", w.Body.String())
				}
				for _, secret := range []string{"private-path", "query-secret", "private-user", "private-password", "private-fragment", "header-secret", testSecret()} {
					if strings.Contains(logs.String()+w.Body.String(), secret) {
						t.Fatalf("secret leaked: %q", secret)
					}
				}
				if len(b.store.state.Subscriptions) != 0 {
					t.Fatal("denied subscription persisted")
				}
			}
		})
	}
}
