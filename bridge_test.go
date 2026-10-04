package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) *Bridge {
	t.Helper()
	s, e := openStore(filepath.Join(t.TempDir(), "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	return &Bridge{store: s, repo: "colthreepv/symmetro", author: "loopmakes", hosts: map[string]bool{"callback.example": true}, callbacks: &http.Client{}, verified: map[string]time.Time{}, auth: func(*http.Request) (string, error) { return "owner", nil }}
}
func testSecret() string {
	return "whsec_" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSubscriptionLifecycle(t *testing.T) {
	b := fixture(t)
	checks := 0
	b.callbacks.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		checks++
		raw, _ := io.ReadAll(r.Body)
		var challenge map[string]string
		_ = json.Unmarshal(raw, &challenge)
		if r.Header.Get("X-MCP-Subscription-Id") == "" {
			t.Error("missing subscription")
		}
		expected := signature(testSecret(), r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp"), raw)
		if r.Header.Get("webhook-signature") != expected {
			t.Error("wrong signature")
		}
		data, _ := json.Marshal(map[string]string{"challenge": challenge["challenge"]})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{}}, nil
	})
	p := subscriptionRequest{Name: "bridge.test", Arguments: Arguments{b.repo, b.author}, Delivery: Delivery{Mode: "webhook", URL: "https://callback.example/events", Secret: testSecret()}}
	raw, _ := json.Marshal(p)
	res, e := b.call(context.Background(), "owner", "events/subscribe", raw)
	if e != nil {
		t.Fatal(e)
	}
	id := res.(map[string]any)["id"].(string)
	_, e = b.call(context.Background(), "owner", "events/subscribe", raw)
	if e != nil || checks != 1 || len(b.store.state.Subscriptions) != 1 {
		t.Fatalf("idempotency/cache failed: %v", e)
	}
	if e := b.enqueueTest(); e != nil {
		t.Fatal(e)
	}
	if len(b.store.state.Queue) != 1 {
		t.Fatal("no queued event")
	}
	s, e2 := openStore(b.store.path)
	if e2 != nil || s.state.Subscriptions[id].ID != id || len(s.state.Queue) != 1 {
		t.Fatal("persistence failed")
	}
	_, e = b.call(context.Background(), "different-owner", "events/unsubscribe", raw)
	if e != nil || len(b.store.state.Subscriptions) != 1 {
		t.Fatal("owner isolation failed")
	}
	_, e = b.call(context.Background(), "owner", "events/unsubscribe", raw)
	if e != nil || len(b.store.state.Subscriptions) != 0 || len(b.store.state.Queue) != 0 {
		t.Fatal("unsubscribe failed")
	}
}
func TestBaselineDedupAndRestart(t *testing.T) {
	b := fixture(t)
	b.store.state.Subscriptions["s"] = Subscription{ID: "s", Name: "github.pull_request.changed", Arguments: Arguments{b.repo, b.author}, Expires: time.Now().Add(time.Hour)}
	o := []Observation{{Key: "pr/1", Fingerprint: "a", Timestamp: time.Now(), Data: map[string]any{"kind": "state"}}}
	if e := b.applyObservations(o); e != nil {
		t.Fatal(e)
	}
	if len(b.store.state.Queue) != 0 {
		t.Fatal("initial flood")
	}
	o[0].Fingerprint = "b"
	if e := b.applyObservations(o); e != nil {
		t.Fatal(e)
	}
	if len(b.store.state.Queue) != 1 {
		t.Fatal("change missing")
	}
	s, e := openStore(b.store.path)
	if e != nil {
		t.Fatal(e)
	}
	b.store = s
	if e := b.applyObservations(o); e != nil {
		t.Fatal(e)
	}
	if len(s.state.Queue) != 1 {
		t.Fatal("restart duplicate")
	}
}
func TestCallbackPolicy(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "100.64.0.1", "198.18.0.1", "2001:db8::1"} {
		if publicIP(netip.MustParseAddr(ip)) {
			t.Errorf("nonpublic address accepted %s", ip)
		}
	}
	if !publicIP(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address rejected")
	}
	for _, u := range []string{"http://callback.example/x", "https://callback.example:8443/x", "https://user@callback.example/x", "https://other.example/x"} {
		if validCallback(u, map[string]bool{"callback.example": true}) == nil {
			t.Errorf("invalid URL accepted %s", u)
		}
	}
}
func TestSigning(t *testing.T) {
	body := []byte(`{"a":1}`)
	m := hmac.New(sha256.New, []byte(strings.Repeat("x", 32)))
	m.Write([]byte("event.123."))
	m.Write(body)
	want := "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
	if signature(testSecret(), "event", "123", body) != want {
		t.Fatal("wrong Standard Webhooks signature")
	}
}
func TestTerminalDelivery(t *testing.T) {
	b := fixture(t)
	b.store.state.Subscriptions["s"] = Subscription{ID: "s", Name: "bridge.test", Expires: time.Now().Add(time.Hour), Delivery: Delivery{URL: "https://callback.example/e", Secret: testSecret()}}
	b.store.state.Queue = []Pending{{SubscriptionID: "s", Event: Event{ID: "e"}}}
	b.callbacks.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 410, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})
	b.deliverOne(context.Background())
	if !b.store.state.Queue[0].Dead || len(b.store.state.Subscriptions) != 0 {
		t.Fatal("410 not terminal")
	}
}
func TestDiscovery(t *testing.T) {
	b := fixture(t)
	r, q := transportFixture(t, "server/discover", nil)
	raw, _ := json.Marshal(q)
	r.Body = io.NopCloser(strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `2026-07-28`) {
		t.Fatal(w.Body.String())
	}
}

func TestStatePreservesLargeIdentifiers(t *testing.T) {
	b := fixture(t)
	b.store.mu.Lock()
	n := b.store.copy()
	n.Queue = []Pending{{Event: Event{ID: "large", Data: map[string]any{"id": int64(9007199254740993)}}}}
	if err := b.store.save(n); err != nil {
		t.Fatal(err)
	}
	b.store.mu.Unlock()
	s, err := openStore(b.store.path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s.copy().Queue[0].Event.Data)
	if !strings.Contains(string(raw), "9007199254740993") {
		t.Fatalf("identifier rounded: %s", raw)
	}
}
