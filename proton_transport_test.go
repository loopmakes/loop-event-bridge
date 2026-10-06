package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProtonTransportRejectsOriginsAndRedirects(t *testing.T) {
	calls := 0
	transport := &protonTransport{base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return protonTestResponse(request, 302, ""), nil
	})}
	for _, url := range []string{"http://mail.proton.me/api/core/v4/users", "https://evil.example/api/core/v4/users", "https://mail.proton.me/not-api", "https://mail.proton.me:443/api/core/v4/users", "https://user:pass@mail.proton.me/api/core/v4/users"} {
		request, _ := http.NewRequest("GET", url, nil)
		if _, err := transport.RoundTrip(request); err == nil {
			t.Fatalf("accepted %s", url)
		}
	}
	if calls != 0 {
		t.Fatal("unsafe origin requested")
	}
	request, _ := http.NewRequest("GET", "https://mail.proton.me/api/core/v4/users", nil)
	if _, err := transport.RoundTrip(request); err == nil || calls != 1 {
		t.Fatal("redirect accepted")
	}
}
func TestProtonTransportRespectsRetryAfter(t *testing.T) {
	for _, value := range []string{"172800", "9223372036854775807", time.Now().Add(48 * time.Hour).UTC().Format(http.TimeFormat)} {
		transport := &protonTransport{base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			response := protonTestResponse(request, 429, `{"Code":1}`)
			response.Header.Set("Retry-After", value)
			return response, nil
		})}
		request, _ := http.NewRequest("GET", "https://mail.proton.me/api/core/v4/users", nil)
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if transport.minimumPoll() < 47*time.Hour {
			t.Fatalf("Retry-After shortened: %s", value)
		}
	}
}
func TestProtonBodyAndCumulativeBudgets(t *testing.T) {
	body := &protonBoundedBody{ReadCloser: io.NopCloser(strings.NewReader("12345")), remaining: 4}
	if _, err := io.ReadAll(body); err == nil {
		t.Fatal("response cap ignored")
	}
	budget := new(atomic.Int64)
	budget.Store(64<<20 - 3)
	body = &protonBoundedBody{ReadCloser: io.NopCloser(strings.NewReader("1234")), remaining: 10, budget: budget}
	if _, err := io.ReadAll(body); err == nil {
		t.Fatal("poll budget ignored")
	}
	ctx := protonPollContext(context.Background())
	if _, ok := ctx.Value(protonBudgetKey{}).(*atomic.Int64); !ok {
		t.Fatal("missing poll budget")
	}
}
func TestProtonTransportDoesNotUseFailedSession(t *testing.T) {
	store, _, _ := protonTestStore(t)
	store.failed = true
	called := false
	transport := &protonTransport{session: store, base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return protonTestResponse(request, 200, "{}"), nil
	})}
	request, _ := http.NewRequest("GET", "https://mail.proton.me/api/core/v4/users", nil)
	if _, err := transport.RoundTrip(request); err == nil || called {
		t.Fatal("used unpersisted credential")
	}
}
