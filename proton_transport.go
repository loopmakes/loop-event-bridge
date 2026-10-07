package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
)

// This client never accepts a configurable API origin or follows a redirect to
// another host. Tokens are confined to Proton's official HTTPS API endpoint.
type protonTransport struct {
	base    http.RoundTripper
	session *protonSessionStore
	mu      sync.Mutex
	retryAt time.Time
}
type protonQuietLogger struct{}

func (protonQuietLogger) Errorf(string, ...interface{}) {}
func (protonQuietLogger) Warnf(string, ...interface{})  {}
func (protonQuietLogger) Debugf(string, ...interface{}) {}

type protonBudgetKey struct{}

func newProtonManager(appVersion string, session *protonSessionStore) (*proton.Manager, *protonTransport) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ResponseHeaderTimeout = 30 * time.Second
	transport := &protonTransport{base: base, session: session}
	manager := proton.New(proton.WithAppVersion(appVersion), proton.WithTransport(transport), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}), proton.WithDebug(false))
	return manager, transport
}
func (t *protonTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != "mail.proton.me" || request.URL.User != nil || !strings.HasPrefix(request.URL.Path, "/api/") {
		return nil, errors.New("Proton API origin refused")
	}
	if t.session != nil {
		if err := t.session.check(); err != nil {
			return nil, err
		}
	}
	recordProtonAuthResponse(request, 0)
	response, err := t.base.RoundTrip(request)
	if response != nil {
		recordProtonAuthResponse(request, response.StatusCode)
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			response.Body.Close()
			return nil, errors.New("Proton API redirect refused")
		}
		if response.StatusCode == 429 || response.StatusCode == 503 {
			delay := githubRetryDelay(response.Header, time.Now())
			t.mu.Lock()
			next := time.Now().Add(delay)
			if next.After(t.retryAt) {
				t.retryAt = next
			}
			t.mu.Unlock()
		}
		budget, _ := request.Context().Value(protonBudgetKey{}).(*atomic.Int64)
		response.Body = &protonBoundedBody{ReadCloser: response.Body, remaining: 8 << 20, budget: budget}
	}
	return response, err
}
func (t *protonTransport) minimumPoll() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return max(time.Until(t.retryAt), 0)
}
func (t *protonTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type protonBoundedBody struct {
	io.ReadCloser
	remaining int64
	budget    *atomic.Int64
}

func (b *protonBoundedBody) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return 0, errors.New("Proton response exceeds limit")
	}
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if b.budget != nil && b.budget.Add(int64(n)) > 64<<20 {
		return 0, errors.New("Proton poll response budget exceeded")
	}
	if b.remaining < 0 {
		return 0, errors.New("Proton response exceeds limit")
	}
	return n, err
}

func protonPollContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, protonBudgetKey{}, new(atomic.Int64))
}
