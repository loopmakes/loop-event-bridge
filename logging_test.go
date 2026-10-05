package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func captureOperationalLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buffer)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buffer
}

func TestPollLifecycleLogging(t *testing.T) {
	logs := captureOperationalLogs(t)
	b := fixture(t)
	for _, id := range []string{"one", "two"} {
		b.store.state.Subscriptions[id] = Subscription{ID: id, Name: "github.notification.changed", Expires: time.Now().Add(time.Hour)}
	}
	title := "PRIVATE_NOTIFICATION_CONTENT"
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"id":42,"login":"loopmakes"}`
		if r.URL.Path == "/notifications" {
			body = `[{"id":"1","reason":"mention","unread":true,"updated_at":"2026-10-04T00:00:00Z","repository":{"full_name":"PRIVATE_REPOSITORY"},"subject":{"type":"Issue","title":"` + title + `"}}]`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	for _, want := range []string{
		"observed=1 changed=0 unchanged=0 baseline=1 enqueued=0",
		"observed=1 changed=0 unchanged=1 baseline=0 enqueued=0",
		"observed=1 changed=1 unchanged=0 baseline=0 enqueued=2",
	} {
		logs.Reset()
		delay, failures := b.pollOnce(context.Background(), client, "SECRET_GITHUB_TOKEN", 5*time.Minute, 2)
		if delay != 5*time.Minute || failures != 0 {
			t.Fatalf("unexpected schedule %s %d", delay, failures)
		}
		for _, field := range []string{"GitHub inbox poll started", "GitHub inbox poll complete", want, "duration=", "next_poll_in=5m0s"} {
			if !strings.Contains(logs.String(), field) {
				t.Errorf("missing %q in %s", field, logs)
			}
		}
		for _, secret := range []string{"PRIVATE_", "SECRET_GITHUB_TOKEN", "https://"} {
			if strings.Contains(logs.String(), secret) {
				t.Fatalf("sensitive value leaked: %s", logs)
			}
		}
		if strings.Contains(want, "unchanged=1") {
			title += "_CHANGED"
		}
	}
}

func TestPollFailureLoggingRedactsTransportAndPersistence(t *testing.T) {
	logs := captureOperationalLogs(t)
	b := fixture(t)
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("SECRET_TOKEN https://private.example/PRIVATE_BODY")
	})}
	delay, failures := b.pollOnce(context.Background(), client, "SECRET_TOKEN", time.Minute, 7)
	if failures != 8 || delay != 256*time.Second || !strings.Contains(logs.String(), "poll failed stage=fetch http_status=0") {
		t.Fatalf("bad error lifecycle: %s %s %d", logs, delay, failures)
	}
	client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"900"}}, Body: io.NopCloser(strings.NewReader("PRIVATE_BODY SECRET_TOKEN"))}, nil
	})
	delay, _ = b.pollOnce(context.Background(), client, "SECRET_TOKEN", time.Minute, 0)
	if delay != 15*time.Minute || !strings.Contains(logs.String(), "http_status=429 rate_limited=true failures=1") {
		t.Fatalf("rate limit not logged: %s", logs)
	}
	client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `[]`
		if r.URL.Path == "/user" {
			body = `{"id":42,"login":"loopmakes"}`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	if err := b.store.save(b.store.copy()); err != nil {
		t.Fatal(err)
	}
	b.store.path = filepath.Join(b.store.path, "PRIVATE_PATH", "state.json")
	b.pollOnce(context.Background(), client, "SECRET_TOKEN", time.Minute, 0)
	if !strings.Contains(logs.String(), "poll failed stage=persist") {
		t.Fatalf("missing persistence failure: %s", logs)
	}
	for _, secret := range []string{"PRIVATE_", "SECRET_TOKEN", "https://"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("sensitive value leaked: %s", logs)
		}
	}
}

func TestDeliveryLifecycleLogging(t *testing.T) {
	for _, tc := range []struct {
		status, attempts int
		outcome          string
	}{{204, 0, "success"}, {503, 0, "retry"}, {429, 0, "retry"}, {410, 0, "failed"}, {400, 0, "failed"}, {503, 7, "failed"}, {0, 0, "retry"}} {
		t.Run(tc.outcome+http.StatusText(tc.status), func(t *testing.T) {
			logs := captureOperationalLogs(t)
			b := fixture(t)
			b.store.state.Subscriptions["s"] = Subscription{ID: "s", Name: "bridge.test", Expires: time.Now().Add(time.Hour), Delivery: Delivery{URL: "https://callback.example/PRIVATE_CALLBACK", Secret: testSecret()}}
			b.store.state.Queue = []Pending{{SubscriptionID: "s", Attempts: tc.attempts, Event: Event{ID: "PRIVATE_EVENT_ID", Data: map[string]any{"title": "PRIVATE_NOTIFICATION"}}}}
			b.callbacks.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				if tc.status == 0 {
					return nil, errors.New("PRIVATE_TRANSPORT_ERROR")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("PRIVATE_RESPONSE"))}, nil
			})
			b.deliverOne(context.Background())
			for _, field := range []string{"webhook delivery outcome=" + tc.outcome, "http_status=", "attempt=", "duration=", "retry_in=", "state_saved=true", "pending=", "dead="} {
				if !strings.Contains(logs.String(), field) {
					t.Errorf("missing %s: %s", field, logs)
				}
			}
			for _, secret := range []string{"PRIVATE_", testSecret(), "https://"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatalf("sensitive value leaked: %s", logs)
				}
			}
		})
	}
}

func TestBuildIdentityLabels(t *testing.T) {
	for _, value := range []string{"", "https://private.example", "v1\nSECRET", strings.Repeat("x", 81)} {
		if got := safeBuildLabel(value, "unknown"); got != "unknown" {
			t.Fatalf("unsafe build value %q", got)
		}
	}
	if safeBuildLabel("v0.1.0-dirty", "unknown") != "v0.1.0-dirty" {
		t.Fatal("valid build label rejected")
	}
	version, revision := buildIdentity()
	if version == "" || revision == "" {
		t.Fatal("missing development metadata")
	}
}

func TestEmptyPollAndFailedSnapshotCounts(t *testing.T) {
	b := fixture(t)
	stats, err := b.applyObservationsCounted(nil, "42")
	if err != nil || stats != (pollStats{}) {
		t.Fatalf("empty baseline: %+v %v", stats, err)
	}
	b.store.state.Subscriptions["s"] = Subscription{Name: "github.notification.changed", Expires: time.Now().Add(time.Hour)}
	for i := 0; i < maxQueue; i++ {
		b.store.state.Queue = append(b.store.state.Queue, Pending{SubscriptionID: "s"})
	}
	stats, err = b.applyObservationsCounted([]Observation{{Key: "secret", Fingerprint: "new"}}, "42")
	if err == nil || stats != (pollStats{}) || len(b.store.state.Seen) != 0 {
		t.Fatalf("failed snapshot reported committed changes: %+v %v", stats, err)
	}
}

func TestDeliveryPersistenceFailureIsExplicit(t *testing.T) {
	logs := captureOperationalLogs(t)
	b := fixture(t)
	b.store.state.Subscriptions["s"] = Subscription{Name: "bridge.test", Expires: time.Now().Add(time.Hour), Delivery: Delivery{URL: "https://callback.example/secret", Secret: testSecret()}}
	b.store.state.Queue = []Pending{{SubscriptionID: "s", Event: Event{ID: "secret"}}}
	if err := b.store.save(b.store.copy()); err != nil {
		t.Fatal(err)
	}
	b.store.path = filepath.Join(b.store.path, "PRIVATE_PATH")
	b.callbacks.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})
	b.deliverOne(context.Background())
	if !strings.Contains(logs.String(), "outcome=success http_status=204") || !strings.Contains(logs.String(), "state_saved=false pending=1") || strings.Contains(logs.String(), "PRIVATE_PATH") {
		t.Fatalf("misleading persistence logging: %s", logs)
	}
}

func TestTestEventEnqueueLogging(t *testing.T) {
	logs := captureOperationalLogs(t)
	b := fixture(t)
	b.store.state.Subscriptions["secret"] = Subscription{Name: "bridge.test", Expires: time.Now().Add(time.Hour)}
	if err := b.enqueueTest(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "bridge test queued enqueued=1") || strings.Contains(logs.String(), "secret") {
		t.Fatalf("bad test queue logging: %s", logs)
	}
}
