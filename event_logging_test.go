package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEventCorrelationSurvivesRetryAndRestart(t *testing.T) {
	logs := captureOperationalLogs(t)
	b := fixture(t)
	subID := "PRIVATE_SUBSCRIPTION\nforged=true"
	b.store.state.Subscriptions[subID] = Subscription{ID: subID, Name: "github.notification.changed", Expires: time.Now().Add(time.Hour), Delivery: Delivery{URL: "https://callback.example/PRIVATE_CALLBACK", Secret: testSecret()}}
	if err := b.applyObservations(nil, "PRIVATE_ACCOUNT"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "event enqueued") {
		t.Fatal("baseline logged an enqueue")
	}
	observation := Observation{Key: "PRIVATE_NOTIFICATION", Fingerprint: "v1", Timestamp: time.Now().UTC(), Data: map[string]any{"title": "PRIVATE_TITLE", "unread": true, "PRIVATE_KEY\nforged=true": "PRIVATE_VALUE"}}
	if err := b.applyObservations([]Observation{observation}, "PRIVATE_ACCOUNT"); err != nil {
		t.Fatal(err)
	}
	eventID := b.store.state.Queue[0].Event.ID
	var bodies []string
	b.callbacks.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		bodies = append(bodies, string(body))
		if request.Header.Get("webhook-id") != eventID {
			t.Error("correlation ID differs from actual webhook ID")
		}
		status := 503
		if len(bodies) == 2 {
			status = 204
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json; secret=PRIVATE_PARAMETER"}}, Body: io.NopCloser(strings.NewReader("PRIVATE_RESPONSE"))}, nil
	})
	b.deliverOne(context.Background())
	if len(b.store.state.Queue) != 1 || b.store.state.Queue[0].Attempts != 1 {
		t.Fatal("retry was not persisted")
	}
	var err error
	b.store, err = openStore(b.store.path)
	if err != nil {
		t.Fatal(err)
	}
	b.store.state.Queue[0].Next = time.Time{}
	b.deliverOne(context.Background())
	if len(b.store.state.Queue) != 0 || len(bodies) != 2 || bodies[0] != bodies[1] {
		t.Fatal("observability changed retry or acknowledgment behavior")
	}
	if got := strings.Count(logs.String(), "event_id="+eventID); got != 5 {
		t.Fatalf("want enqueue and two start/result pairs, got %d: %s", got, logs)
	}
	if got := strings.Count(logs.String(), "subscription_ref="+subscriptionLogRef(subID)); got != 5 {
		t.Fatalf("subscription correlation changed: %s", logs)
	}
	for _, field := range []string{"event_name=github.notification.changed source=github", "data_fields=title,unread other_data_fields=1", "transport_ack=false", "transport_ack=true", "response_content_type=application/json response_bytes=16 response_complete=true error_class=none", "attempt=2", "payload_encoded=true envelope_fields=eventId,name,timestamp,data,cursor"} {
		if !strings.Contains(logs.String(), field) {
			t.Errorf("missing %q: %s", field, logs)
		}
	}
	for _, forbidden := range []string{"PRIVATE_", "forged=true", "https://", testSecret()} {
		if strings.Contains(logs.String(), forbidden) {
			t.Errorf("unsafe value in operational logs: %s", logs)
		}
	}
}

func TestEventEnqueueCorrelationAcrossSourcesAndSubscriptions(t *testing.T) {
	for _, name := range []string{"bridge.test", "github.notification.changed", "gitlab.todo.changed", "proton.mail.received"} {
		t.Run(name, func(t *testing.T) {
			logs := captureOperationalLogs(t)
			b := fixture(t)
			for _, id := range []string{"one", "two"} {
				b.store.state.Subscriptions[id] = Subscription{Name: name, Expires: time.Now().Add(time.Hour)}
			}
			observation := Observation{Key: "PRIVATE_KEY", Fingerprint: "first", Timestamp: time.Now(), Data: map[string]any{"title": "PRIVATE_VALUE"}}
			switch name {
			case "bridge.test":
				if err := b.enqueueTest(); err != nil {
					t.Fatal(err)
				}
			case "github.notification.changed":
				if err := b.applyObservations(nil, "PRIVATE_ACCOUNT"); err != nil {
					t.Fatal(err)
				}
				if err := b.applyObservations([]Observation{observation}, "PRIVATE_ACCOUNT"); err != nil {
					t.Fatal(err)
				}
			default:
				_, sourceName := eventLogLabels(name)
				source := sourceConfig{Name: sourceName, Namespace: sourceName, EventName: name}
				if _, err := b.applySourceBatch(source, SourceBatch{AccountID: "PRIVATE_ACCOUNT"}); err != nil {
					t.Fatal(err)
				}
				if _, err := b.applySourceBatch(source, SourceBatch{AccountID: "PRIVATE_ACCOUNT", Observations: []Observation{observation}}); err != nil {
					t.Fatal(err)
				}
			}
			if len(b.store.state.Queue) != 2 || strings.Count(logs.String(), "event enqueued") != 2 {
				t.Fatalf("missing durable enqueue correlation: %s", logs)
			}
			for _, pending := range b.store.state.Queue {
				if !strings.Contains(logs.String(), "event_id="+pending.Event.ID+" event_name="+name) || !strings.Contains(logs.String(), "subscription_ref="+subscriptionLogRef(pending.SubscriptionID)) {
					t.Fatalf("missing entry correlation: %s", logs)
				}
			}
			if name != "bridge.test" && b.store.state.Queue[0].Event.ID != b.store.state.Queue[1].Event.ID {
				t.Fatal("one observation should retain one event ID across subscribers")
			}
			if strings.Contains(logs.String(), "PRIVATE_") {
				t.Fatalf("source content leaked: %s", logs)
			}
		})
	}
}

func TestFailedPersistenceDoesNotClaimEnqueue(t *testing.T) {
	for _, kind := range []string{"test", "github", "source"} {
		t.Run(kind, func(t *testing.T) {
			logs := captureOperationalLogs(t)
			b := fixture(t)
			b.store.state.Subscriptions["s"] = Subscription{Name: "bridge.test", Expires: time.Now().Add(time.Hour)}
			if err := b.store.save(b.store.copy()); err != nil {
				t.Fatal(err)
			}
			b.store.path = filepath.Join(b.store.path, "PRIVATE_PATH")
			observation := Observation{Key: "PRIVATE_KEY", Fingerprint: "first", Timestamp: time.Now(), Data: map[string]any{"title": "PRIVATE_VALUE"}}
			var err error
			switch kind {
			case "test":
				err = b.enqueueTest()
			case "github":
				b.store.state.Subscriptions["s"] = Subscription{Name: "github.notification.changed", Expires: time.Now().Add(time.Hour)}
				b.store.state.Baselines["notifications/PRIVATE_ACCOUNT"] = true
				err = b.applyObservations([]Observation{observation}, "PRIVATE_ACCOUNT")
			case "source":
				b.store.state.Subscriptions["s"] = Subscription{Name: "gitlab.todo.changed", Expires: time.Now().Add(time.Hour)}
				b.store.state.Sources = map[string]SourceState{"gitlab": {AccountID: "PRIVATE_ACCOUNT", Baseline: true}}
				_, err = b.applySourceBatch(sourceConfig{Name: "gitlab", Namespace: "gitlab", EventName: "gitlab.todo.changed"}, SourceBatch{AccountID: "PRIVATE_ACCOUNT", Observations: []Observation{observation}})
			}
			if err == nil || strings.Contains(logs.String(), "event enqueued") || strings.Contains(logs.String(), "PRIVATE_") {
				t.Fatalf("failed save claimed enqueue or leaked error: %s", logs)
			}
		})
	}
}

func TestEventLabelsRejectLogInjection(t *testing.T) {
	for _, id := range []string{"", "PRIVATE_ID\nforged=true", "evt_" + strings.Repeat("x", 48), "evt_" + strings.Repeat("a", 49)} {
		got := eventLogID(id)
		if !strings.HasPrefix(got, "event_sha256_") || strings.ContainsAny(got, "\r\n\t") || strings.Contains(got, "PRIVATE") {
			t.Fatalf("unsafe ID label %q", got)
		}
	}
	id := "evt_" + strings.Repeat("a", 48)
	if eventLogID(id) != id || eventLogID("one") == eventLogID("two") || subscriptionLogRef("one") == subscriptionLogRef("two") {
		t.Fatal("correlation labels are not stable/distinct")
	}
	name, source := eventLogLabels("PRIVATE_NAME\nforged=true")
	if name != "unknown" || source != "unknown" {
		t.Fatal("unknown event name leaked")
	}
}

func TestEventDiscoveryLogsOnlyAdvertisedAllowlistedNames(t *testing.T) {
	logs := captureOperationalLogs(t)
	b := fixture(t)
	b.githubDisabled = true
	b.sources = []sourceConfig{{Name: "proton", EventName: "proton.mail.received"}}
	var workers sync.WaitGroup
	for range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			result, err := b.call(context.Background(), "PRIVATE_OWNER", "events/list", json.RawMessage(`{}`))
			if err != nil || len(result.(map[string]any)["events"].([]any)) != 2 {
				t.Error("discovery behavior changed")
			}
		}()
	}
	workers.Wait()
	if strings.Count(logs.String(), "event discovery") != 1 || !strings.Contains(logs.String(), "event_count=2 event_names=bridge.test,proton.mail.received suppressed_since_last=0") {
		t.Fatalf("unbounded or inaccurate discovery logs: %s", logs)
	}
	b.discoveryLastLog = time.Now().Add(-time.Minute)
	b.call(context.Background(), "PRIVATE_OWNER", "events/list", nil)
	if !strings.Contains(logs.String(), "suppressed_since_last=19") {
		t.Fatal("suppressed discovery count missing")
	}
	b.githubDisabled = false
	b.call(context.Background(), "PRIVATE_OWNER", "events/list", nil)
	if !strings.Contains(logs.String(), "event_count=3 event_names=bridge.test,github.notification.changed,proton.mail.received") {
		t.Fatal("changed advertised set not logged immediately")
	}
	b.logEventDiscovery([]any{map[string]any{"name": "PRIVATE_NAME\nforged=true"}})
	if strings.Contains(logs.String(), "PRIVATE_") || strings.Contains(logs.String(), "forged=true") {
		t.Fatalf("untrusted discovery data leaked: %s", logs)
	}
}

func TestSubscriptionCorrelationLogsOnlyPersistedActions(t *testing.T) {
	logs := captureOperationalLogs(t)
	b := fixture(t)
	b.callbacks.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var challenge map[string]string
		if err := json.NewDecoder(request.Body).Decode(&challenge); err != nil {
			t.Fatal(err)
		}
		response, _ := json.Marshal(map[string]string{"challenge": challenge["challenge"]})
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(response)))}, nil
	})
	params, _ := json.Marshal(subscriptionRequest{Name: "bridge.test", Delivery: Delivery{Mode: "webhook", URL: "https://callback.example/PRIVATE_PATH?token=PRIVATE_QUERY", Secret: testSecret()}})
	result, err := b.call(context.Background(), "PRIVATE_OWNER\nforged=true", "events/subscribe", params)
	if err != nil {
		t.Fatal(err)
	}
	id := result.(map[string]any)["id"].(string)
	for _, method := range []string{"events/subscribe", "events/unsubscribe"} {
		if _, err := b.call(context.Background(), "PRIVATE_OWNER\nforged=true", method, params); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(logs.String(), "subscription_ref="+subscriptionLogRef(id)) != 3 {
		t.Fatalf("subscription lifecycle lost correlation: %s", logs)
	}
	for _, field := range []string{"action=subscribe event_name=bridge.test source=bridge", "refreshed=false", "refreshed=true", "expires_at=", "action=unsubscribe", "state_saved=true"} {
		if !strings.Contains(logs.String(), field) {
			t.Errorf("missing %q: %s", field, logs)
		}
	}
	for _, forbidden := range []string{"PRIVATE_", "forged=true", id, testSecret(), "https://"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Errorf("subscription content leaked: %s", logs)
		}
	}
	logs.Reset()
	b.store.path = filepath.Join(b.store.path, "PRIVATE_PATH")
	for _, method := range []string{"events/subscribe", "events/unsubscribe"} {
		if _, err := b.call(context.Background(), "PRIVATE_OWNER\nforged=true", method, params); err == nil {
			t.Fatal("failed persistence succeeded")
		}
	}
	if logs.Len() != 0 {
		t.Fatalf("failed subscription save claimed success: %s", logs)
	}
}

func TestCallbackDiagnosticsAreBoundedAndContentFree(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body, wantType, wantClass string
		transportFailure, readFailure                bool
		wantBytes                                    int
		wantComplete                                 bool
	}{
		{name: "json parameters", contentType: "application/json; token=PRIVATE_PARAMETER", body: "PRIVATE_BODY", wantType: "application/json", wantClass: "none", wantBytes: 12, wantComplete: true},
		{name: "unknown", contentType: "application/PRIVATE_TYPE", wantType: "other", wantClass: "none", wantComplete: true},
		{name: "invalid", contentType: "text/plain\nPRIVATE_HEADER", wantType: "invalid", wantClass: "none", wantComplete: true},
		{name: "missing", wantType: "none", wantClass: "none", wantComplete: true},
		{name: "oversize", body: strings.Repeat("x", 9000), wantType: "none", wantClass: "response_invalid", wantBytes: 8193},
		{name: "transport failure", transportFailure: true, wantType: "none", wantClass: "request_failed"},
		{name: "read failure", readFailure: true, wantType: "none", wantClass: "response_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureOperationalLogs(t)
			b := fixture(t)
			b.store.state.Subscriptions["PRIVATE_SUB"] = Subscription{ID: "s", Name: "bridge.test", Expires: time.Now().Add(time.Hour), Delivery: Delivery{URL: "https://callback.example/PRIVATE_CALLBACK", Secret: testSecret()}}
			b.store.state.Queue = []Pending{{SubscriptionID: "PRIVATE_SUB", Event: Event{ID: "PRIVATE_ID", Name: "bridge.test"}}}
			b.callbacks.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				if tc.transportFailure {
					return nil, errors.New("PRIVATE_TRANSPORT_ERROR")
				}
				var body io.ReadCloser = io.NopCloser(strings.NewReader(tc.body))
				if tc.readFailure {
					body = io.NopCloser(diagnosticErrorReader{})
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{tc.contentType}}, Body: body}, nil
			})
			b.deliverOne(context.Background())
			if strings.Contains(logs.String(), "PRIVATE_") || strings.Contains(logs.String(), testSecret()) {
				t.Fatalf("diagnostic leaked content: %s", logs)
			}
			if !strings.Contains(logs.String(), "response_content_type="+tc.wantType) || !strings.Contains(logs.String(), "error_class="+tc.wantClass) {
				t.Fatalf("missing safe classifications: %s", logs)
			}
			if !strings.Contains(logs.String(), fmt.Sprintf("response_bytes=%d response_complete=%t", tc.wantBytes, tc.wantComplete)) {
				t.Fatalf("inaccurate bounded response observation: %s", logs)
			}
			if tc.transportFailure && len(b.store.state.Queue) != 1 || !tc.transportFailure && len(b.store.state.Queue) != 0 {
				t.Fatal("diagnostics changed 2xx acknowledgment semantics")
			}
		})
	}
}

type diagnosticErrorReader struct{}

func (diagnosticErrorReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_READ_ERROR") }
