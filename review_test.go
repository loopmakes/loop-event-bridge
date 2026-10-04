package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A receipt acknowledgement is the HTTP status, not an application response
// body. Body validation is required only for callback verification.
func TestReviewAcknowledgedDeliveryDoesNotDependOnResponseBody(t *testing.T) {
	b := fixture(t)
	b.store.state.Subscriptions["s"] = Subscription{ID: "s", Name: "bridge.test", Expires: time.Now().Add(time.Hour), Delivery: Delivery{URL: "https://callback.example/events", Secret: testSecret()}}
	b.store.state.Queue = []Pending{{SubscriptionID: "s", Event: Event{ID: "acknowledged"}}}
	b.callbacks.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 8193))), Header: http.Header{}}, nil
	})
	b.deliverOne(context.Background())
	if len(b.store.state.Queue) != 0 {
		t.Fatal("a received 2xx acknowledgement must remove the pending delivery")
	}
}

func TestReviewSubscriptionLifetimeStartsAfterVerification(t *testing.T) {
	b := fixture(t)
	b.callbacks.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond)
		body, _ := json.Marshal(map[string]string{"challenge": payload["challenge"]})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})
	p := subscriptionRequest{Name: "bridge.test", Arguments: Arguments{}, Delivery: Delivery{Mode: "webhook", URL: "https://callback.example/events", Secret: testSecret()}, TTL: json.RawMessage(`1000`)}
	raw, _ := json.Marshal(p)
	result, rpcErr := b.call(context.Background(), "owner", "events/subscribe", raw)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	id := result.(map[string]any)["id"].(string)
	if !b.store.state.Subscriptions[id].Expires.After(time.Now().Add(500 * time.Millisecond)) {
		t.Fatal("successful subscription must retain its granted lifetime after callback verification")
	}
}
