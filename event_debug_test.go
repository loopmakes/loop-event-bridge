package main

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

func readEventDebugRecord(t *testing.T, logs string) (eventDebugRecord, eventDebugEnvelope, string) {
	t.Helper()
	const marker = "event debug "
	index := strings.Index(logs, marker)
	if index < 0 {
		t.Fatal("event debug record missing")
	}
	line := strings.SplitN(logs[index:], "\n", 2)[0]
	if len(line) > eventDebugMaxBytes {
		t.Fatalf("event debug exceeds message bound: %d", len(line))
	}
	if strings.ContainsFunc(line, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
	}) {
		t.Fatal("raw control character or line separator in log")
	}
	var record eventDebugRecord
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, marker)), &record); err != nil {
		t.Fatalf("event debug is not valid JSON: %v", err)
	}
	var envelope eventDebugEnvelope
	if len(record.Event) > 0 {
		if err := json.Unmarshal(record.Event, &envelope); err != nil {
			t.Fatalf("event envelope is not valid JSON: %v", err)
		}
		if record.SanitizedBytes != len(record.Event) {
			t.Fatalf("incorrect sanitized byte length: %d != %d", record.SanitizedBytes, len(record.Event))
		}
	}
	return record, envelope, line
}

func sampleDebugEvent(name string, data map[string]any) Event {
	return Event{ID: "evt_" + strings.Repeat("a", 48), Name: name, Timestamp: time.Date(2026, 10, 7, 7, 0, 0, 123, time.UTC), Data: data}
}

func TestEventDebugDefaultOff(t *testing.T) {
	logs := captureOperationalLogs(t)
	b := &Bridge{}
	b.logEventDebug(sampleDebugEvent("github.notification.changed", map[string]any{"title": "SYNTHETIC_CONTENT"}), "subscription")
	if logs.Len() != 0 {
		t.Fatal("default bridge must not log event content")
	}
}

func TestEventDebugKnownEvents(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		data         map[string]any
	}{
		{"bridge.test", "bridge", map[string]any{"message": "Operator-triggered bridge connectivity test"}},
		{"github.notification.changed", "github", map[string]any{
			"kind": "notification", "account_login": "operator", "account_id": "42", "notification_id": "123",
			"repository": "owner/project", "subject_type": "PullRequest", "title": "Fix delivery diagnostics", "reason": "review_requested", "unread": false,
			"updated_at": "2026-10-07T07:00:00Z", "last_read_at": nil, "api_url": "https://api.github.com/notifications/threads/123",
			"subject_api_url": "https://api.github.com/repos/owner/project/pulls/7", "latest_comment_api_url": "https://api.github.com/repos/owner/project/issues/comments/8", "url": "https://github.com/owner/project/pull/7",
		}},
		{"gitlab.todo.changed", "gitlab", map[string]any{
			"kind": "todo", "account_id": "42", "todo_id": "123", "account_username": "operator", "project": "owner/project", "target_type": "MergeRequest",
			"title": "Review delivery", "action": "mentioned", "state": "pending", "created_at": "2026-10-07T06:00:00Z", "updated_at": "2026-10-07T07:00:00Z",
			"instance_url": "https://gitlab.example", "url": "https://gitlab.example/owner/project/-/merge_requests/7",
		}},
		{"proton.mail.received", "proton", map[string]any{"message_id": "synthetic-message-id", "received_at": "2026-10-07T07:00:00Z"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureOperationalLogs(t)
			b := &Bridge{eventDebug: true}
			event := sampleDebugEvent(tc.name, tc.data)
			b.logEventDebug(event, "synthetic-subscription")
			record, envelope, _ := readEventDebugRecord(t, logs.String())
			if record.EventID != event.ID || record.EventName != tc.name || record.Source != tc.source || record.Subscription != subscriptionLogRef("synthetic-subscription") || record.Truncated || record.OmittedFields != 0 || record.OmittedCursor {
				t.Fatalf("wrong correlation or inclusion: %+v", record)
			}
			if envelope.ID != event.ID || envelope.Name != tc.name || envelope.Timestamp != event.Timestamp.Format(time.RFC3339Nano) || string(envelope.Cursor) != "null" || !reflect.DeepEqual(envelope.Data, tc.data) {
				t.Fatalf("known event metadata changed: %+v", envelope)
			}
		})
	}
}

type eventDebugPanicMarshaler struct{}

func (eventDebugPanicMarshaler) MarshalJSON() ([]byte, error) { panic("must not inspect nested data") }

func TestEventDebugExcludesUnknownAndNestedValues(t *testing.T) {
	logs := captureOperationalLogs(t)
	data := map[string]any{
		"title": map[string]any{"token": "NESTED_SECRET"}, "repository": []any{"NESTED_SECRET"},
		"reason": eventDebugPanicMarshaler{}, "account_id": 42, "notification_id": json.Number("123"),
		"unread": "true", "api_url": map[string]any{"url": "https://secret.example"},
		"authorization": "Bearer AUTH_SECRET", "signature": "SIGNATURE_SECRET", "callback_url": "https://callback.example/CALLBACK_SECRET",
		"UNKNOWN_SECRET_KEY": "UNKNOWN_SECRET_VALUE", "response_body": "RESPONSE_SECRET", "cursor": "CURSOR_SECRET",
		"subject_type": (*string)(nil), "updated_at": time.Now(), "last_read_at": eventDebugPanicMarshaler{},
	}
	event := sampleDebugEvent("github.notification.changed", data)
	event.Cursor = eventDebugPanicMarshaler{}
	(&Bridge{eventDebug: true}).logEventDebug(event, "SYNTHETIC_RAW_SUBSCRIPTION")
	record, envelope, _ := readEventDebugRecord(t, logs.String())
	if len(envelope.Data) != 0 || record.OmittedFields != len(data) || !record.OmittedCursor || len(envelope.Cursor) != 0 {
		t.Fatalf("unexpected invalid-field inclusion: %+v %+v", record, envelope)
	}
	for _, forbidden := range []string{"SECRET", "Bearer", "signature", "callback_url", "response_body", "SYNTHETIC_RAW_SUBSCRIPTION", "https://"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("forbidden content in diagnostic: %s", forbidden)
		}
	}
}

func TestEventDebugExpectedPrimitiveTypes(t *testing.T) {
	for _, value := range []any{true, false, 1, int64(1), 1.0, math.NaN(), json.Number("123"), nil, []string{"text"}, []byte("text"), map[string]any{"token": "secret"}, eventDebugPanicMarshaler{}} {
		data, omitted := eventDebugData(sampleDebugEvent("bridge.test", map[string]any{"message": value}))
		if len(data) != 0 || omitted != 1 {
			t.Fatalf("non-string message accepted (%T)", value)
		}
	}
	for _, value := range []any{"false", 0, nil, []bool{false}, map[string]any{"value": true}} {
		data, omitted := eventDebugData(sampleDebugEvent("github.notification.changed", map[string]any{"unread": value}))
		if len(data) != 0 || omitted != 1 {
			t.Fatalf("non-boolean unread accepted (%T)", value)
		}
	}
	for _, value := range []any{nil, "2026-10-07T07:00:00Z"} {
		data, omitted := eventDebugData(sampleDebugEvent("github.notification.changed", map[string]any{"last_read_at": value}))
		if !reflect.DeepEqual(data["last_read_at"], value) || len(data) != 1 || omitted != 0 {
			t.Fatal("last_read_at string/null was not retained")
		}
	}
}

func TestEventDebugUnknownEventAndInvalidEnvelope(t *testing.T) {
	logs := captureOperationalLogs(t)
	event := sampleDebugEvent("UNKNOWN_SECRET_EVENT\nforged", map[string]any{"title": "UNKNOWN_SECRET_CONTENT"})
	event.ID = "SECRET_EVENT_ID\nforged"
	event.Timestamp = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	(&Bridge{eventDebug: true}).logEventDebug(event, "SECRET_SUBSCRIPTION\nforged")
	record, envelope, _ := readEventDebugRecord(t, logs.String())
	if record.EventID != eventLogID(event.ID) || record.EventName != "unknown" || record.Source != "unknown" || envelope.Name != "unknown" || envelope.Timestamp != "" || len(envelope.Data) != 0 || record.OmittedFields != 1 {
		t.Fatalf("unknown envelope was not sanitized: %+v %+v", record, envelope)
	}
	if strings.Contains(logs.String(), "SECRET") || strings.Contains(logs.String(), "forged") {
		t.Fatal("unknown envelope leaked raw strings")
	}
}

func TestEventDebugURL(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://api.example/path", "https://api.example/path"},
		{"https://user:PASSWORD@api.example/path?token=QUERY_SECRET#FRAGMENT_SECRET", "https://api.example/path"},
		{"https://api.example:8443/path?", "https://api.example:8443/path"},
		{"http://api.example/path?q=x#f", "http://api.example/path"},
		{"https://[2001:db8::1]/path", "https://[2001:db8::1]/path"},
		{"https://api.example/encoded%20space", "https://api.example/encoded%20space"},
		{"", ""}, {"/path", ""}, {"//api.example/path", ""}, {"https:///path", ""}, {"https://", ""},
		{"https:opaque", ""}, {"ftp://api.example/password", ""}, {"javascript:SECRET", ""}, {"data:SECRET", ""},
		{"https://api.example/\\SECRET", ""}, {"https://api.example/%5cSECRET", ""}, {"https://api.example/%0aSECRET", ""},
		{"https://api.example/%7fSECRET", ""}, {"https://api.example/%C2%85SECRET", ""}, {"https://api.example/%zz", ""},
		{"https://api.example/%E2%80%AESECRET", ""}, {"https://api.example/a\u202eSECRET", ""},
		{"https://api.example/a\nSECRET", ""}, {"https://api.example/a\rSECRET", ""}, {"https://api.example/a\tSECRET", ""},
		{"https://api.example/a\x00SECRET", ""}, {"https://api.example/a\x7fSECRET", ""}, {"https://api.example/a\u0085SECRET", ""},
		{" https://api.example/path", ""}, {"https://api.example/a b", ""}, {"https://api.example/\xff", ""},
		{"https://api.example:bad/path", ""}, {"https://user%zz:pass@api.example/path", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := eventDebugURL(tc.input)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("unexpected URL sanitation: %q %t", got, ok)
			}
		})
	}
}

func TestEventDebugSanitizesURLsAndEscapesControls(t *testing.T) {
	logs := captureOperationalLogs(t)
	title := "Fix delivery\nnext\r\t\x1b[31m\x7f\u0085\u009b\u2028\u2029\u202e\U000e0001 https://user:PASSWORD@example.test/PATH_SECRET?token=QUERY_SECRET#FRAGMENT_SECRET"
	event := sampleDebugEvent("github.notification.changed", map[string]any{
		"title": title, "repository": "owner/project", "reason": "mention",
		"api_url":         "https://user:PASSWORD@api.example/path?token=QUERY_SECRET#FRAGMENT_SECRET",
		"subject_api_url": "https://api.example/%0aURL_SECRET",
	})
	(&Bridge{eventDebug: true}).logEventDebug(event, "subscription")
	record, envelope, _ := readEventDebugRecord(t, logs.String())
	if record.OmittedFields != 1 || envelope.Data["title"] != eventDebugText(title) || envelope.Data["api_url"] != "https://api.example/path" {
		t.Fatalf("expected sanitized metadata: %+v", envelope)
	}
	if strings.Count(logs.String(), "\n") != 1 {
		t.Fatal("one event must produce exactly one log line")
	}
	for _, forbidden := range []string{"PASSWORD", "PATH_SECRET", "QUERY_SECRET", "FRAGMENT_SECRET", "URL_SECRET"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("URL content leaked: %s", forbidden)
		}
	}
	for _, value := range []string{"HTTP://example.test/secret", "git+ssh://user:secret@example.test/repo", "www.example.test/secret", "mailto:secret@example.test", "data:text/plain,secret", "javascript:secret"} {
		if got := eventDebugText("before " + value + " after"); got != "before [URL omitted] after" {
			t.Fatalf("URL-like text not omitted: %q", got)
		}
	}
	// A diagnostic preserves actual text; it cannot recognize arbitrary secrets.
	if eventDebugText("ordinary text with arbitrary-string") != "ordinary text with arbitrary-string" {
		t.Fatal("unexpected free-text transformation")
	}
}

func TestEventDebugBoundedValidJSON(t *testing.T) {
	for _, text := range []string{"x", "é🎉", "\n\r\t\x00\x1b", "\u0085\u202e\U000e0001", "\\\"<>&"} {
		t.Run(text, func(t *testing.T) {
			logs := captureOperationalLogs(t)
			event := sampleDebugEvent("github.notification.changed", map[string]any{"title": strings.Repeat(text, 50000), "repository": "owner/project", "unknown": "RAW_SECRET"})
			b := &Bridge{eventDebug: true}
			b.logEventDebug(event, "subscription")
			record, _, line := readEventDebugRecord(t, logs.String())
			if !record.Truncated || record.SanitizedBytes <= eventDebugMaxBytes || len(record.Event) != 0 || record.Excerpt == "" || len(record.SanitizedHash) != 64 || !utf8.ValidString(record.Excerpt) {
				t.Fatalf("missing bounded excerpt diagnostics: %+v", record)
			}
			data, _ := eventDebugData(event)
			sanitized := eventDebugJSON(eventDebugEnvelope{ID: event.ID, Name: event.Name, Timestamp: event.Timestamp.Format(time.RFC3339Nano), Data: data, Cursor: json.RawMessage("null")})
			if record.SanitizedBytes != len(sanitized) || record.SanitizedHash != digest(string(sanitized)) || !strings.HasPrefix(string(sanitized), record.Excerpt) {
				t.Fatal("length/hash/excerpt must refer only to the sanitized envelope")
			}
			// Altering an excluded secret must never change the diagnostic hash.
			event.Data["unknown"] = "DIFFERENT_RAW_SECRET"
			logs.Reset()
			b.logEventDebug(event, "subscription")
			_, _, secondLine := readEventDebugRecord(t, logs.String())
			if line != secondLine {
				t.Fatal("raw excluded content influenced diagnostics")
			}
		})
	}
}

func TestEventDebugDeliveryPreservesWirePayload(t *testing.T) {
	logs := captureOperationalLogs(t)
	b := fixture(t)
	b.eventDebug = true
	sub := Subscription{ID: "s", Name: "github.notification.changed", Expires: time.Now().Add(time.Hour), Delivery: Delivery{URL: "https://callback.example/CALLBACK_SECRET", Secret: testSecret()}}
	b.store.state.Subscriptions[sub.ID] = sub
	event := sampleDebugEvent(sub.Name, map[string]any{"title": "Actual title", "repository": "owner/project", "reason": "mention", "unknown": "PAYLOAD_SECRET"})
	event.Cursor = map[string]any{"value": "CURSOR_SECRET"}
	b.store.state.Queue = []Pending{{SubscriptionID: sub.ID, Event: event}}
	want, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	b.callbacks.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		got, err := io.ReadAll(r.Body)
		if err != nil || string(got) != string(want) {
			t.Fatal("debug logging changed event delivery")
		}
		return &http.Response{StatusCode: 204, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("RESPONSE_SECRET"))}, nil
	})
	b.deliverOne(context.Background())
	if !called || len(b.store.state.Queue) != 0 {
		t.Fatal("delivery was not completed")
	}
	record, envelope, _ := readEventDebugRecord(t, logs.String())
	if envelope.Data["title"] != "Actual title" || record.OmittedFields != 1 || !record.OmittedCursor {
		t.Fatal("delivery debug record missing actual metadata or omission indicators")
	}
	if !strings.Contains(logs.String(), "event_id="+event.ID) || !strings.Contains(logs.String(), "subscription_ref="+record.Subscription) {
		t.Fatal("debug correlation does not match operational delivery logs")
	}
	for _, forbidden := range []string{"CALLBACK_SECRET", "PAYLOAD_SECRET", "CURSOR_SECRET", "RESPONSE_SECRET", testSecret(), "webhook-signature"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("delivery secret leaked: %s", forbidden)
		}
	}
}
