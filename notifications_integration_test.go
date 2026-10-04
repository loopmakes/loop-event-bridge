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

func inboxFixture(id, repository, subjectType, title string) map[string]any {
	return map[string]any{"id": id, "reason": "subscribed", "unread": true, "updated_at": "2026-10-04T00:00:00Z", "repository": map[string]any{"full_name": repository}, "subject": map[string]any{"type": subjectType, "title": title}}
}
func inboxReply(body any, headers http.Header) *http.Response {
	raw, _ := json.Marshal(body)
	return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader(string(raw)))}
}
func TestNotificationsWholeInboxBaselineAndChanges(t *testing.T) {
	b := fixture(t)
	b.store.state.Subscriptions["s"] = Subscription{ID: "s", Name: "github.notification.changed", Expires: time.Now().Add(time.Hour)}
	rows := []map[string]any{inboxFixture("1", "one/repo", "Issue", "Issue title"), inboxFixture("2", "two/repo", "Release", "Release title")}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatalf("unexpected write method %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal("missing authentication")
		}
		if r.URL.Path == "/user" {
			return inboxReply(map[string]any{"id": 42, "login": "loopmakes"}, http.Header{}), nil
		}
		if r.URL.Path != "/notifications" || r.URL.Query().Get("all") != "true" || r.URL.Query().Get("participating") != "false" {
			t.Fatal("inbox was filtered")
		}
		return inboxReply(rows, http.Header{"X-Poll-Interval": []string{"900"}}), nil
	})}
	poll := func() {
		t.Helper()
		obs, id, wait, err := FetchNotifications(context.Background(), client, "https://api.github.com", "test-token", "loopmakes")
		if err != nil {
			t.Fatal(err)
		}
		if id != "42" || wait != 15*time.Minute {
			t.Fatalf("wrong identity/minimum: %s %s", id, wait)
		}
		if err := b.applyObservations(obs, id); err != nil {
			t.Fatal(err)
		}
	}
	poll()
	if len(b.store.state.Queue) != 0 {
		t.Fatal("historical inbox flooded")
	}
	rows = append(rows, inboxFixture("3", "three/repo", "FutureSubjectType", "Unknown types must not be dropped"))
	poll()
	if len(b.store.state.Queue) != 1 || b.store.state.Queue[0].Event.Data["subject_type"] != "FutureSubjectType" {
		t.Fatal("new cross-repository subject missing")
	}
	poll()
	if len(b.store.state.Queue) != 1 {
		t.Fatal("unchanged inbox emitted duplicates")
	}
	rows[0]["subject"].(map[string]any)["title"] = "Updated title"
	poll()
	if len(b.store.state.Queue) != 2 {
		t.Fatal("updated notification not emitted")
	}
	reloaded, err := openStore(b.store.path)
	if err != nil {
		t.Fatal(err)
	}
	b.store = reloaded
	poll()
	if len(b.store.state.Queue) != 2 {
		t.Fatal("restart produced duplicates")
	}
}
func TestNotificationsAccountGuardStopsBeforeInbox(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/user" {
			t.Fatal("private inbox read before identity check")
		}
		return inboxReply(map[string]any{"id": 99, "login": "other-account"}, http.Header{}), nil
	})}
	if _, _, _, err := FetchNotifications(context.Background(), client, "https://api.github.com", "test-token", "loopmakes"); err == nil {
		t.Fatal("wrong account accepted")
	}
	if calls != 1 {
		t.Fatal("unexpected requests")
	}
	calls = 0
	if _, _, _, err := FetchNotifications(context.Background(), client, "https://api.github.com", "", "loopmakes"); err == nil {
		t.Fatal("empty token accepted")
	}
	if calls != 0 {
		t.Fatal("request made without token")
	}
}

func TestNotificationsPaginationAndFailClosed(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		t.Run(map[bool]string{false: "all pages", true: "second page fails"}[failSecond], func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" {
					t.Fatal("unexpected mutation")
				}
				if r.URL.Path == "/user" {
					return inboxReply(map[string]any{"id": 42, "login": "loopmakes"}, http.Header{}), nil
				}
				if r.URL.Query().Get("per_page") != "50" {
					t.Fatal("wrong page size")
				}
				switch r.URL.Query().Get("page") {
				case "1":
					return inboxReply([]any{inboxFixture("1", "one/repo", "Issue", "one")}, http.Header{"Link": []string{`<https://api.github.com/notifications?page=2>; rel="next"`}}), nil
				case "2":
					if failSecond {
						return &http.Response{StatusCode: 502, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("private response body"))}, nil
					}
					return inboxReply([]any{inboxFixture("2", "two/repo", "Release", "two")}, http.Header{}), nil
				default:
					t.Fatal("unexpected page")
					return nil, nil
				}
			})}
			obs, id, _, err := FetchNotifications(context.Background(), client, "https://api.github.com", "test-token", "loopmakes")
			if calls != 3 {
				t.Fatalf("calls %d", calls)
			}
			if failSecond {
				if err == nil || obs != nil || id != "" || strings.Contains(err.Error(), "private response") {
					t.Fatal("partial or sensitive failure result")
				}
			} else if err != nil || id != "42" || len(obs) != 2 {
				t.Fatalf("incomplete result: %d %s %v", len(obs), id, err)
			}
		})
	}
}
func TestNotificationsRateLimitMinimum(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/user" {
			return inboxReply(map[string]any{"id": 42, "login": "loopmakes"}, http.Header{}), nil
		}
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"1200"}}, Body: io.NopCloser(strings.NewReader("private limit response"))}, nil
	})}
	obs, _, wait, err := FetchNotifications(context.Background(), client, "https://api.github.com", "test-token", "loopmakes")
	if err == nil || obs != nil || wait < 20*time.Minute || strings.Contains(err.Error(), "private limit") {
		t.Fatalf("bad rate limit handling: %v %s", err, wait)
	}
}
func TestNotificationsPaginationLimit(t *testing.T) {
	pages := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/user" {
			return inboxReply(map[string]any{"id": 42, "login": "loopmakes"}, http.Header{}), nil
		}
		pages++
		return inboxReply([]any{}, http.Header{"Link": []string{`<https://api.github.com/notifications?page=next>; rel="next"`}}), nil
	})}
	obs, _, _, err := FetchNotifications(context.Background(), client, "https://api.github.com", "test-token", "loopmakes")
	if err == nil || obs != nil || pages != notificationMaxPages {
		t.Fatalf("page cap not enforced: %d %v", pages, err)
	}
}
func TestNotificationsBodyBudget(t *testing.T) {
	remaining := int64(1)
	if _, err := readNotificationBody(io.NopCloser(strings.NewReader("[]")), &remaining); err == nil {
		t.Fatal("aggregate body budget not enforced")
	}
	remaining = notificationBudget
	if _, err := readNotificationBody(io.NopCloser(strings.NewReader(strings.Repeat("x", notificationMaxBody+1))), &remaining); err == nil {
		t.Fatal("response body bound not enforced")
	}
}
func TestNotificationSafeURLs(t *testing.T) {
	if got := notificationWebURL("one/repo", "PullRequest", "https://api.github.com/repos/one/repo/pulls/7"); got != "https://github.com/one/repo/pull/7" {
		t.Fatal(got)
	}
	if got := notificationWebURL("one/repo", "Release", "https://api.github.com/repos/one/repo/releases/7"); got != "" {
		t.Fatal("release web URL guessed")
	}
	if notificationAPIURL("https://other.example/path") != "" {
		t.Fatal("unexpected API origin accepted")
	}
}

func TestNotificationReadChangeUsesSourceReadTime(t *testing.T) {
	raw, _ := json.Marshal(inboxFixture("8", "one/repo", "Issue", "title"))
	var n githubNotification
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatal(err)
	}
	readAt := n.UpdatedAt.Add(time.Hour)
	n.LastReadAt = &readAt
	all := map[string]Observation{}
	if err := addNotificationObservation(all, notificationAccount{ID: 42, Login: "loopmakes"}, n); err != nil {
		t.Fatal(err)
	}
	for _, o := range all {
		if !o.Timestamp.Equal(readAt) {
			t.Fatal("read change used stale timestamp")
		}
	}
}
