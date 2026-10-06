package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func gitlabFixture(id int, action, targetType string) map[string]any {
	return map[string]any{
		"id": id, "action_name": action, "target_type": targetType, "state": "pending",
		"created_at": "2026-10-04T01:02:03Z", "updated_at": "2026-10-04T04:05:06Z",
		"project":    map[string]any{"id": 9, "path_with_namespace": "group/subgroup/project"},
		"target":     map[string]any{"title": "Synthetic title"},
		"target_url": "https://gitlab.example/group/subgroup/project/-/issues/7#note_123",
	}
}

func gitlabReply(value any, header http.Header) *http.Response {
	encoded, _ := json.Marshal(value)
	return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(string(encoded)))}
}

func gitlabTestClient(t *testing.T, todos func(*http.Request) (*http.Response, error)) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Fatalf("adapter attempted mutation: %s", r.Method)
		}
		if r.Header.Get("PRIVATE-TOKEN") != "synthetic-token" || r.URL.User != nil || r.URL.Query().Get("private_token") != "" || strings.Contains(r.URL.String(), "synthetic-token") {
			t.Fatal("credentials missing from header or present in URL")
		}
		if r.URL.Path == "/api/v4/user" {
			return gitlabReply(map[string]any{"id": 42, "username": "example.user"}, http.Header{}), nil
		}
		if r.URL.Path != "/api/v4/todos" || r.URL.Query().Get("state") != "pending" || r.URL.Query().Get("per_page") != "100" || len(r.URL.Query()) != 3 {
			t.Fatal("unexpected Todos endpoint or filters")
		}
		return todos(r)
	})}
}

func TestGitLabTodosReadOnlyIdentityAndCoverage(t *testing.T) {
	rows := []map[string]any{
		gitlabFixture(1, "mentioned", "Issue"), gitlabFixture(2, "assigned", "MergeRequest"),
		gitlabFixture(3, "approval_required", "MergeRequest"), gitlabFixture(4, "directly_addressed", "Commit"),
		gitlabFixture(5, "future_action", "FutureTargetType"),
	}
	client := gitlabTestClient(t, func(*http.Request) (*http.Response, error) { return gitlabReply(rows, http.Header{}), nil })
	fetch := func(origin string) []Observation {
		t.Helper()
		observations, id, delay, err := FetchGitLabTodos(context.Background(), client, origin, "synthetic-token", "EXAMPLE.USER")
		if err != nil || id != "42" || delay != time.Minute || len(observations) != len(rows) {
			t.Fatalf("invalid snapshot: %d %q %s %v", len(observations), id, delay, err)
		}
		return observations
	}
	first := fetch("https://gitlab.example")
	second := fetch("https://gitlab.example/")
	for i, observation := range first {
		if observation.Key != second[i].Key || observation.Fingerprint != second[i].Fingerprint || observation.Timestamp.IsZero() || observation.Data["kind"] != "todo" {
			t.Fatal("unstable identity or fingerprint")
		}
		if observation.Data["url"] != rows[i]["target_url"] || observation.Data["action"] != rows[i]["action_name"] {
			t.Fatal("action/target coverage missing")
		}
	}
	rows[0]["target"].(map[string]any)["title"] = "Updated synthetic title"
	changed := fetch("https://gitlab.example")
	if first[0].Key != changed[0].Key || first[0].Fingerprint == changed[0].Fingerprint {
		t.Fatal("edit changed identity or failed to change fingerprint")
	}
	other := fetch("https://another-gitlab.example")
	if first[0].Key == other[0].Key {
		t.Fatal("two instances share observation identity")
	}
}

func TestGitLabTodosAccountGuard(t *testing.T) {
	for _, identity := range []any{map[string]any{"id": 42, "username": "other"}, map[string]any{"id": 0, "username": "example.user"}, map[string]any{"id": 42}, nil} {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Path != "/api/v4/user" {
				t.Fatal("Todos fetched before verifying identity")
			}
			return gitlabReply(identity, http.Header{}), nil
		})}
		obs, id, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
		if err == nil || obs != nil || id != "" || calls != 1 {
			t.Fatalf("invalid identity accepted: %v", err)
		}
	}
}

func TestGitLabTodosRejectUnsafeConfiguration(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network request"); return nil, nil })}
	for _, origin := range []string{
		"http://gitlab.example", "http://localhost:1234", "http://127.0.0.1", "ftp://gitlab.example",
		"https://user:password@gitlab.example", "https://gitlab.example?token=secret", "https://gitlab.example?",
		"https://gitlab.example/#secret", "https://gitlab.example/api/v4", "https://gitlab.example/%2f", "//gitlab.example", "://bad",
	} {
		t.Run(origin, func(t *testing.T) {
			obs, _, _, err := FetchGitLabTodos(context.Background(), client, origin, "synthetic-token", "example.user")
			if err == nil || obs != nil || strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe configuration accepted or leaked: %v", err)
			}
		})
	}
	for _, token := range []string{"", "\n", "secret\r\nInjected: true", "two tokens"} {
		if _, _, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", token, "example.user"); err == nil {
			t.Fatal("bad token accepted")
		}
	}
	for _, username := range []string{"", "@example", "name with spaces", "name/other"} {
		if _, _, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", username); err == nil {
			t.Fatal("bad username accepted")
		}
	}
	if _, _, _, err := FetchGitLabTodos(context.Background(), nil, "http://127.0.0.1:1234", "synthetic-token", "example.user"); err == nil {
		t.Fatal("plaintext accepted without explicit test client")
	}
}

func TestGitLabTodosLoopbackAndRedirectSafety(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	var redirect atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("PRIVATE-TOKEN") != "synthetic-token" {
			t.Error("wrong method or missing token")
		}
		if redirect.Load() {
			http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
			return
		}
		if r.URL.Path == "/api/v4/user" {
			fmt.Fprint(w, `{"id":42,"username":"example.user"}`)
			return
		}
		fmt.Fprint(w, `[]`)
	}))
	defer server.Close()
	obs, id, _, err := FetchGitLabTodos(context.Background(), server.Client(), server.URL, "synthetic-token", "example.user")
	if err != nil || obs == nil || len(obs) != 0 || id != "42" {
		t.Fatalf("empty loopback snapshot failed: %v", err)
	}
	redirect.Store(true)
	obs, id, _, err = FetchGitLabTodos(context.Background(), server.Client(), server.URL, "synthetic-token", "example.user")
	if err == nil || obs != nil || id != "" || redirected.Load() != 0 {
		t.Fatal("redirect followed or partial result exposed")
	}
}

func TestGitLabTodosPagination(t *testing.T) {
	for _, mode := range []string{"header", "link", "missing metadata", "failure", "conflict", "duplicate", "bad next"} {
		t.Run(mode, func(t *testing.T) {
			pages := 0
			client := gitlabTestClient(t, func(r *http.Request) (*http.Response, error) {
				pages++
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				if page != pages || page > 2 {
					t.Fatal("unexpected pagination")
				}
				if page == 1 {
					header := http.Header{"X-Next-Page": []string{"2"}}
					rows := []map[string]any{gitlabFixture(1, "assigned", "Issue")}
					switch mode {
					case "link":
						header = http.Header{"Link": []string{`<https://attacker.invalid/?private_token=secret>; rel="next"`}}
					case "missing metadata":
						header = http.Header{}
						for i := 2; i <= gitlabPageSize; i++ {
							rows = append(rows, gitlabFixture(i, "mentioned", "Issue"))
						}
					case "bad next":
						header.Set("X-Next-Page", "999")
					}
					return gitlabReply(rows, header), nil
				}
				if mode == "failure" {
					return &http.Response{StatusCode: 502, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("sensitive response synthetic-token"))}, nil
				}
				row := gitlabFixture(101, "mentioned", "Issue")
				if mode == "duplicate" || mode == "conflict" {
					row = gitlabFixture(1, "assigned", "Issue")
				}
				if mode == "conflict" {
					row["action_name"] = "mentioned"
				}
				return gitlabReply([]any{row}, http.Header{"X-Next-Page": []string{""}}), nil
			})
			obs, id, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
			if mode == "failure" || mode == "conflict" || mode == "bad next" {
				if err == nil || obs != nil || id != "" || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "synthetic-token") {
					t.Fatalf("unsafe partial result: %v", err)
				}
				return
			}
			want := 2
			if mode == "duplicate" {
				want = 1
			}
			if mode == "missing metadata" {
				want = 101
			}
			if err != nil || id != "42" || len(obs) != want || pages != 2 {
				t.Fatalf("incomplete snapshot: %d pages %d: %v", len(obs), pages, err)
			}
		})
	}
}

func TestGitLabTodosPaginationBound(t *testing.T) {
	pages := 0
	client := gitlabTestClient(t, func(*http.Request) (*http.Response, error) {
		pages++
		return gitlabReply([]any{}, http.Header{"X-Next-Page": []string{strconv.Itoa(pages + 1)}}), nil
	})
	obs, id, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
	if err == nil || obs != nil || id != "" || pages != gitlabMaxPages {
		t.Fatalf("pagination unbounded: %d %v", pages, err)
	}
}

func TestGitLabTodosMalformedResponses(t *testing.T) {
	for _, body := range []string{"null", "{}", "[] trailing", "[", `[{"id":1}]`, strings.Repeat(" ", gitlabMaxBody+1)} {
		client := gitlabTestClient(t, func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		obs, id, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
		if err == nil || obs != nil || id != "" {
			t.Fatalf("malformed response accepted: %v", err)
		}
	}
	for _, field := range []string{"id", "created_at", "action_name", "target_type", "state"} {
		row := gitlabFixture(1, "assigned", "Issue")
		delete(row, field)
		client := gitlabTestClient(t, func(*http.Request) (*http.Response, error) { return gitlabReply([]any{row}, http.Header{}), nil })
		if _, _, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user"); err == nil {
			t.Fatalf("missing %s accepted", field)
		}
	}
}

func TestGitLabTodosRateLimitBackoff(t *testing.T) {
	for _, status := range []int{200, 403, 429} {
		for _, endpoint := range []string{"/api/v4/user", "/api/v4/todos"} {
			t.Run(fmt.Sprintf("%d%s", status, endpoint), func(t *testing.T) {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.URL.Path != endpoint {
						return gitlabReply(map[string]any{"id": 42, "username": "example.user"}, http.Header{}), nil
					}
					header := http.Header{"Retry-After": []string{"1200"}, "Ratelimit-Remaining": []string{"0"}, "X-Next-Page": []string{"2"}}
					if status == 200 {
						if endpoint == "/api/v4/user" {
							return gitlabReply(map[string]any{"id": 42, "username": "example.user"}, header), nil
						}
						return gitlabReply([]any{gitlabFixture(1, "assigned", "Issue")}, header), nil
					}
					return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader("synthetic-token private response"))}, nil
				})}
				obs, id, delay, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
				var rate *GitLabHTTPError
				if !errors.As(err, &rate) || !rate.RateLimited || rate.RetryAfter < 20*time.Minute || delay < 20*time.Minute || obs != nil || id != "" || strings.Contains(err.Error(), "synthetic-token") {
					t.Fatalf("bad rate handling: %v %s", err, delay)
				}
				want := 1
				if endpoint == "/api/v4/todos" {
					want = 2
				}
				if calls != want {
					t.Fatal("continued scan after rate exhaustion")
				}
			})
		}
	}
}

func TestGitLabRateDelayFormats(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for _, header := range []http.Header{
		{"Retry-After": []string{"1800"}},
		{"Retry-After": []string{now.Add(30 * time.Minute).Format(http.TimeFormat)}},
		{"Ratelimit-Reset": []string{strconv.FormatInt(now.Add(30*time.Minute).Unix(), 10)}},
		{"Ratelimit-Resettime": []string{now.Add(30 * time.Minute).Format(http.TimeFormat)}},
	} {
		if got := gitlabRetryDelay(header, now); got != 30*time.Minute {
			t.Fatalf("unexpected backoff %s for %v", got, header)
		}
	}
	if got := gitlabRetryDelay(http.Header{"Retry-After": []string{"9223372036854775807"}}, now); got != time.Duration(1<<63-1) {
		t.Fatal("overflowed backoff")
	}
	if got := gitlabRetryDelay(http.Header{"Retry-After": []string{"-1"}}, now); got != time.Minute {
		t.Fatal("negative backoff")
	}
}

func TestGitLabTodosURLSanitization(t *testing.T) {
	origin, _ := url.Parse("https://gitlab.example")
	for _, raw := range []string{
		"https://user:secret@gitlab.example/g/p", "https://attacker.invalid/g/p", "http://gitlab.example/g/p",
		"https://gitlab.example/g/p?private_token=secret", "https://gitlab.example/g/p?", "https://gitlab.example/g/../p",
		"https://gitlab.example/g/%2e%2e/p", "https://gitlab.example//p", "https://gitlab.example/g/p#secret", "javascript:alert(1)",
		"https://gitlab.example/" + strings.Repeat("x", 8192),
	} {
		if gitlabTodoURL(raw, origin) != "" {
			t.Fatalf("unsafe target URL accepted: %s", raw)
		}
	}
	if got := gitlabTodoURL("https://gitlab.example/g/p/-/issues/1#note_123", origin); got == "" {
		t.Fatal("safe Todo URL omitted")
	}
}

func TestGitLabTodosTransportErrorsAreSanitized(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("synthetic-token secret transport error")
	})}
	obs, _, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
	if err == nil || obs != nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "synthetic-token") {
		t.Fatal("transport error leaked data")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := FetchGitLabTodos(ctx, client, "https://gitlab.example", "synthetic-token", "example.user"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestGitLabTodosResponseBudget(t *testing.T) {
	pages := 0
	client := gitlabTestClient(t, func(*http.Request) (*http.Response, error) {
		pages++
		// Unknown JSON fields can make a page large without producing large
		// event payloads. The complete scan still has a strict byte budget.
		row := gitlabFixture(pages, "assigned", "Issue")
		row["ignored"] = strings.Repeat("x", 9<<20)
		return gitlabReply([]any{row}, http.Header{"X-Next-Page": []string{strconv.Itoa(pages + 1)}}), nil
	})
	obs, id, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
	if err == nil || obs != nil || id != "" || pages != 8 || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("scan body budget not enforced: %d %v", pages, err)
	}
}

func TestGitLabTodosBoundedTitlesAndPendingOnly(t *testing.T) {
	for _, mode := range []string{"title", "body", "done", "too many rows"} {
		t.Run(mode, func(t *testing.T) {
			row := gitlabFixture(1, "assigned", "Issue")
			rows := []map[string]any{row}
			switch mode {
			case "title":
				row["target"] = map[string]any{"title": strings.Repeat("x", (32<<10)+1)}
			case "body":
				delete(row, "target")
				row["body"] = strings.Repeat("x", (32<<10)+1)
			case "done":
				row["state"] = "done"
			case "too many rows":
				for i := 2; i <= gitlabPageSize+1; i++ {
					rows = append(rows, gitlabFixture(i, "assigned", "Issue"))
				}
			}
			client := gitlabTestClient(t, func(*http.Request) (*http.Response, error) { return gitlabReply(rows, http.Header{}), nil })
			obs, id, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
			if err == nil || obs != nil || id != "" {
				t.Fatal("invalid Todo page accepted")
			}
		})
	}
}

func TestGitLabTodosOptionalFieldsAndSuccessfulExhaustion(t *testing.T) {
	row := gitlabFixture(1, "member_access_requested", "Namespace")
	delete(row, "updated_at")
	delete(row, "project")
	delete(row, "target")
	row["body"] = "Synthetic namespace request"
	row["target_url"] = "https://user:secret@gitlab.example/group"
	client := gitlabTestClient(t, func(*http.Request) (*http.Response, error) {
		return gitlabReply([]any{row}, http.Header{"Ratelimit-Remaining": []string{"0"}, "Retry-After": []string{"1800"}}), nil
	})
	obs, id, delay, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
	if err != nil || len(obs) != 1 || id != "42" || delay != 30*time.Minute {
		t.Fatalf("complete quota-exhausting page rejected: %v", err)
	}
	if obs[0].Data["url"] != nil || obs[0].Data["title"] != row["body"] || obs[0].Data["updated_at"] != row["created_at"] {
		t.Fatal("optional fields or URL sanitization failed")
	}
}

type gitlabErrorBody struct{ closed bool }

func (r *gitlabErrorBody) Read([]byte) (int, error) {
	return 0, errors.New("sensitive response read error")
}
func (r *gitlabErrorBody) Close() error { r.closed = true; return nil }

func TestGitLabTodosReadFailureAndBodyClosure(t *testing.T) {
	body := &gitlabErrorBody{}
	client := gitlabTestClient(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body}, nil
	})
	obs, id, _, err := FetchGitLabTodos(context.Background(), client, "https://gitlab.example", "synthetic-token", "example.user")
	if err == nil || obs != nil || id != "" || !body.closed || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("read failure leaked or left body open: %v", err)
	}
}
