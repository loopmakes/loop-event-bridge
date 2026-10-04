package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type githubTestTransport func(*http.Request) (*http.Response, error)

func (f githubTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const githubTestTime = "2026-10-03T01:02:03Z"

func githubTestResponse(status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}
func githubTestJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
func githubTestPull(number int, author string) map[string]any {
	return map[string]any{"number": number, "user": map[string]any{"login": author}, "state": "open", "draft": false, "title": "PR title", "html_url": fmt.Sprintf("https://github.com/acme/repo/pull/%d", number), "updated_at": githubTestTime, "head": map[string]any{"sha": "abc123"}, "base": map[string]any{"ref": "main"}}
}
func githubTestReview(id int64) map[string]any {
	return map[string]any{"id": id, "user": map[string]any{"login": "reviewer"}, "state": "APPROVED", "body": "private review text", "html_url": "https://github.com/acme/repo/pull/1#pullrequestreview-1", "commit_id": "abc123", "submitted_at": githubTestTime}
}
func githubTestComment(id int64) map[string]any {
	return map[string]any{"id": id, "user": map[string]any{"login": "commenter"}, "body": "private comment text", "html_url": "https://github.com/acme/repo/pull/1#issuecomment-1", "updated_at": githubTestTime, "path": "main.go", "line": 4, "commit_id": "abc123", "pull_request_review_id": 20, "in_reply_to_id": 3}
}

func TestFetchGitHubPaginationAndAuthor(t *testing.T) {
	calls := make(map[string]int)
	client := &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Host != "mock.github.test" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") == "" {
			t.Error("missing GitHub headers")
		}
		if r.URL.Query().Get("per_page") != "100" {
			t.Error("missing per_page=100")
		}
		page := r.URL.Query().Get("page")
		key := r.URL.Path + "?page=" + page
		calls[key]++
		var values []map[string]any
		next := false
		switch key {
		case "/repos/acme/repo/pulls?page=1":
			if r.URL.Query().Get("state") != "all" || r.URL.Query().Get("sort") != "created" || r.URL.Query().Get("direction") != "asc" {
				t.Error("PRs must include every state in stable created order")
			}
			values = []map[string]any{githubTestPull(1, "Alice"), githubTestPull(99, "Bob")}
			next = true
		case "/repos/acme/repo/pulls?page=2":
			values = []map[string]any{githubTestPull(2, "aLiCe")}
		case "/repos/acme/repo/pulls/1/reviews?page=1":
			pending := githubTestReview(999)
			pending["state"] = "PENDING"
			delete(pending, "submitted_at")
			values = []map[string]any{githubTestReview(20), pending}
			next = true
		case "/repos/acme/repo/pulls/1/reviews?page=2":
			values = []map[string]any{githubTestReview(21)}
		case "/repos/acme/repo/issues/1/comments?page=1":
			values = []map[string]any{githubTestComment(30)}
			next = true
		case "/repos/acme/repo/issues/1/comments?page=2":
			values = []map[string]any{githubTestComment(31)}
		case "/repos/acme/repo/pulls/1/comments?page=1":
			values = []map[string]any{githubTestComment(40)}
			next = true
		case "/repos/acme/repo/pulls/1/comments?page=2":
			values = []map[string]any{githubTestComment(41)}
		case "/repos/acme/repo/pulls/2/reviews?page=1", "/repos/acme/repo/issues/2/comments?page=1", "/repos/acme/repo/pulls/2/comments?page=1":
			values = []map[string]any{}
		default:
			t.Errorf("unexpected endpoint %s", key)
			values = []map[string]any{}
		}
		header := make(http.Header)
		if next {
			// The next URL is untrusted. Only its relation may be used; every
			// actual request must stay at our original API origin and path.
			header.Set("Link", `<https://untrusted.invalid/steal?page=2>; rel="next", <https://mock.github.test/?page=5>; rel="last"`)
		}
		return githubTestResponse(http.StatusOK, githubTestJSON(values), header), nil
	})}
	got, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "test-token", "ACME/Repo", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 || len(calls) != 11 {
		t.Fatalf("got %d observations, %d calls; want 8 and 11", len(got), len(calls))
	}
	keys := make([]string, len(got))
	for i, observation := range got {
		keys[i] = observation.Key
		if len(observation.Fingerprint) != 64 {
			t.Error("fingerprint is not SHA-256")
		}
		if observation.Timestamp.Format(time.RFC3339) != githubTestTime {
			t.Errorf("not a source timestamp: %s", observation.Timestamp)
		}
		for _, field := range []string{"repository", "author", "pull_request_number", "kind", "url"} {
			if _, exists := observation.Data[field]; !exists {
				t.Errorf("missing data field %s", field)
			}
		}
		encoded := githubTestJSON(observation.Data)
		if strings.Contains(encoded, "private") || strings.Contains(encoded, "test-token") {
			t.Errorf("sensitive source text leaked: %s", encoded)
		}
	}
	if !sort.StringsAreSorted(keys) {
		t.Error("results not sorted by key")
	}
	if got[0].Data["author"] != "Alice" {
		t.Error("author should identify PR creator")
	}
	if got[1].Data["actor"] != "commenter" {
		t.Error("comment actor should be retained")
	}
	// The exact same snapshot must yield byte-for-byte equivalent observations.
	again, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "test-token", "acme/repo", "ALICE")
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("non-deterministic snapshot: %v", err)
	}
}

func TestFetchGitHubFailureReturnsNoPartialSnapshot(t *testing.T) {
	client := &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/repos/acme/repo/pulls" {
			return githubTestResponse(200, githubTestJSON([]any{githubTestPull(1, "alice")}), nil), nil
		}
		return githubTestResponse(403, `{"message":"rate limit exceeded: secret-token"}`, http.Header{"Retry-After": {"120"}}), nil
	})}
	observations, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "secret-token", "acme/repo", "alice")
	if observations != nil || err == nil {
		t.Fatalf("partial result escaped on failure: %v, %v", observations, err)
	}
	var apiError *GitHubHTTPError
	if !errors.As(err, &apiError) || apiError.StatusCode != 403 || !apiError.RateLimited || apiError.RetryAfter != 2*time.Minute {
		t.Fatalf("wrong rate-limit error: %v", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatal("error leaks token/body")
	}
}

func TestFetchGitHubInputAndResponseErrors(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
	}{
		{"malformed_json", "[", 200}, {"null_page", "null", 200}, {"object_page", "{}", 200}, {"http_not_found", `{}`, 404}, {"not_modified_without_cache", ``, 304}, {"oversized_page", strings.Repeat(" ", githubMaxBody+1), 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: githubTestTransport(func(*http.Request) (*http.Response, error) {
				return githubTestResponse(test.status, test.body, nil), nil
			})}
			got, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "", "acme/repo", "alice")
			if err == nil || got != nil {
				t.Fatalf("expected closed failure, got %v, %v", got, err)
			}
		})
	}
	for _, repo := range []string{"", "repo", "acme/repo/extra", "acme/..", "acme/repo?token=bad"} {
		if _, err := FetchGitHub(context.Background(), nil, "https://mock.github.test", "", repo, "alice"); err == nil {
			t.Errorf("accepted invalid repo %q", repo)
		}
	}
	for _, base := range []string{"not-a-url", "file:///tmp/github", "https://name:password@github.test", "https://github.test?token=bad", "https://github.test#fragment"} {
		if _, err := FetchGitHub(context.Background(), nil, base, "", "acme/repo", "alice"); err == nil {
			t.Errorf("accepted invalid base URL %q", base)
		}
	}
	if _, err := FetchGitHub(context.Background(), nil, "https://mock.github.test", "", "acme/repo", "  "); err == nil {
		t.Error("accepted empty author")
	}
}

func TestFetchGitHubPaginationLimit(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Query().Get("page") != strconv.Itoa(calls) {
			t.Error("pagination did not increment")
		}
		return githubTestResponse(200, `[]`, http.Header{"Link": {`<https://mock.github.test?page=999>; rel="next"`}}), nil
	})}
	got, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "", "acme/repo", "alice")
	if got != nil || err == nil || calls != githubMaxPages || !strings.Contains(err.Error(), "partial snapshot") {
		t.Fatalf("limit failed: calls=%d observations=%v err=%v", calls, got, err)
	}
}

func TestFetchGitHubRejectsRedirect(t *testing.T) {
	calls := 0
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		t.Error("caller redirect handler should not be used")
		return nil
	}, Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return githubTestResponse(302, "", http.Header{"Location": {"https://other.invalid/token-target"}}), nil
	})}
	got, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "secret-token", "acme/repo", "alice")
	var apiError *GitHubHTTPError
	if got != nil || !errors.As(err, &apiError) || apiError.StatusCode != 302 || calls != 1 {
		t.Fatalf("redirect not rejected: calls=%d error=%v", calls, err)
	}
	if client.CheckRedirect == nil {
		t.Error("caller client unexpectedly mutated")
	}
}

func TestFetchGitHubCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })}
	got, err := FetchGitHub(ctx, client, "https://mock.github.test", "", "acme/repo", "alice")
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation lost: %v", err)
	}
}

func TestFetchGitHubImportantChangesOnly(t *testing.T) {
	pull := githubTestPull(1, "alice")
	comment := githubTestComment(1)
	client := &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
		var values []any
		switch r.URL.Path {
		case "/repos/acme/repo/pulls":
			values = []any{pull}
		case "/repos/acme/repo/issues/1/comments":
			values = []any{comment}
		default:
			values = []any{}
		}
		return githubTestResponse(200, githubTestJSON(values), nil), nil
	})}
	fetch := func() []Observation {
		t.Helper()
		got, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "", "acme/repo", "alice")
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := fetch()
	pull["updated_at"] = "2026-10-04T01:02:03Z"
	after := fetch()
	if before[0].Fingerprint != after[0].Fingerprint {
		t.Error("PR timestamp alone caused state event")
	}
	if before[0].Timestamp.Equal(after[0].Timestamp) {
		t.Error("PR source update timestamp was lost")
	}
	comment["body"] = "edited body"
	after = fetch()
	if before[1].Fingerprint == after[1].Fingerprint {
		t.Error("comment edit not detected")
	}
	pull["head"] = map[string]any{"sha": "new-commit"}
	after = fetch()
	if before[0].Fingerprint == after[0].Fingerprint {
		t.Error("head change not detected")
	}
	pull["state"], pull["merged_at"] = "closed", "2026-10-04T01:02:03Z"
	after = fetch()
	if after[0].Data["merged"] != true || after[0].Data["state"] != "closed" {
		t.Error("merge state missing")
	}
}

func TestGitHubRetryDelay(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, test := range []struct {
		name   string
		header http.Header
		want   time.Duration
	}{
		{"retry_after", http.Header{"Retry-After": {"120"}}, 2 * time.Minute},
		{"reset_wins", http.Header{"Retry-After": {"10"}, "X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"1180"}}, 3 * time.Minute},
		{"http_date", http.Header{"Retry-After": {now.Add(time.Hour).UTC().Format(http.TimeFormat)}}, time.Hour},
		{"default", make(http.Header), time.Minute},
		{"invalid", http.Header{"Retry-After": {"-1"}}, time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := githubRetryDelay(test.header, now); got != test.want {
				t.Errorf("got %s, want %s", got, test.want)
			}
		})
	}
}

func TestFetchGitHubFullPageWithoutLink(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			values := make([]any, githubPageSize)
			for i := range values {
				values[i] = githubTestPull(i+1, "someone-else")
			}
			return githubTestResponse(200, githubTestJSON(values), nil), nil
		}
		if calls != 2 || r.URL.Query().Get("page") != "2" {
			t.Error("unexpected continuation")
		}
		return githubTestResponse(200, `[]`, nil), nil
	})}
	got, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "", "acme/repo", "alice")
	if err != nil || len(got) != 0 || calls != 2 {
		t.Fatalf("full-page continuation failed: got=%v calls=%d err=%v", got, calls, err)
	}
}

func TestFetchGitHubDuplicateConsistency(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed_%t", changed), func(t *testing.T) {
			client := &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/repos/acme/repo/pulls" {
					return githubTestResponse(200, `[]`, nil), nil
				}
				pull := githubTestPull(1, "alice")
				header := make(http.Header)
				if r.URL.Query().Get("page") == "1" {
					header.Set("Link", `<https://mock.github.test?page=2>; rel="next"`)
				} else if changed {
					pull["state"] = "closed"
				}
				return githubTestResponse(200, githubTestJSON([]any{pull}), header), nil
			})}
			got, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "", "acme/repo", "alice")
			if changed {
				if got != nil || err == nil {
					t.Fatal("inconsistent pagination must reject complete snapshot")
				}
			} else if err != nil || len(got) != 1 {
				t.Fatalf("identical duplicate should deduplicate: %v, %v", got, err)
			}
		})
	}
}

func TestFetchGitHubMissingSourceFields(t *testing.T) {
	for _, test := range []struct {
		name, endpoint string
		data           map[string]any
		field          string
	}{
		{"pull_timestamp", "/repos/acme/repo/pulls", githubTestPull(1, "alice"), "updated_at"},
		{"pull_number", "/repos/acme/repo/pulls", githubTestPull(1, "alice"), "number"},
		{"pull_head", "/repos/acme/repo/pulls", githubTestPull(1, "alice"), "head"},
		{"review_submission", "/repos/acme/repo/pulls/1/reviews", githubTestReview(1), "submitted_at"},
		{"comment_id", "/repos/acme/repo/issues/1/comments", githubTestComment(1), "id"},
		{"comment_timestamp", "/repos/acme/repo/pulls/1/comments", githubTestComment(1), "updated_at"},
	} {
		t.Run(test.name, func(t *testing.T) {
			delete(test.data, test.field)
			client := &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
				values := []any{}
				if r.URL.Path == test.endpoint {
					values = []any{test.data}
				} else if r.URL.Path == "/repos/acme/repo/pulls" {
					values = []any{githubTestPull(1, "alice")}
				}
				return githubTestResponse(200, githubTestJSON(values), nil), nil
			})}
			got, err := FetchGitHub(context.Background(), client, "https://mock.github.test", "", "acme/repo", "alice")
			if err == nil || got != nil {
				t.Fatalf("incomplete %s accepted", test.name)
			}
		})
	}
}

func TestGitHubTotalScanBudget(t *testing.T) {
	base, _ := url.Parse("https://api.github.test")
	remaining := int64(3)
	reader := githubReader{base: base, remaining: &remaining, client: &http.Client{Transport: githubTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("[]"))}, nil
	})}}
	if _, _, err := reader.get(context.Background(), "/first", url.Values{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.get(context.Background(), "/second", url.Values{}); err == nil {
		t.Fatal("aggregate body budget not enforced")
	}
}
