package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	gitlabPageSize = 100
	gitlabMaxPages = 100
	gitlabMaxBody  = 10 << 20
	gitlabBudget   = 64 << 20
)

// GitLabHTTPError deliberately excludes URLs, credentials and response bodies.
type GitLabHTTPError struct {
	StatusCode  int
	RateLimited bool
	RetryAfter  time.Duration
}

func (e *GitLabHTTPError) Error() string {
	if e.RateLimited {
		return fmt.Sprintf("GitLab API rate limited (HTTP %d; retry after %s)", e.StatusCode, e.RetryAfter)
	}
	return fmt.Sprintf("GitLab API returned HTTP %d", e.StatusCode)
}

type gitlabAccount struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type gitlabTodo struct {
	ID         int64     `json:"id"`
	Action     string    `json:"action_name"`
	TargetType string    `json:"target_type"`
	TargetURL  string    `json:"target_url"`
	Body       string    `json:"body"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Project    struct {
		ID   int64  `json:"id"`
		Path string `json:"path_with_namespace"`
	} `json:"project"`
	Target struct {
		Title string `json:"title"`
	} `json:"target"`
}

var gitlabUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$`)
var gitlabNoteFragmentPattern = regexp.MustCompile(`^note_[0-9]+$`)

// FetchGitLabTodos takes a complete, read-only snapshot of pending GitLab Todos.
// It is NOT a full notifications inbox: only items surfaced by GitLab as Todos
// are visible, including mentions, assignments and approval/review requests.
// Done, deleted or newly inaccessible Todos are absent, and disappearances do
// not imply completion. All action/target types are retained without filtering.
// https://docs.gitlab.com/api/todos/
//
// GET /api/v4/user must match expectedUsername before reading any Todos. The
// numeric accountID is immutable within an instance; callers must additionally
// namespace the baseline by the configured instance origin. The first complete
// snapshot must be saved silently by the caller. Every error discards the whole
// snapshot. minPoll applies even on errors and never falls below one minute.
//
// baseURL is an HTTPS origin (for example https://gitlab.com), not an API URL.
// HTTP is accepted only with an explicit client and numeric loopback test port.
// Redirects and server-provided pagination URLs are never followed. This adapter
// issues GET requests only; it never marks Todos read/done or changes GitLab.
func FetchGitLabTodos(ctx context.Context, client *http.Client, baseURL, token, expectedUsername string) (observations []Observation, accountID string, minPoll time.Duration, err error) {
	minPoll = time.Minute
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, "", minPoll, errors.New("GitLab Todos require an authentication token")
	}
	expectedUsername = strings.TrimSpace(expectedUsername)
	if !gitlabUsernamePattern.MatchString(expectedUsername) {
		return nil, "", minPoll, errors.New("GitLab Todos require an expected account username")
	}
	base, parseErr := gitlabOrigin(baseURL, client != nil)
	if parseErr != nil {
		return nil, "", minPoll, parseErr
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	isolated := *client
	if isolated.Timeout <= 0 {
		isolated.Timeout = 30 * time.Second
	}
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	reader := gitlabReader{client: &isolated, base: base, token: token, remaining: gitlabBudget, minPoll: &minPoll}
	body, headers, getErr := reader.get(ctx, "/user", nil)
	if getErr != nil {
		return nil, "", minPoll, getErr
	}
	var account gitlabAccount
	if json.Unmarshal(body, &account) != nil || account.ID <= 0 || !gitlabUsernamePattern.MatchString(account.Username) {
		return nil, "", minPoll, errors.New("GitLab returned an invalid authenticated account")
	}
	if !strings.EqualFold(account.Username, expectedUsername) {
		return nil, "", minPoll, errors.New("GitLab token account does not match configured account")
	}
	if gitlabMustWait(headers) {
		return nil, "", minPoll, &GitLabHTTPError{StatusCode: http.StatusOK, RateLimited: true, RetryAfter: minPoll}
	}
	all := make(map[string]Observation)
	for page := 1; page <= gitlabMaxPages; page++ {
		query := url.Values{"state": {"pending"}, "page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(gitlabPageSize)}}
		body, headers, getErr := reader.get(ctx, "/todos", query)
		if getErr != nil {
			return nil, "", minPoll, getErr
		}
		var items []gitlabTodo
		if json.Unmarshal(body, &items) != nil || items == nil || len(items) > gitlabPageSize {
			return nil, "", minPoll, errors.New("GitLab returned an invalid Todos page")
		}
		for _, item := range items {
			if addErr := addGitLabTodo(all, base, account, item); addErr != nil {
				return nil, "", minPoll, addErr
			}
		}
		hasNext, paginationErr := gitlabHasNextPage(headers, page, len(items))
		if paginationErr != nil {
			return nil, "", minPoll, paginationErr
		}
		if !hasNext {
			result := make([]Observation, 0, len(all))
			for _, observation := range all {
				result = append(result, observation)
			}
			sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
			return result, strconv.FormatInt(account.ID, 10), minPoll, nil
		}
		if gitlabMustWait(headers) {
			return nil, "", minPoll, &GitLabHTTPError{StatusCode: http.StatusOK, RateLimited: true, RetryAfter: minPoll}
		}
	}
	return nil, "", minPoll, errors.New("GitLab Todos pagination exceeded page limit; refusing a partial snapshot")
}

func gitlabOrigin(raw string, explicitClient bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if len(raw) > 2048 || err != nil || u == nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid GitLab API origin")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		port, portErr := strconv.Atoi(u.Port())
		if u.Scheme != "http" || !explicitClient || ip == nil || !ip.IsLoopback() || portErr != nil || port < 1 || port > 65535 {
			return nil, errors.New("GitLab API origin must use HTTPS")
		}
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = ""
	return u, nil
}

type gitlabReader struct {
	client    *http.Client
	base      *url.URL
	token     string
	remaining int64
	minPoll   *time.Duration
}

func (reader *gitlabReader) get(ctx context.Context, path string, query url.Values) ([]byte, http.Header, error) {
	endpoint := *reader.base
	endpoint.Path = "/api/v4" + path
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, nil, errors.New("construct GitLab Todos request failed")
	}
	req.Header.Set("PRIVATE-TOKEN", reader.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "loop-event-bridge")
	response, err := reader.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, errors.New("GitLab Todos request failed")
	}
	defer response.Body.Close()
	if gitlabMustWait(response.Header) || response.StatusCode == http.StatusTooManyRequests {
		*reader.minPoll = max(*reader.minPoll, gitlabRetryDelay(response.Header, time.Now()))
	}
	// Error bodies can include tokens or private data. Do not decode, retain or
	// return them; close immediately so even oversized error responses are safe.
	if response.StatusCode != http.StatusOK {
		httpErr := &GitLabHTTPError{StatusCode: response.StatusCode}
		httpErr.RateLimited = response.StatusCode == http.StatusTooManyRequests || (response.StatusCode == http.StatusForbidden && gitlabMustWait(response.Header))
		if httpErr.RateLimited {
			httpErr.RetryAfter = *reader.minPoll
		}
		return nil, nil, httpErr
	}
	limit := min(int64(gitlabMaxBody), reader.remaining)
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, errors.New("read GitLab Todos response failed")
	}
	if int64(len(body)) > limit {
		return nil, nil, errors.New("GitLab Todos response or scan body budget exceeded")
	}
	reader.remaining -= int64(len(body))
	return body, response.Header, nil
}

func gitlabMustWait(header http.Header) bool {
	return header.Get("RateLimit-Remaining") == "0" || header.Get("X-RateLimit-Remaining") == "0" || header.Get("Retry-After") != ""
}

func gitlabRetryDelay(header http.Header, now time.Time) time.Duration {
	delay := time.Minute
	if seconds, err := strconv.ParseInt(header.Get("Retry-After"), 10, 64); err == nil && seconds >= 0 {
		const maxDuration = time.Duration(1<<63 - 1)
		if seconds > int64(maxDuration/time.Second) {
			return maxDuration
		}
		delay = max(delay, time.Duration(seconds)*time.Second)
	} else if until, err := http.ParseTime(header.Get("Retry-After")); err == nil {
		delay = max(delay, until.Sub(now))
	}
	for _, name := range []string{"RateLimit-Reset", "X-RateLimit-Reset"} {
		if seconds, err := strconv.ParseInt(header.Get(name), 10, 64); err == nil && seconds > 0 {
			delay = max(delay, time.Unix(seconds, 0).Sub(now))
		}
	}
	if until, err := http.ParseTime(header.Get("RateLimit-ResetTime")); err == nil {
		delay = max(delay, until.Sub(now))
	}
	return delay
}

func gitlabHasNextPage(header http.Header, page, count int) (bool, error) {
	link := strings.Join(header.Values("Link"), ",")
	next := header.Get("X-Next-Page")
	if next != "" {
		value, err := strconv.Atoi(next)
		if err != nil || value != page+1 {
			return false, errors.New("GitLab returned invalid Todos pagination")
		}
		return true, nil
	}
	if githubHasNextLink(link) {
		return true, nil
	}
	// An explicit empty next-page header indicates completion. When a proxy
	// strips pagination metadata, a full page requires one further request.
	_, hasNextHeader := header[http.CanonicalHeaderKey("X-Next-Page")]
	return !hasNextHeader && link == "" && count >= gitlabPageSize, nil
}

func addGitLabTodo(all map[string]Observation, base *url.URL, account gitlabAccount, item gitlabTodo) error {
	if item.ID <= 0 || item.CreatedAt.IsZero() || item.State != "pending" || item.Action == "" || item.TargetType == "" || len(item.Action) > 256 || len(item.TargetType) > 256 || len(item.Project.Path) > 4096 {
		return errors.New("GitLab returned an incomplete Todo")
	}
	title := item.Target.Title
	if title == "" {
		title = item.Body
	}
	// Reject unbounded display text instead of enqueueing an undeliverable event.
	if len(title) > 32<<10 {
		return errors.New("GitLab returned an oversized Todo title")
	}
	updated := item.UpdatedAt
	if updated.IsZero() {
		updated = item.CreatedAt
	}
	data := map[string]any{
		"kind": "todo", "todo_id": strconv.FormatInt(item.ID, 10),
		"account_id": strconv.FormatInt(account.ID, 10), "account_username": account.Username,
		"instance_url": base.String(), "project": item.Project.Path,
		"target_type": item.TargetType, "title": title,
		"action": item.Action, "state": item.State,
		"created_at": item.CreatedAt.UTC().Format(time.RFC3339Nano),
		"updated_at": updated.UTC().Format(time.RFC3339Nano),
	}
	if safe := gitlabTodoURL(item.TargetURL, base); safe != "" {
		data["url"] = safe
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return errors.New("encode GitLab Todo fingerprint failed")
	}
	digest := sha256.Sum256(encoded)
	originDigest := sha256.Sum256([]byte(base.String()))
	key := "gitlab:instance:" + hex.EncodeToString(originDigest[:]) + ":account:" + strconv.FormatInt(account.ID, 10) + ":todo:" + strconv.FormatInt(item.ID, 10)
	observation := Observation{Key: key, Fingerprint: hex.EncodeToString(digest[:]), Timestamp: updated.UTC(), Data: data}
	if previous, exists := all[key]; exists && previous.Fingerprint != observation.Fingerprint {
		return errors.New("GitLab Todos changed during pagination; retry the poll")
	}
	all[key] = observation
	return nil
}

func gitlabTodoURL(raw string, origin *url.URL) string {
	if len(raw) > 8192 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != origin.Scheme || !strings.EqualFold(u.Host, origin.Host) || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || !strings.HasPrefix(u.Path, "/") || strings.ContainsAny(u.Path, "\\\r\n\t ") || (u.Fragment != "" && !gitlabNoteFragmentPattern.MatchString(u.Fragment)) {
		return ""
	}
	for _, segment := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ""
		}
	}
	return u.String()
}
