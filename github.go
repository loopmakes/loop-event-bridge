package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	githubPageSize = 100
	githubMaxPages = 100
	githubMaxBody  = 10 << 20
)

// GitHubHTTPError deliberately excludes response text and authentication data.
// RetryAfter is the minimum delay before another attempt when RateLimited is true.
type GitHubHTTPError struct {
	StatusCode  int
	RateLimited bool
	RetryAfter  time.Duration
}

func (e *GitHubHTTPError) Error() string {
	if e.RateLimited {
		return fmt.Sprintf("GitHub API rate limited (HTTP %d; retry after %s)", e.StatusCode, e.RetryAfter)
	}
	return fmt.Sprintf("GitHub API returned HTTP %d", e.StatusCode)
}

type githubUser struct {
	Login string `json:"login"`
}
type githubPull struct {
	Number    int        `json:"number"`
	User      githubUser `json:"user"`
	State     string     `json:"state"`
	Draft     bool       `json:"draft"`
	Title     string     `json:"title"`
	HTMLURL   string     `json:"html_url"`
	UpdatedAt time.Time  `json:"updated_at"`
	MergedAt  *time.Time `json:"merged_at"`
	Head      struct {
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}
type githubReview struct {
	ID          int64      `json:"id"`
	User        githubUser `json:"user"`
	State       string     `json:"state"`
	Body        string     `json:"body"`
	HTMLURL     string     `json:"html_url"`
	CommitID    string     `json:"commit_id"`
	SubmittedAt *time.Time `json:"submitted_at"`
}
type githubComment struct {
	ID          int64      `json:"id"`
	User        githubUser `json:"user"`
	Body        string     `json:"body"`
	HTMLURL     string     `json:"html_url"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Path        string     `json:"path"`
	Line        *int       `json:"line"`
	CommitID    string     `json:"commit_id"`
	ReviewID    int64      `json:"pull_request_review_id"`
	InReplyToID int64      `json:"in_reply_to_id"`
}

type githubReader struct {
	client    *http.Client
	base      *url.URL
	token     string
	remaining *int64
}

var githubRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$`)

// FetchGitHub returns a complete, deterministic snapshot for PRs created by author.
// All requests are GETs. No token, comment body, or review body is returned in Data.
// The caller must persist an initial baseline before emitting changes. Failed polls
// return no observations, so a partial response can never replace that baseline.
//
// baseURL supports a mock API in tests. Production callers should use the fixed
// https://api.github.com origin. Redirects are disabled even for supplied clients.
func FetchGitHub(ctx context.Context, client *http.Client, baseURL, token, repo, author string) ([]Observation, error) {
	repo = strings.ToLower(strings.TrimSpace(repo))
	author = strings.TrimSpace(author)
	if !githubRepositoryPattern.MatchString(repo) || strings.HasSuffix(repo, "/.") || strings.HasSuffix(repo, "/..") {
		return nil, errors.New("GitHub repository must be owner/repository")
	}
	if author == "" {
		return nil, errors.New("GitHub author is required")
	}
	base, err := url.Parse(baseURL)
	if err != nil || base == nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("invalid GitHub API base URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	isolatedClient := *client
	if isolatedClient.Timeout <= 0 {
		isolatedClient.Timeout = 30 * time.Second
	}
	isolatedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	budget := int64(64 << 20)
	reader := githubReader{client: &isolatedClient, base: base, token: token, remaining: &budget}
	root := "/repos/" + repo
	pulls, err := githubList[githubPull](ctx, reader, root+"/pulls", url.Values{"state": {"all"}, "sort": {"created"}, "direction": {"asc"}})
	if err != nil {
		return nil, fmt.Errorf("list GitHub pull requests: %w", err)
	}
	observations := make(map[string]Observation)
	seenPulls := make(map[int]bool)
	for _, pull := range pulls {
		if !strings.EqualFold(pull.User.Login, author) {
			continue
		}
		if pull.Number <= 0 || pull.UpdatedAt.IsZero() || pull.Head.SHA == "" || (pull.State != "open" && pull.State != "closed") {
			return nil, errors.New("GitHub returned an incomplete pull request")
		}
		key := fmt.Sprintf("github:%s:pr:%d", repo, pull.Number)
		baseData := func(kind, link string) map[string]any {
			return map[string]any{"repository": repo, "author": pull.User.Login, "pull_request_number": pull.Number, "kind": kind, "url": link}
		}
		data := baseData("pull_request", pull.HTMLURL)
		data["title"], data["state"], data["draft"] = pull.Title, pull.State, pull.Draft
		data["head_sha"], data["base_ref"], data["merged"] = pull.Head.SHA, pull.Base.Ref, pull.MergedAt != nil
		// updated_at alone changes for conversation activity. Excluding it from
		// the PR fingerprint avoids an extra PR notification for every comment.
		if err := githubAddObservation(observations, key, pull.UpdatedAt, data, data); err != nil {
			return nil, err
		}
		if seenPulls[pull.Number] {
			continue
		}
		seenPulls[pull.Number] = true
		pullPath := fmt.Sprintf("%s/pulls/%d", root, pull.Number)
		reviews, err := githubList[githubReview](ctx, reader, pullPath+"/reviews", nil)
		if err != nil {
			return nil, fmt.Errorf("list GitHub reviews for PR %d: %w", pull.Number, err)
		}
		for _, review := range reviews {
			// Unsubmitted draft reviews have no actual source timestamp and
			// are not public review events. They appear after submission.
			if strings.EqualFold(review.State, "PENDING") {
				continue
			}
			if review.ID <= 0 || review.SubmittedAt == nil || review.SubmittedAt.IsZero() {
				return nil, errors.New("GitHub returned an incomplete submitted review")
			}
			data := baseData("review", review.HTMLURL)
			data["id"], data["actor"], data["state"], data["commit_id"] = review.ID, review.User.Login, review.State, review.CommitID
			fingerprintData := map[string]any{"data": data, "body": review.Body, "submitted_at": review.SubmittedAt}
			if err := githubAddObservation(observations, fmt.Sprintf("%s:review:%d", key, review.ID), *review.SubmittedAt, data, fingerprintData); err != nil {
				return nil, err
			}
		}
		commentLists := []struct {
			kind, path string
			query      url.Values
		}{
			{"issue_comment", fmt.Sprintf("%s/issues/%d/comments", root, pull.Number), nil},
			{"review_comment", pullPath + "/comments", url.Values{"sort": {"created"}, "direction": {"asc"}}},
		}
		for _, list := range commentLists {
			comments, err := githubList[githubComment](ctx, reader, list.path, list.query)
			if err != nil {
				return nil, fmt.Errorf("list GitHub %s for PR %d: %w", list.kind, pull.Number, err)
			}
			for _, comment := range comments {
				if comment.ID <= 0 || comment.UpdatedAt.IsZero() {
					return nil, errors.New("GitHub returned an incomplete comment")
				}
				data := baseData(list.kind, comment.HTMLURL)
				data["id"], data["actor"] = comment.ID, comment.User.Login
				if list.kind == "review_comment" {
					data["path"], data["line"], data["commit_id"] = comment.Path, comment.Line, comment.CommitID
					data["review_id"], data["in_reply_to_id"] = comment.ReviewID, comment.InReplyToID
				}
				fingerprintData := map[string]any{"data": data, "body": comment.Body, "updated_at": comment.UpdatedAt}
				if err := githubAddObservation(observations, fmt.Sprintf("%s:%s:%d", key, list.kind, comment.ID), comment.UpdatedAt, data, fingerprintData); err != nil {
					return nil, err
				}
			}
		}
	}
	result := make([]Observation, 0, len(observations))
	for _, observation := range observations {
		result = append(result, observation)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

func githubAddObservation(all map[string]Observation, key string, timestamp time.Time, data map[string]any, fingerprintData any) error {
	encoded, err := json.Marshal(fingerprintData)
	if err != nil {
		return fmt.Errorf("encode GitHub fingerprint: %w", err)
	}
	digest := sha256.Sum256(encoded)
	observation := Observation{Key: key, Fingerprint: hex.EncodeToString(digest[:]), Timestamp: timestamp.UTC(), Data: data}
	if previous, exists := all[key]; exists {
		if previous.Fingerprint != observation.Fingerprint {
			return errors.New("GitHub data changed during pagination; retry the poll")
		}
		// Stable deduplication if a page boundary repeats an identical object.
		if previous.Timestamp.After(observation.Timestamp) {
			return nil
		}
	}
	all[key] = observation
	return nil
}

func githubList[T any](ctx context.Context, reader githubReader, path string, query url.Values) ([]T, error) {
	if query == nil {
		query = make(url.Values)
	}
	query.Set("per_page", strconv.Itoa(githubPageSize))
	result := make([]T, 0)
	for page := 1; page <= githubMaxPages; page++ {
		query.Set("page", strconv.Itoa(page))
		body, link, err := reader.get(ctx, path, query)
		if err != nil {
			return nil, err
		}
		var items []T
		if len(body) == 0 || strings.TrimSpace(string(body)) == "null" {
			return nil, errors.New("GitHub returned a non-array page")
		}
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, errors.New("GitHub returned an invalid JSON page")
		}
		result = append(result, items...)
		// Build every next request ourselves; never follow a server-supplied
		// pagination URL (which could otherwise send the token elsewhere).
		hasNext := githubHasNextLink(link)
		if !hasNext && (link != "" || len(items) < githubPageSize) {
			return result, nil
		}
	}
	return nil, fmt.Errorf("GitHub pagination exceeded %d pages; refusing a partial snapshot", githubMaxPages)
}

func githubHasNextLink(header string) bool {
	for _, link := range strings.Split(header, ",") {
		for _, parameter := range strings.Split(link, ";")[1:] {
			pair := strings.SplitN(strings.TrimSpace(parameter), "=", 2)
			if len(pair) != 2 || !strings.EqualFold(pair[0], "rel") {
				continue
			}
			for _, relation := range strings.Fields(strings.Trim(pair[1], `"`)) {
				if strings.EqualFold(relation, "next") {
					return true
				}
			}
		}
	}
	return false
}

func (reader githubReader) get(ctx context.Context, path string, query url.Values) ([]byte, string, error) {
	endpoint := *reader.base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawPath = ""
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, "", errors.New("construct GitHub request failed")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "loop-event-bridge")
	if reader.token != "" {
		request.Header.Set("Authorization", "Bearer "+reader.token)
	}
	response, err := reader.client.Do(request)
	if err != nil {
		// Preserve cancellation classification without reflecting a URL or token.
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		return nil, "", errors.New("GitHub request failed")
	}
	defer response.Body.Close()
	limit := int64(githubMaxBody)
	if reader.remaining != nil && *reader.remaining < limit {
		limit = *reader.remaining
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, "", errors.New("read GitHub response failed")
	}
	if int64(len(body)) > limit {
		return nil, "", errors.New("GitHub scan body budget exceeded")
	}
	if reader.remaining != nil {
		*reader.remaining -= int64(len(body))
	}
	if len(body) > githubMaxBody {
		return nil, "", errors.New("GitHub response exceeded 10 MiB")
	}
	if response.StatusCode != http.StatusOK {
		err := &GitHubHTTPError{StatusCode: response.StatusCode}
		lowerBody := strings.ToLower(string(body))
		err.RateLimited = response.StatusCode == http.StatusTooManyRequests || (response.StatusCode == http.StatusForbidden && (response.Header.Get("X-RateLimit-Remaining") == "0" || response.Header.Get("Retry-After") != "" || strings.Contains(lowerBody, "rate limit")))
		if err.RateLimited {
			err.RetryAfter = githubRetryDelay(response.Header, time.Now())
		}
		return nil, "", err
	}
	return body, strings.Join(response.Header.Values("Link"), ","), nil
}

func githubRetryDelay(header http.Header, now time.Time) time.Duration {
	var delay time.Duration
	if retry := header.Get("Retry-After"); retry != "" {
		if seconds, err := strconv.ParseInt(retry, 10, 64); err == nil && seconds >= 0 {
			const maxDuration = time.Duration(1<<63 - 1)
			if seconds > int64(maxDuration/time.Second) {
				delay = maxDuration
			} else {
				delay = time.Duration(seconds) * time.Second
			}
		} else if until, err := http.ParseTime(retry); err == nil {
			delay = until.Sub(now)
		}
	}
	if header.Get("X-RateLimit-Remaining") == "0" {
		if seconds, err := strconv.ParseInt(header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			if remaining := time.Unix(seconds, 0).Sub(now); remaining > delay {
				delay = remaining
			}
		}
	}
	if delay <= 0 {
		return time.Minute
	}
	return delay
}
