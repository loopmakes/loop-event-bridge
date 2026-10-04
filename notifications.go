package main

import (
	"context"
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
	// The notifications endpoint has a smaller maximum than most REST lists.
	notificationPageSize = 50
	notificationMaxPages = 100
	notificationMaxBody  = 10 << 20
	notificationBudget   = 64 << 20
)

type githubNotification struct {
	ID         string     `json:"id"`
	Reason     string     `json:"reason"`
	Unread     *bool      `json:"unread"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastReadAt *time.Time `json:"last_read_at"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Subject struct {
		Title            string `json:"title"`
		Type             string `json:"type"`
		URL              string `json:"url"`
		LatestCommentURL string `json:"latest_comment_url"`
	} `json:"subject"`
}

// FetchNotifications reads the authenticated user's entire available inbox,
// including read notifications and every repository, subject type and reason.
// GET /user must match expectedLogin before any inbox request; its numeric ID
// namespaces observations and is returned even for a successful empty inbox.
// GitHub currently requires a classic PAT with notifications (or repo) scope;
// fine-grained PATs and GitHub App tokens do not support this endpoint.
// https://docs.github.com/en/rest/activity/notifications
//
// Every request is a GET. The caller must persist a complete first baseline
// without emitting it. Errors return no observations, so incomplete scans never
// advance that baseline. minPoll is a minimum delay before the next full scan,
// including when err is non-nil. Pagination requests are part of the same scan.
// No conditional requests are made, since a 304 cannot supply a full snapshot.
//
// Production callers must pass the fixed https://api.github.com origin. baseURL
// is injectable for mock tests; redirects and server-supplied next URLs are never
// followed. Tokens and response bodies are never included in errors or logs.
func FetchNotifications(ctx context.Context, client *http.Client, baseURL, token, expectedLogin string) (observations []Observation, accountID string, minPoll time.Duration, err error) {
	minPoll = time.Minute
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, "", minPoll, errors.New("GitHub notifications require an authentication token")
	}
	expectedLogin = strings.TrimSpace(expectedLogin)
	if !notificationLoginPattern.MatchString(expectedLogin) {
		return nil, "", minPoll, errors.New("GitHub notifications require an expected account login")
	}
	base, parseErr := url.Parse(baseURL)
	if parseErr != nil || base == nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || base.RawPath != "" || (base.Path != "" && base.Path != "/") {
		return nil, "", minPoll, errors.New("invalid GitHub notifications API origin")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	isolatedClient := *client
	if isolatedClient.Timeout <= 0 {
		isolatedClient.Timeout = 30 * time.Second
	}
	isolatedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	reader := notificationReader{client: &isolatedClient, base: base, token: token, remaining: notificationBudget, minPoll: &minPoll}
	identityBody, identityHeaders, identityErr := reader.get(ctx, "/user", nil)
	if identityErr != nil {
		return nil, "", minPoll, identityErr
	}
	var account notificationAccount
	if json.Unmarshal(identityBody, &account) != nil || account.ID <= 0 || !notificationLoginPattern.MatchString(account.Login) {
		return nil, "", minPoll, errors.New("GitHub returned an invalid authenticated account")
	}
	if !strings.EqualFold(account.Login, expectedLogin) {
		return nil, "", minPoll, errors.New("GitHub token account does not match configured account")
	}
	if notificationMustWait(identityHeaders) {
		return nil, "", minPoll, &GitHubHTTPError{StatusCode: http.StatusOK, RateLimited: true, RetryAfter: minPoll}
	}
	accountID = strconv.FormatInt(account.ID, 10)
	all := make(map[string]Observation)
	for page := 1; page <= notificationMaxPages; page++ {
		query := url.Values{
			"all": {"true"}, "participating": {"false"},
			"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(notificationPageSize)},
		}
		body, headers, readErr := reader.get(ctx, "/notifications", query)
		if readErr != nil {
			return nil, "", minPoll, readErr
		}
		var items []githubNotification
		if len(body) == 0 || strings.TrimSpace(string(body)) == "null" {
			return nil, "", minPoll, errors.New("GitHub returned a non-array notifications page")
		}
		if json.Unmarshal(body, &items) != nil {
			return nil, "", minPoll, errors.New("GitHub returned an invalid notifications JSON page")
		}
		for _, notification := range items {
			if err := addNotificationObservation(all, account, notification); err != nil {
				return nil, "", minPoll, err
			}
		}
		link := strings.Join(headers.Values("Link"), ",")
		hasNext := githubHasNextLink(link) || (link == "" && len(items) >= notificationPageSize)
		if !hasNext {
			result := make([]Observation, 0, len(all))
			for _, observation := range all {
				result = append(result, observation)
			}
			sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
			return result, accountID, minPoll, nil
		}
		// A successful response can exhaust the remaining quota. Do not issue
		// another page request until GitHub's reset/retry deadline has elapsed.
		if notificationMustWait(headers) {
			return nil, "", minPoll, &GitHubHTTPError{StatusCode: http.StatusOK, RateLimited: true, RetryAfter: minPoll}
		}
	}
	return nil, "", minPoll, fmt.Errorf("GitHub notifications pagination exceeded %d pages; refusing a partial snapshot", notificationMaxPages)
}

var notificationLoginPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

type notificationAccount struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type notificationReader struct {
	client    *http.Client
	base      *url.URL
	token     string
	remaining int64
	minPoll   *time.Duration
}

func notificationMustWait(header http.Header) bool {
	return header.Get("X-RateLimit-Remaining") == "0" || header.Get("Retry-After") != ""
}

func (reader *notificationReader) get(ctx context.Context, path string, query url.Values) ([]byte, http.Header, error) {
	endpoint := *reader.base
	endpoint.Path, endpoint.RawPath = path, ""
	endpoint.RawQuery = query.Encode()
	request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if requestErr != nil {
		return nil, nil, errors.New("construct GitHub notifications request failed")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "loop-event-bridge")
	request.Header.Set("Authorization", "Bearer "+reader.token)
	response, requestErr := reader.client.Do(request)
	if requestErr != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, errors.New("GitHub notifications request failed")
	}
	*reader.minPoll = max(*reader.minPoll, notificationPollInterval(response.Header))
	body, readErr := readNotificationBody(response.Body, &reader.remaining)
	if readErr != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, readErr
	}
	if response.StatusCode != http.StatusOK {
		httpErr := &GitHubHTTPError{StatusCode: response.StatusCode}
		httpErr.RateLimited = response.StatusCode == http.StatusTooManyRequests || (response.StatusCode == http.StatusForbidden && (notificationMustWait(response.Header) || strings.Contains(strings.ToLower(string(body)), "rate limit")))
		if httpErr.RateLimited {
			httpErr.RetryAfter = max(*reader.minPoll, githubRetryDelay(response.Header, time.Now()))
			*reader.minPoll = max(*reader.minPoll, httpErr.RetryAfter)
		}
		return nil, nil, httpErr
	}
	return body, response.Header, nil
}

func readNotificationBody(body io.ReadCloser, remaining *int64) ([]byte, error) {
	defer body.Close()
	limit := min(int64(notificationMaxBody), *remaining)
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, errors.New("read GitHub notifications response failed")
	}
	if int64(len(data)) > limit {
		return nil, errors.New("GitHub notifications response or scan body budget exceeded")
	}
	*remaining -= int64(len(data))
	return data, nil
}

func notificationPollInterval(header http.Header) time.Duration {
	var delay time.Duration
	if seconds, err := strconv.ParseInt(header.Get("X-Poll-Interval"), 10, 64); err == nil && seconds > 0 {
		const maxDuration = time.Duration(1<<63 - 1)
		if seconds > int64(maxDuration/time.Second) {
			delay = maxDuration
		} else {
			delay = time.Duration(seconds) * time.Second
		}
	}
	if header.Get("Retry-After") != "" || header.Get("X-RateLimit-Remaining") == "0" {
		delay = max(delay, githubRetryDelay(header, time.Now()))
	}
	return delay
}

func addNotificationObservation(all map[string]Observation, account notificationAccount, notification githubNotification) error {
	if !notificationDecimalID(notification.ID) || notification.UpdatedAt.IsZero() || notification.Unread == nil || notification.Subject.Type == "" {
		return errors.New("GitHub returned an incomplete notification")
	}
	var lastRead any
	if notification.LastReadAt != nil {
		lastRead = notification.LastReadAt.UTC().Format(time.RFC3339Nano)
	}
	data := map[string]any{
		"kind": "notification", "notification_id": notification.ID,
		"account_login": account.Login, "account_id": strconv.FormatInt(account.ID, 10),
		"repository":   notification.Repository.FullName,
		"subject_type": notification.Subject.Type, "title": notification.Subject.Title,
		"reason": notification.Reason, "unread": *notification.Unread,
		"updated_at": notification.UpdatedAt.UTC().Format(time.RFC3339Nano), "last_read_at": lastRead,
		"api_url": "https://api.github.com/notifications/threads/" + notification.ID,
	}
	if safeURL := notificationAPIURL(notification.Subject.URL); safeURL != "" {
		data["subject_api_url"] = safeURL
	}
	if safeURL := notificationAPIURL(notification.Subject.LatestCommentURL); safeURL != "" {
		data["latest_comment_api_url"] = safeURL
	}
	if webURL := notificationWebURL(notification.Repository.FullName, notification.Subject.Type, notification.Subject.URL); webURL != "" {
		data["url"] = webURL
	}
	occurredAt := notification.UpdatedAt
	if notification.LastReadAt != nil && notification.LastReadAt.After(occurredAt) {
		occurredAt = *notification.LastReadAt
	}
	return githubAddObservation(all, "github:account:"+strconv.FormatInt(account.ID, 10)+":notification:"+notification.ID, occurredAt, data, data)
}

func notificationDecimalID(id string) bool {
	if id == "" || id[0] == '0' {
		return false
	}
	for _, digit := range id {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// Only return links on the trusted public API origin, without user information,
// query strings, fragments, encoded path characters or dot path segments.
func notificationAPIURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Host != "api.github.com" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/") || strings.ContainsAny(u.Path, "\\\r\n\t ") {
		return ""
	}
	for _, segment := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ""
		}
	}
	return u.String()
}

// Releases and other subjects need another lookup to find their browser URL.
// Omit it rather than guessing, filtering the thread or making extra API calls.
func notificationWebURL(repository, subjectType, raw string) string {
	if !githubRepositoryPattern.MatchString(repository) || strings.HasSuffix(repository, "/.") || strings.HasSuffix(repository, "/..") || notificationAPIURL(raw) == "" {
		return ""
	}
	u, _ := url.Parse(raw)
	prefix := "/repos/" + repository + "/"
	if !strings.HasPrefix(u.Path, prefix) {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, prefix), "/")
	if len(parts) != 2 {
		return ""
	}
	webPath := ""
	switch subjectType {
	case "Issue":
		if parts[0] == "issues" && notificationDecimalID(parts[1]) {
			webPath = "issues/" + parts[1]
		}
	case "PullRequest":
		if parts[0] == "pulls" && notificationDecimalID(parts[1]) {
			webPath = "pull/" + parts[1]
		}
	case "Discussion":
		if parts[0] == "discussions" && notificationDecimalID(parts[1]) {
			webPath = "discussions/" + parts[1]
		}
	case "Commit":
		if parts[0] == "commits" && len(parts[1]) == 40 && strings.Trim(parts[1], "0123456789abcdefABCDEF") == "" {
			webPath = "commit/" + parts[1]
		}
	}
	if webPath == "" {
		return ""
	}
	return "https://github.com/" + repository + "/" + webPath
}
