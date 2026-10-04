package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
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

var githubRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$`)

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
