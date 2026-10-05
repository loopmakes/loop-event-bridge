package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"
)

const maxQueue = 10000

type pollStats struct {
	Observed, Changed, Unchanged, Baseline, Enqueued int
}

func (b *Bridge) applyObservations(observations []Observation, accountID string) error {
	_, err := b.applyObservationsCounted(observations, accountID)
	return err
}

// Counts describe only a successfully persisted snapshot. Baseline records are
// deliberately separate from changes because initial history emits no events.
func (b *Bridge) applyObservationsCounted(observations []Observation, accountID string) (pollStats, error) {
	stats := pollStats{Observed: len(observations)}
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	next := b.store.copy()
	b.pruneState(&next, time.Now())
	if accountID == "" {
		return pollStats{}, errors.New("GitHub account identity missing")
	}
	key := "notifications/" + accountID
	baseline := next.Baselines[key]
	now := time.Now().UTC()
	for _, o := range observations {
		seenKey := key + "/" + o.Key
		if next.Seen[seenKey] == o.Fingerprint {
			stats.Unchanged++
			continue
		}
		next.Seen[seenKey] = o.Fingerprint
		if !baseline {
			stats.Baseline++
			continue
		}
		stats.Changed++
		e := Event{ID: "evt_" + randomID(), Name: "github.notification.changed", Timestamp: o.Timestamp, Data: o.Data}
		for id, s := range next.Subscriptions {
			if s.Name == e.Name && (b.authorizedOwner == nil || b.authorizedOwner(s.Owner)) && s.Expires.After(now) {
				if len(next.Queue) >= maxQueue {
					return pollStats{}, errors.New("queue capacity reached; snapshot not advanced")
				}
				next.Queue = append(next.Queue, Pending{SubscriptionID: id, Event: e, Next: now})
				stats.Enqueued++
			}
		}
	}
	next.Baselines[key] = true
	next.LastPoll = now
	next.LastError = ""
	if err := b.store.save(next); err != nil {
		return pollStats{}, err
	}
	return stats, nil
}
func (b *Bridge) enqueueTest() error {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	next := b.store.copy()
	now := time.Now().UTC()
	n := 0
	for id, s := range next.Subscriptions {
		if s.Name == "bridge.test" && (b.authorizedOwner == nil || b.authorizedOwner(s.Owner)) && s.Expires.After(now) {
			if len(next.Queue) >= maxQueue {
				return errors.New("queue full")
			}
			next.Queue = append(next.Queue, Pending{SubscriptionID: id, Event: Event{ID: "evt_" + randomID(), Name: s.Name, Timestamp: now, Data: map[string]any{"message": "Operator-triggered bridge connectivity test"}}, Next: now})
			n++
		}
	}
	if n == 0 {
		return errors.New("no active bridge.test subscription")
	}
	if err := b.store.save(next); err != nil {
		return err
	}
	log.Printf("bridge test queued enqueued=%d", n)
	return nil
}
func (b *Bridge) recordError(message string) {
	log.Print(message)
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	n := b.store.copy()
	n.LastError = message
	if e := b.store.save(n); e != nil {
		log.Print("state persistence failed")
	}
}
func (b *Bridge) deliverOne(ctx context.Context) {
	b.store.mu.Lock()
	now := time.Now()
	var item Pending
	var s Subscription
	found := false
	for _, p := range b.store.state.Queue {
		if p.Dead || p.Next.After(now) {
			continue
		}
		sub, ok := b.store.state.Subscriptions[p.SubscriptionID]
		if !ok || validCallback(sub.Delivery.URL, b.hosts) != nil || !sub.Expires.After(now) || (b.authorizedOwner != nil && !b.authorizedOwner(sub.Owner)) {
			continue
		}
		item = p
		s = sub
		found = true
		break
	}
	b.store.mu.Unlock()
	if !found {
		return
	}
	started := time.Now()
	body, _ := json.Marshal(item.Event)
	status, _, _ := postSigned(ctx, b.callbacks, s, item.Event.ID, body)
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	next := b.store.copy()
	outcome := "discarded"
	retryAfter := time.Duration(0)
	for i, p := range next.Queue {
		if p.SubscriptionID != item.SubscriptionID || p.Event.ID != item.Event.ID {
			continue
		}
		if status >= 200 && status < 300 {
			outcome = "success"
			next.Queue = append(next.Queue[:i], next.Queue[i+1:]...)
		} else {
			p.Attempts++
			if status == 410 {
				delete(next.Subscriptions, p.SubscriptionID)
			}
			p.Dead = status == 410 || status == 413 || (status >= 400 && status < 500 && status != 408 && status != 429) || p.Attempts >= 8
			p.Next = time.Now().Add(time.Duration(1<<min(p.Attempts, 10)) * time.Second)
			outcome = "retry"
			retryAfter = time.Until(p.Next)
			if p.Dead {
				outcome = "failed"
				retryAfter = 0
			}
			next.Queue[i] = p
			next.LastError = "webhook delivery failed; inspect bridge_status and local state counts"
		}
		break
	}
	persisted := b.store.save(next) == nil
	if !persisted {
		log.Print("delivery state persistence failed; delivery may repeat")
	}
	httpStatus := status
	if len(body) > 262144 {
		httpStatus = 0
	} // local size rejection, no HTTP request
	pending, dead := queueCounts(b.store.state.Queue)
	log.Printf("webhook delivery outcome=%s http_status=%d attempt=%d duration=%s retry_in=%s state_saved=%t pending=%d dead=%d", outcome, httpStatus, item.Attempts+1, time.Since(started).Round(time.Millisecond), retryAfter.Round(time.Millisecond), persisted, pending, dead)
}
func (b *Bridge) run(ctx context.Context, github *http.Client, token string, interval time.Duration) {
	go b.pollLoop(ctx, github, token, interval)
	delivery := time.NewTicker(time.Second)
	defer delivery.Stop()
	maintenance := time.NewTicker(time.Minute)
	defer maintenance.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-delivery.C:
			b.deliverOne(ctx)
		case <-maintenance.C:
			b.maintenance()
		}
	}
}
func (b *Bridge) pollLoop(ctx context.Context, github *http.Client, token string, interval time.Duration) {
	poll := time.NewTimer(0)
	defer poll.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			delay, nextFailures := b.pollOnce(ctx, github, token, interval, failures)
			failures = nextFailures
			poll.Reset(delay)
		}
	}
}

// pollOnce emits a bounded, content-free lifecycle even for an empty or unchanged inbox.
func (b *Bridge) pollOnce(ctx context.Context, github *http.Client, token string, interval time.Duration, failures int) (time.Duration, int) {
	started := time.Now()
	log.Print("GitHub inbox poll started")
	pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	observations, accountID, minPoll, err := FetchNotifications(pollCtx, github, "https://api.github.com", token, b.account)
	cancel()
	stage := "fetch"
	stats := pollStats{}
	if err == nil {
		stage = "persist"
		stats, err = b.applyObservationsCounted(observations, accountID)
	}
	delay := nextPollDelay(interval, minPoll, 0)
	if err != nil {
		failures++
		delay = nextPollDelay(interval, minPoll, failures)
		status := 0
		rateLimited := false
		var ge *GitHubHTTPError
		if errors.As(err, &ge) {
			status, rateLimited = ge.StatusCode, ge.RateLimited
			delay = max(delay, ge.RetryAfter)
		}
		// Filesystem/transport errors can contain paths, URLs or credentials. Never
		// print err here; the stage, status and counters are enough for triage.
		b.recordError("GitHub inbox polling failed during " + stage + "; inspect configuration and service health")
		log.Printf("GitHub inbox poll failed stage=%s http_status=%d rate_limited=%t failures=%d duration=%s next_poll_in=%s", stage, status, rateLimited, failures, time.Since(started).Round(time.Millisecond), delay)
	} else {
		failures = 0
		log.Printf("GitHub inbox poll complete observed=%d changed=%d unchanged=%d baseline=%d enqueued=%d duration=%s next_poll_in=%s", stats.Observed, stats.Changed, stats.Unchanged, stats.Baseline, stats.Enqueued, time.Since(started).Round(time.Millisecond), delay)
	}
	return delay, failures
}

func queueCounts(queue []Pending) (pending, dead int) {
	for _, p := range queue {
		if p.Dead {
			dead++
		} else {
			pending++
		}
	}
	return
}

// Retain at most 100 terminal failures for seven days. Expired/revoked
// subscriptions cannot receive queued events and are removed with their queue.
func (b *Bridge) pruneState(s *State, now time.Time) bool {
	changed := false
	for id, sub := range s.Subscriptions {
		if (sub.Name != "bridge.test" && sub.Name != "github.notification.changed") || !sub.Expires.After(now) || (b.authorizedOwner != nil && !b.authorizedOwner(sub.Owner)) {
			delete(s.Subscriptions, id)
			changed = true
		}
	}
	out := make([]Pending, 0, len(s.Queue))
	dead := 0
	for i := len(s.Queue) - 1; i >= 0; i-- {
		p := s.Queue[i]
		_, exists := s.Subscriptions[p.SubscriptionID]
		if !exists {
			changed = true
			continue
		}
		if p.Dead {
			dead++
			if dead > 100 || p.Next.Before(now.Add(-7*24*time.Hour)) {
				changed = true
				continue
			}
		}
		out = append(out, p)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	s.Queue = out
	return changed
}
func (b *Bridge) maintenance() {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	next := b.store.copy()
	if b.pruneState(&next, time.Now()) {
		if b.store.save(next) != nil {
			log.Print("maintenance persistence failed")
		}
	}
}

func nextPollDelay(interval, sourceMinimum time.Duration, failures int) time.Duration {
	delay := max(interval, sourceMinimum)
	if failures > 0 {
		delay = max(delay, min(time.Hour, time.Duration(1<<min(failures, 12))*time.Second))
	}
	return delay
}
