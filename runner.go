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

func (b *Bridge) applyObservations(observations []Observation) error {
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	next := b.store.copy()
	b.pruneState(&next, time.Now())
	key := b.repo + "/" + b.author
	baseline := next.Baselines[key]
	now := time.Now().UTC()
	for _, o := range observations {
		seenKey := key + "/" + o.Key
		if next.Seen[seenKey] == o.Fingerprint {
			continue
		}
		next.Seen[seenKey] = o.Fingerprint
		if !baseline {
			continue
		}
		e := Event{ID: "evt_" + randomID(), Name: "github.pull_request.changed", Timestamp: o.Timestamp, Data: o.Data}
		for id, s := range next.Subscriptions {
			if s.Name == e.Name && (b.authorizedOwner == nil || b.authorizedOwner(s.Owner)) && s.Expires.After(now) && s.Arguments.Repository == b.repo && s.Arguments.Author == b.author {
				if len(next.Queue) >= maxQueue {
					return errors.New("queue capacity reached; snapshot not advanced")
				}
				next.Queue = append(next.Queue, Pending{SubscriptionID: id, Event: e, Next: now})
			}
		}
	}
	next.Baselines[key] = true
	next.LastPoll = now
	next.LastError = ""
	return b.store.save(next)
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
			next.Queue = append(next.Queue, Pending{SubscriptionID: id, Event: Event{ID: "evt_" + randomID(), Name: s.Name, Timestamp: now, Data: map[string]any{"repository": b.repo, "author": b.author, "message": "Operator-triggered bridge connectivity test"}}, Next: now})
			n++
		}
	}
	if n == 0 {
		return errors.New("no active bridge.test subscription")
	}
	return b.store.save(next)
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
	body, _ := json.Marshal(item.Event)
	status, _, _ := postSigned(ctx, b.callbacks, s, item.Event.ID, body)
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	next := b.store.copy()
	for i, p := range next.Queue {
		if p.SubscriptionID != item.SubscriptionID || p.Event.ID != item.Event.ID {
			continue
		}
		if status >= 200 && status < 300 {
			next.Queue = append(next.Queue[:i], next.Queue[i+1:]...)
		} else {
			p.Attempts++
			if status == 410 {
				delete(next.Subscriptions, p.SubscriptionID)
			}
			p.Dead = status == 410 || status == 413 || (status >= 400 && status < 500 && status != 408 && status != 429) || p.Attempts >= 8
			p.Next = time.Now().Add(time.Duration(1<<min(p.Attempts, 10)) * time.Second)
			next.Queue[i] = p
			next.LastError = "webhook delivery failed; inspect bridge_status and local state counts"
		}
		break
	}
	if e := b.store.save(next); e != nil {
		log.Print("delivery state persistence failed; delivery may repeat")
	}
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
			pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			observations, err := FetchGitHub(pollCtx, github, "https://api.github.com", token, b.repo, b.author)
			cancel()
			delay := interval
			if err == nil {
				err = b.applyObservations(observations)
			}
			if err != nil {
				failures++
				delay = max(interval, time.Duration(1<<min(failures, 10))*time.Second)
				delay = min(delay, time.Hour)
				var ge *GitHubHTTPError
				if errors.As(err, &ge) && ge.RetryAfter > delay {
					delay = ge.RetryAfter
				}
				b.recordError("GitHub polling or snapshot persistence failed; inspect API access and storage")
			} else {
				failures = 0
			}
			poll.Reset(delay)
		}
	}
}

// Retain at most 100 terminal failures for seven days. Expired/revoked
// subscriptions cannot receive queued events and are removed with their queue.
func (b *Bridge) pruneState(s *State, now time.Time) bool {
	changed := false
	for id, sub := range s.Subscriptions {
		if !sub.Expires.After(now) || (b.authorizedOwner != nil && !b.authorizedOwner(sub.Owner)) {
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
