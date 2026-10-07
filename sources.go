package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
)

// SourceBatch is committed atomically with its outbox entries. Cursor is opaque
// source state, never a downstream replay cursor or an authentication secret.
type SourceBatch struct {
	Observations []Observation
	AccountID    string
	Cursor       string
	MinimumPoll  time.Duration
	Baseline     bool
}
type SourceAdapter interface {
	Poll(context.Context, string) (SourceBatch, error)
}
type sourceConfig struct {
	Name, Namespace, EventName string
	Adapter                    SourceAdapter
	InitError                  bool
	InitDiagnostic             sourceInitDiagnostic
}

// Only allowlisted local reasons survive initialization; never save an
// arbitrary provider, filesystem, or credential error for logs/status.
type sourceInitDiagnostic uint8

const (
	sourceInitUnknown sourceInitDiagnostic = iota
	sourceInitProtonAppVersion
)

func (source sourceConfig) initializationError() error {
	if source.InitDiagnostic == sourceInitProtonAppVersion {
		return &protonAppVersionConfigError{}
	}
	return errors.New("source configuration unavailable")
}

type SourceState struct {
	AccountID   string
	Cursor      string
	Baseline    bool
	LastPoll    time.Time
	LastError   string
	Failures    int
	NeedsAction bool
}
type sourceStatus struct {
	Enabled     bool      `json:"enabled"`
	LastPoll    time.Time `json:"lastPoll"`
	LastError   string    `json:"lastError"`
	Failures    int       `json:"failures"`
	NeedsAction bool      `json:"needsAction"`
}

func knownEvent(name string) bool {
	switch name {
	case "bridge.test", "github.notification.changed", "gitlab.todo.changed", "proton.mail.received":
		return true
	}
	return false
}
func (b *Bridge) eventEnabled(name string) bool {
	if name == "bridge.test" {
		return true
	}
	if name == "github.notification.changed" {
		return !b.githubDisabled
	}
	for _, source := range b.sources {
		if source.EventName == name {
			return true
		}
	}
	return false
}

func (b *Bridge) sourceStatusesLocked() map[string]sourceStatus {
	github := b.store.state.Sources["github"]
	if github.LastPoll.IsZero() && github.LastError == "" {
		github.LastPoll = b.store.state.LastPoll
		github.LastError = b.store.state.LastError
	}
	out := map[string]sourceStatus{
		"github": {Enabled: !b.githubDisabled, LastPoll: github.LastPoll, LastError: github.LastError, Failures: github.Failures},
		"gitlab": {}, "proton": {},
	}
	for _, source := range b.sources {
		state := b.store.state.Sources[source.Namespace]
		status := sourceStatus{Enabled: true, LastPoll: state.LastPoll, LastError: state.LastError, Failures: state.Failures, NeedsAction: state.NeedsAction}
		if source.InitError {
			status.LastError = source.initializationError().Error()
			status.NeedsAction = true
		}
		out[source.Name] = status
	}
	return out
}

func (b *Bridge) applySourceBatch(source sourceConfig, batch SourceBatch) (pollStats, error) {
	if batch.AccountID == "" || len(batch.Cursor) > 1<<20 {
		return pollStats{}, errors.New("invalid source checkpoint")
	}
	b.store.mu.Lock()
	defer b.store.mu.Unlock()
	next := b.store.copy()
	if next.Sources == nil {
		next.Sources = map[string]SourceState{}
	}
	state := next.Sources[source.Namespace]
	if state.AccountID != "" && state.AccountID != batch.AccountID {
		return pollStats{}, errors.New("source account changed; checkpoint not advanced")
	}
	b.pruneState(&next, time.Now())
	queueStart := len(next.Queue)
	stats := pollStats{Observed: len(batch.Observations)}
	now := time.Now().UTC()
	prefix := "source/" + source.Namespace + "/" + digest(batch.AccountID) + "/"
	baseline := state.Baseline && !batch.Baseline
	for _, observation := range batch.Observations {
		if observation.Key == "" || observation.Fingerprint == "" || observation.Timestamp.IsZero() {
			return pollStats{}, errors.New("invalid source observation")
		}
		key := prefix + observation.Key
		if next.Seen[key] == observation.Fingerprint {
			stats.Unchanged++
			continue
		}
		next.Seen[key] = observation.Fingerprint
		if !baseline {
			stats.Baseline++
			continue
		}
		stats.Changed++
		event := Event{ID: "evt_" + randomID(), Name: source.EventName, Timestamp: observation.Timestamp, Data: observation.Data}
		for id, subscription := range next.Subscriptions {
			if subscription.Name != event.Name || !subscription.Expires.After(now) || (b.authorizedOwner != nil && !b.authorizedOwner(subscription.Owner)) {
				continue
			}
			if len(next.Queue) >= maxQueue {
				return pollStats{}, errors.New("queue capacity reached; checkpoint not advanced")
			}
			next.Queue = append(next.Queue, Pending{SubscriptionID: id, Event: event, Next: now})
			stats.Enqueued++
		}
	}
	next.Sources[source.Namespace] = SourceState{AccountID: batch.AccountID, Cursor: batch.Cursor, Baseline: true, LastPoll: now}
	if err := b.store.save(next); err != nil {
		return pollStats{}, err
	}
	logEnqueuedEvents(next.Queue[queueStart:])
	return stats, nil
}

func (b *Bridge) sourcePollOnce(ctx context.Context, source sourceConfig, interval time.Duration, failures int) (time.Duration, int) {
	b.store.mu.Lock()
	checkpoint := b.store.state.Sources[source.Namespace]
	cursor := checkpoint.Cursor
	b.store.mu.Unlock()
	started := time.Now()
	var batch SourceBatch
	var err error
	if source.Name == "proton" && checkpoint.Baseline && cursor == "" {
		err = errors.New("Proton checkpoint missing; refusing a fresh baseline")
	} else if source.InitError || source.Adapter == nil {
		err = source.initializationError()
	} else {
		pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		batch, err = source.Adapter.Poll(pollCtx, cursor)
		cancel()
	}
	stats := pollStats{}
	if err == nil {
		stats, err = b.applySourceBatch(source, batch)
	}
	if ctx.Err() != nil {
		return interval, failures
	}
	if err != nil {
		failures++
		b.store.mu.Lock()
		next := b.store.copy()
		if next.Sources == nil {
			next.Sources = map[string]SourceState{}
		}
		state := next.Sources[source.Namespace]
		state.LastError = "source polling failed; check source configuration or reauthenticate"
		var authRequired *ProtonAuthRequiredError
		state.NeedsAction = errors.As(err, &authRequired)
		var appVersionConfig *protonAppVersionConfigError
		invalidAppVersion := errors.As(err, &appVersionConfig)
		var authDiagnostic *protonAuthError
		_ = errors.As(err, &authDiagnostic)
		if state.NeedsAction {
			state.LastError = authRequired.Error()
			authDiagnostic = authRequired.diagnostic
		} else if authDiagnostic != nil {
			state.LastError = authDiagnostic.Error()
		}
		if invalidAppVersion {
			state.NeedsAction = true
			state.LastError = appVersionConfig.Error()
		}
		state.Failures = failures
		next.Sources[source.Namespace] = state
		if b.store.save(next) != nil {
			log.Print("source status persistence failed")
		}
		b.store.mu.Unlock()
		// Never log provider errors: URLs, credentials and response contents may occur.
		log.Printf("source poll failed source=%s failures=%d", source.Name, failures)
		if authDiagnostic != nil {
			log.Printf("source authentication diagnostic source=%s stage=%s http_status=%d api_code=%d", source.Name, authDiagnostic.stage, authDiagnostic.httpStatus, authDiagnostic.apiCode)
		}
		if invalidAppVersion {
			log.Printf("source configuration diagnostic source=%s reason=invalid_application_version stage=configuration http_status=0 api_code=0", source.Name)
		}
	} else {
		failures = 0
		log.Printf("source poll complete source=%s observed=%d changed=%d baseline=%d enqueued=%d duration=%s", source.Name, stats.Observed, stats.Changed, stats.Baseline, stats.Enqueued, time.Since(started).Round(time.Millisecond))
	}
	return nextPollDelay(interval, batch.MinimumPoll, failures), failures
}
func (b *Bridge) sourceLoop(ctx context.Context, source sourceConfig, interval time.Duration) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			delay, nextFailures := b.sourcePollOnce(ctx, source, interval, failures)
			failures = nextFailures
			timer.Reset(delay)
		}
	}
}

type gitlabAdapter struct {
	client                 *http.Client
	origin, token, account string
}

func (a *gitlabAdapter) Poll(ctx context.Context, _ string) (SourceBatch, error) {
	observations, id, minimum, err := FetchGitLabTodos(ctx, a.client, a.origin, a.token, a.account)
	return SourceBatch{Observations: observations, AccountID: id, MinimumPoll: minimum}, err
}
