package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
)

type protonFakeMailbox struct {
	latest    string
	latestErr error
	events    func(string) ([]proton.Event, bool, error)
	metadata  func(proton.MessageFilter) ([]proton.MessageMetadata, error)
	calls     []string
}

func (f *protonFakeMailbox) GetLatestEventID(context.Context) (string, error) {
	f.calls = append(f.calls, "latest")
	return f.latest, f.latestErr
}
func (f *protonFakeMailbox) GetEvent(_ context.Context, id string) ([]proton.Event, bool, error) {
	f.calls = append(f.calls, "event:"+id)
	return f.events(id)
}
func (f *protonFakeMailbox) GetMessageMetadataPage(_ context.Context, page, size int, filter proton.MessageFilter) ([]proton.MessageMetadata, error) {
	f.calls = append(f.calls, "metadata:"+filter.EndID)
	if page != 0 || size != protonPageSize || !bool(filter.Desc) {
		return nil, errors.New("unexpected pagination")
	}
	return f.metadata(filter)
}
func fakeProtonAdapter(f *protonFakeMailbox) *ProtonAdapter {
	return &ProtonAdapter{mailbox: f, accountID: "account", config: ProtonConfig{AccountID: "account"}}
}
func protonTestCursor(id string) string {
	b, _ := json.Marshal(protonCursor{Version: 1, AccountID: "account", EventID: id})
	return string(b)
}
func protonTestMessage(id string) proton.MessageMetadata {
	return proton.MessageMetadata{ID: id, Flags: proton.MessageFlagReceived, Time: 1700000000, Subject: "PRIVATE_SUBJECT", LabelIDs: []string{proton.InboxLabel}}
}
func protonTestEvent(eventID, messageID string, action proton.EventAction) proton.Event {
	return proton.Event{EventID: eventID, Messages: []proton.MessageEvent{{EventItem: proton.EventItem{ID: messageID, Action: action}, Message: protonTestMessage(messageID)}}}
}

func TestProtonBaselineUsesMetadataAndLatestCheckpoint(t *testing.T) {
	fake := &protonFakeMailbox{latest: "latest", metadata: func(proton.MessageFilter) ([]proton.MessageMetadata, error) {
		return []proton.MessageMetadata{protonTestMessage("old")}, nil
	}}
	batch, err := fakeProtonAdapter(fake).Poll(context.Background(), "")
	if err != nil || !batch.Baseline || batch.AccountID != "account" || batch.Cursor != protonTestCursor("latest") || len(batch.Observations) != 1 {
		t.Fatalf("baseline: %+v %v", batch, err)
	}
	if !reflect.DeepEqual(fake.calls, []string{"latest", "metadata:"}) {
		t.Fatalf("checkpoint not before scan: %v", fake.calls)
	}
	encoded, _ := json.Marshal(batch)
	if strings.Contains(string(encoded), "PRIVATE_SUBJECT") || strings.Contains(string(encoded), "LabelIDs") {
		t.Fatal("private metadata escaped")
	}
	if len(batch.Observations[0].Data) != 2 {
		t.Fatal("nonminimal payload")
	}
}
func TestProtonIncomingCreatesOnlyAndStableFingerprint(t *testing.T) {
	event := protonTestEvent("new", "incoming", proton.EventCreate)
	for i, action := range []proton.EventAction{proton.EventUpdate, proton.EventUpdateFlags, proton.EventDelete} {
		event.Messages = append(event.Messages, protonTestEvent("unused", fmt.Sprintf("update%d", i), action).Messages[0])
	}
	for i, flags := range []proton.MessageFlag{0, proton.MessageFlagSent, proton.MessageFlagReceived | proton.MessageFlagSent, proton.MessageFlagReceived | proton.MessageFlagImported} {
		m := protonTestEvent("unused", fmt.Sprintf("skip%d", i), proton.EventCreate).Messages[0]
		m.Message.Flags = flags
		event.Messages = append(event.Messages, m)
	}
	for i, label := range []string{proton.DraftsLabel, proton.AllDraftsLabel, proton.SentLabel, proton.AllSentLabel, proton.OutboxLabel} {
		m := protonTestEvent("unused", fmt.Sprintf("label%d", i), proton.EventCreate).Messages[0]
		m.Message.LabelIDs = []string{label}
		event.Messages = append(event.Messages, m)
	}
	event.Messages = append(event.Messages, event.Messages[0])
	fake := &protonFakeMailbox{events: func(string) ([]proton.Event, bool, error) { return []proton.Event{event}, false, nil }}
	batch, err := fakeProtonAdapter(fake).Poll(context.Background(), protonTestCursor("old"))
	if err != nil || batch.Baseline || len(batch.Observations) != 1 || batch.Observations[0].Key != "incoming" {
		t.Fatalf("incoming: %+v %v", batch, err)
	}
	changed := protonTestMessage("incoming")
	changed.Time++
	changed.Subject = "different"
	changed.LabelIDs = []string{proton.ArchiveLabel}
	second, err := protonObservation(changed)
	if err != nil || second.Fingerprint != batch.Observations[0].Fingerprint {
		t.Fatal("fingerprint changed with metadata")
	}
}
func TestProtonReconcilesExpiredCursorWithoutResetBaseline(t *testing.T) {
	for _, mode := range []string{"refresh", "notfound", "gone"} {
		t.Run(mode, func(t *testing.T) {
			fake := &protonFakeMailbox{latest: "reconciled", metadata: func(proton.MessageFilter) ([]proton.MessageMetadata, error) {
				return []proton.MessageMetadata{protonTestMessage("old"), protonTestMessage("new")}, nil
			}}
			fake.events = func(string) ([]proton.Event, bool, error) {
				if mode == "refresh" {
					return []proton.Event{{EventID: "expired", Refresh: proton.RefreshMail}}, false, nil
				}
				status := http.StatusNotFound
				if mode == "gone" {
					status = http.StatusGone
				}
				return nil, false, &proton.APIError{Status: status}
			}
			batch, err := fakeProtonAdapter(fake).Poll(context.Background(), protonTestCursor("old-cursor"))
			if err != nil || batch.Baseline || batch.Cursor != protonTestCursor("reconciled") || len(batch.Observations) != 2 {
				t.Fatalf("reconcile: %+v %v", batch, err)
			}
		})
	}
}
func TestProtonSnapshotInclusiveAnchorAndIncompleteFailure(t *testing.T) {
	fake := &protonFakeMailbox{latest: "latest"}
	fake.metadata = func(filter proton.MessageFilter) ([]proton.MessageMetadata, error) {
		if filter.EndID == "m99" {
			return []proton.MessageMetadata{protonTestMessage("m99"), protonTestMessage("m100")}, nil
		}
		out := []proton.MessageMetadata{}
		for i := 0; i < 100; i++ {
			out = append(out, protonTestMessage(fmt.Sprintf("m%d", i)))
		}
		return out, nil
	}
	batch, err := fakeProtonAdapter(fake).Poll(context.Background(), "")
	if err != nil || len(batch.Observations) != 101 {
		t.Fatalf("inclusive pagination: %d %v", len(batch.Observations), err)
	}
	fake.metadata = func(filter proton.MessageFilter) ([]proton.MessageMetadata, error) {
		if filter.EndID != "" {
			return nil, errors.New("private upstream detail")
		}
		out := make([]proton.MessageMetadata, 100)
		for i := range out {
			out[i] = protonTestMessage(fmt.Sprintf("m%d", i))
		}
		return out, nil
	}
	batch, err = fakeProtonAdapter(fake).Poll(context.Background(), "")
	if err == nil || batch.Cursor != "" || len(batch.Observations) != 0 || strings.Contains(err.Error(), "private") {
		t.Fatalf("partial snapshot committed: %+v %v", batch, err)
	}
}
func TestProtonRejectsWrongAccountAndInvalidCursorBeforeCalls(t *testing.T) {
	for _, raw := range []string{`{"version":1,"account_id":"other","event_id":"valid"}`, `{"version":1,"account_id":"account","event_id":"../secret"}`, `null`, protonTestCursor("valid") + " garbage"} {
		fake := &protonFakeMailbox{}
		if _, err := fakeProtonAdapter(fake).Poll(context.Background(), raw); err == nil || len(fake.calls) != 0 {
			t.Fatalf("accepted checkpoint %q", raw)
		}
	}
}
func TestProtonPollFailuresDoNotAdvance(t *testing.T) {
	for _, mode := range []string{"network", "empty", "stalled", "badid", "mismatch", "missingtime", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			fake := &protonFakeMailbox{events: func(string) ([]proton.Event, bool, error) {
				event := protonTestEvent("new", "message", proton.EventCreate)
				switch mode {
				case "network":
					return nil, false, errors.New("TOKEN_PRIVATE")
				case "empty":
					return nil, false, nil
				case "stalled":
					event.EventID = "old"
					return []proton.Event{event}, true, nil
				case "badid":
					event.EventID = "../bad"
				case "mismatch":
					event.Messages[0].Message.ID = "another"
				case "missingtime":
					event.Messages[0].Message.Time = 0
				case "unauthorized":
					return nil, false, &proton.APIError{Status: 401, Message: "TOKEN_PRIVATE"}
				}
				return []proton.Event{event}, false, nil
			}}
			batch, err := fakeProtonAdapter(fake).Poll(context.Background(), protonTestCursor("old"))
			if err == nil || batch.Cursor != "" || len(batch.Observations) != 0 || strings.Contains(err.Error(), "TOKEN_PRIVATE") {
				t.Fatalf("unsafe failure: %+v %v", batch, err)
			}
		})
	}
}
func TestProtonEventPaginationBoundedPrefix(t *testing.T) {
	count := 0
	fake := &protonFakeMailbox{events: func(string) ([]proton.Event, bool, error) {
		count++
		return []proton.Event{protonTestEvent(fmt.Sprintf("event%d", count), fmt.Sprintf("message%d", count), proton.EventCreate)}, true, nil
	}}
	batch, err := fakeProtonAdapter(fake).Poll(context.Background(), protonTestCursor("old"))
	if err != nil || count != protonMaxEventPages || len(batch.Observations) != protonMaxEventPages || batch.Cursor != protonTestCursor(fmt.Sprintf("event%d", count)) {
		t.Fatalf("bounded prefix: %+v %v", batch, err)
	}
}
func TestProtonRefreshIdentityValidation(t *testing.T) {
	old := protonSavedSession{AccountID: "account", UID: "session", RefreshToken: "old"}
	if got := protonRefreshedSession(old, proton.Auth{RefreshToken: "new"}); got.UID != "session" || got.RefreshToken != "new" {
		t.Fatal("refresh failed")
	}
	for _, auth := range []proton.Auth{{UID: "other", RefreshToken: "new"}, {UserID: "other", RefreshToken: "new"}} {
		if validProtonSession(protonRefreshedSession(old, auth)) {
			t.Fatal("identity mismatch accepted")
		}
	}
}
func TestProtonSuccessfulBatchPreservesMinimumPoll(t *testing.T) {
	a := fakeProtonAdapter(&protonFakeMailbox{events: func(string) ([]proton.Event, bool, error) { return []proton.Event{{EventID: "new"}}, false, nil }})
	a.transport = &protonTransport{retryAt: time.Now().Add(2 * time.Hour)}
	batch, err := a.Poll(context.Background(), protonTestCursor("old"))
	if err != nil || batch.MinimumPoll < time.Hour {
		t.Fatalf("lost delay: %v %v", batch.MinimumPoll, err)
	}
}

func TestProtonBaselineRecoveryAndRestartDoNotFlood(t *testing.T) {
	b, source := sourceTestBridge(t)
	source.Name = "proton"
	source.Namespace = "proton"
	source.EventName = "proton.mail.received"
	b.sources = []sourceConfig{source}
	sub := b.store.state.Subscriptions["new"]
	sub.Name = source.EventName
	b.store.state.Subscriptions["new"] = sub
	fake := &protonFakeMailbox{latest: "before-baseline", metadata: func(proton.MessageFilter) ([]proton.MessageMetadata, error) {
		return []proton.MessageMetadata{protonTestMessage("historical")}, nil
	}}
	batch, err := fakeProtonAdapter(fake).Poll(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.applySourceBatch(source, batch); err != nil {
		t.Fatal(err)
	}
	if len(b.store.state.Queue) != 0 {
		t.Fatal("historical baseline delivered")
	}
	reopened, err := openStore(b.store.path)
	if err != nil {
		t.Fatal(err)
	}
	b.store = reopened
	fake.latest = "recovered"
	fake.events = func(id string) ([]proton.Event, bool, error) {
		if id != "before-baseline" {
			t.Fatalf("did not resume cursor: %s", id)
		}
		return []proton.Event{{EventID: "expired", Refresh: proton.RefreshMail}}, false, nil
	}
	fake.metadata = func(proton.MessageFilter) ([]proton.MessageMetadata, error) {
		return []proton.MessageMetadata{protonTestMessage("historical"), protonTestMessage("arrived-while-down")}, nil
	}
	batch, err = fakeProtonAdapter(fake).Poll(context.Background(), b.store.state.Sources[source.Namespace].Cursor)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := b.applySourceBatch(source, batch)
	if err != nil || stats.Enqueued != 1 || stats.Unchanged != 1 || len(b.store.state.Queue) != 1 {
		t.Fatalf("recovery history flood: %+v %v", stats, err)
	}
	if _, err = b.applySourceBatch(source, batch); err != nil || len(b.store.state.Queue) != 1 {
		t.Fatal("reconciliation replay duplicated received event")
	}
	reopened, err = openStore(b.store.path)
	if err != nil {
		t.Fatal(err)
	}
	b.store = reopened
	fake.events = func(id string) ([]proton.Event, bool, error) {
		if id != "recovered" {
			t.Fatalf("recovery checkpoint not saved: %s", id)
		}
		return []proton.Event{protonTestEvent("next", "arrived-while-down", proton.EventUpdateFlags)}, false, nil
	}
	batch, err = fakeProtonAdapter(fake).Poll(context.Background(), b.store.state.Sources[source.Namespace].Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.applySourceBatch(source, batch); err != nil || len(b.store.state.Queue) != 1 {
		t.Fatal("label update duplicated received event")
	}
	raw, _ := json.Marshal(b.store.state)
	if strings.Contains(string(raw), "PRIVATE_SUBJECT") {
		t.Fatal("mail subject persisted")
	}
}
func TestProtonSnapshotCapacityFailsWithoutCheckpoint(t *testing.T) {
	pages := 0
	fake := &protonFakeMailbox{latest: "latest", metadata: func(proton.MessageFilter) ([]proton.MessageMetadata, error) {
		pages++
		messages := make([]proton.MessageMetadata, protonPageSize)
		for i := range messages {
			messages[i] = protonTestMessage(fmt.Sprintf("same%d", i))
		}
		messages[len(messages)-1] = protonTestMessage(fmt.Sprintf("anchor%d", pages))
		return messages, nil
	}}
	batch, err := fakeProtonAdapter(fake).Poll(context.Background(), "")
	if err == nil || pages != protonMaxSnapshotPages || batch.Cursor != "" || len(batch.Observations) != 0 {
		t.Fatalf("capacity advanced checkpoint: pages=%d cursor=%q err=%v", pages, batch.Cursor, err)
	}
}

func TestProtonAuthFailureAfterConnectRequiresActionAndLatches(t *testing.T) {
	for _, where := range []string{"events", "latest", "metadata"} {
		t.Run(where, func(t *testing.T) {
			fake := &protonFakeMailbox{latest: "latest", metadata: func(proton.MessageFilter) ([]proton.MessageMetadata, error) {
				return nil, &proton.APIError{Status: 422, Code: proton.AuthRefreshTokenInvalid, Message: "PRIVATE_SESSION"}
			}}
			if where == "events" {
				fake.events = func(string) ([]proton.Event, bool, error) {
					return nil, false, &proton.APIError{Status: 401, Message: "PRIVATE_TOKEN"}
				}
			}
			if where == "latest" {
				fake.latestErr = &proton.APIError{Status: 401, Message: "PRIVATE_ACCOUNT"}
			}
			a := fakeProtonAdapter(fake)
			cursor := ""
			if where == "events" {
				cursor = protonTestCursor("old")
			}
			_, err := a.Poll(context.Background(), cursor)
			var required *ProtonAuthRequiredError
			if !errors.As(err, &required) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("auth error not safe/actionable: %v", err)
			}
			calls := len(fake.calls)
			if _, err = a.Poll(context.Background(), cursor); !errors.As(err, &required) || len(fake.calls) != calls {
				t.Fatal("revoked session retried")
			}
		})
	}
}

func TestProtonNonAuthBadRequestDoesNotLatch(t *testing.T) {
	fake := &protonFakeMailbox{events: func(string) ([]proton.Event, bool, error) {
		return nil, false, &proton.APIError{Status: 400, Code: proton.InvalidValue}
	}}
	a := fakeProtonAdapter(fake)
	for i := 0; i < 2; i++ {
		_, err := a.Poll(context.Background(), protonTestCursor("old"))
		var auth *ProtonAuthRequiredError
		if err == nil || errors.As(err, &auth) {
			t.Fatalf("non-auth request mislabeled: %v", err)
		}
	}
	if len(fake.calls) != 2 {
		t.Fatal("non-auth request latched authentication")
	}
}
