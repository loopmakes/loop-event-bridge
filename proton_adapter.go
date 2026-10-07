package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
)

const (
	protonPageSize         = 100
	protonMaxSnapshotPages = 1000
	protonMaxEventPages    = 20
)

// ProtonConfig is operator-only configuration. Username/password inputs are
// used for a single absent-session bootstrap, never accepted through HTTP/MCP.
type ProtonConfig struct {
	SessionFile    string
	SessionKeyFile string
	AppVersion     string
	AccountID      string
	Username       string
	Password       string
	UsernameFile   string
	PasswordFile   string
}

type protonMailbox interface {
	GetLatestEventID(context.Context) (string, error)
	GetEvent(context.Context, string) ([]proton.Event, bool, error)
	GetMessageMetadataPage(context.Context, int, int, proton.MessageFilter) ([]proton.MessageMetadata, error)
}

type protonCursor struct {
	Version   int    `json:"version"`
	AccountID string `json:"account_id"`
	EventID   string `json:"event_id"`
}

// ProtonAdapter is lazy: no network calls take place until Poll. Construction is
// only called for an explicitly enabled source. One adapter owns one session.
type ProtonAdapter struct {
	mu                 sync.Mutex
	config             ProtonConfig
	session            *protonSessionStore
	manager            *proton.Manager
	client             *proton.Client
	mailbox            protonMailbox
	accountID          string
	transport          *protonTransport
	closed             bool
	bootstrapPending   bool
	reauthRequired     bool
	authFailure        *ProtonAuthRequiredError
	bootstrapAttempted bool
	login              func(context.Context, string, []byte) (*proton.Client, proton.Auth, error)
}

func validateProtonConfig(c ProtonConfig, requireAccount bool) error {
	if c.SessionFile == "" || c.SessionKeyFile == "" || c.SessionFile == c.SessionKeyFile {
		return errors.New("Proton requires separate session and key files")
	}
	if !validProtonAppVersion(c.AppVersion) {
		return &protonAppVersionConfigError{}
	}
	if requireAccount && !validProtonID(c.AccountID) {
		return errors.New("Proton requires the account ID returned by proton-auth")
	}
	if c.AccountID != "" && !validProtonID(c.AccountID) {
		return errors.New("invalid Proton account ID")
	}
	return nil
}

// Reject unsafe header values and bare numeric frontend versions. Other
// explicit identifiers are left to Proton: not all clients use the common
// platform-product@version convention, and local syntax cannot prove access.
func validProtonAppVersion(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	bareVersion, hasDigit := true, false
	for _, ch := range value {
		if ch <= ' ' || ch >= 127 {
			return false
		}
		if ch >= '0' && ch <= '9' {
			hasDigit = true
		} else if ch != '.' {
			bareVersion = false
		}
	}
	return !(bareVersion && hasDigit)
}

func NewProtonAdapter(c ProtonConfig) (*ProtonAdapter, error) {
	if err := validateProtonConfig(c, false); err != nil {
		return nil, err
	}
	session, err := openProtonSessionStore(c.SessionFile, c.SessionKeyFile)
	if err != nil {
		return nil, err
	}
	adapter := &ProtonAdapter{config: c, session: session}
	if _, err = os.Lstat(c.SessionFile); errors.Is(err, os.ErrNotExist) {
		adapter.bootstrapPending = true
		return adapter, nil
	} else if err != nil {
		session.close()
		return nil, errors.New("Proton session file unavailable")
	}
	saved, err := session.load()
	if err != nil {
		session.close()
		return nil, err
	}
	if c.AccountID != "" && c.AccountID != saved.AccountID {
		session.close()
		return nil, errors.New("Proton session account does not match configured account")
	}
	adapter.accountID = saved.AccountID
	adapter.config.Password = ""
	return adapter, nil
}

func (a *ProtonAdapter) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	if a.client != nil {
		a.client.Close()
	}
	if a.manager != nil {
		a.manager.Close()
	}
	if a.session != nil {
		a.session.close()
	}
}

func (a *ProtonAdapter) connect(ctx context.Context) error {
	if a.mailbox != nil {
		return nil
	}
	if a.manager == nil {
		a.manager, a.transport = newProtonManager(a.config.AppVersion, a.session)
	}
	if a.bootstrapPending {
		return a.bootstrap(ctx)
	}
	saved, err := a.session.load()
	if err != nil {
		return err
	}
	if a.config.AccountID != "" && saved.AccountID != a.config.AccountID {
		return errors.New("Proton session account does not match configured account")
	}
	if err = protonCheckConfiguredUsername(a.config, saved); err != nil {
		return err
	}
	refreshCtx := protonAuthContext(ctx)
	client, auth, err := a.manager.NewClientWithRefresh(refreshCtx, saved.UID, saved.RefreshToken)
	if err != nil {
		return protonSessionRefreshError(refreshCtx, err)
	}
	// Persist a rotated refresh token before any other network operation. A write
	// failure latches the store closed, preventing this process from going on with
	// an unpersisted replacement token.
	if err = a.session.save(protonRefreshedSession(saved, auth)); err != nil {
		client.Close()
		return err
	}
	client.AddAuthHandler(func(auth proton.Auth) {
		_ = a.session.save(protonRefreshedSession(saved, auth))
	})
	userCtx := protonAuthContext(ctx)
	user, err := client.GetUser(userCtx)
	if err != nil {
		client.Close()
		classified := a.classifyAPIError(err, "Proton account verification failed")
		var required *ProtonAuthRequiredError
		if errors.As(classified, &required) {
			required.diagnostic = protonLoginError(userCtx, protonStageUser, err)
			return required
		}
		return protonLoginError(userCtx, protonStageUser, err)
	}
	if user.ID != saved.AccountID {
		client.Close()
		return errors.New("Proton account identity changed; polling refused")
	}
	if err = a.session.check(); err != nil {
		client.Close()
		return err
	}
	a.client = client
	a.mailbox = client
	a.accountID = user.ID
	return nil
}

func (a *ProtonAdapter) Poll(ctx context.Context, rawCursor string) (SourceBatch, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return SourceBatch{}, errors.New("Proton adapter is closed")
	}
	if a.reauthRequired {
		if a.authFailure != nil {
			return a.failure(a.authFailure)
		}
		return a.failure(&ProtonAuthRequiredError{})
	}
	ctx, cancel := context.WithTimeout(protonPollContext(ctx), 2*time.Minute)
	defer cancel()
	var cursor protonCursor
	if rawCursor != "" {
		if len(rawCursor) > 4096 || decodeOAuthJSON([]byte(rawCursor), &cursor) != nil || cursor.Version != 1 || !validProtonID(cursor.EventID) || !validProtonID(cursor.AccountID) || (a.accountID != "" && cursor.AccountID != a.accountID) || (a.config.AccountID != "" && cursor.AccountID != a.config.AccountID) {
			return SourceBatch{}, errors.New("invalid Proton checkpoint or account mismatch")
		}
	}
	// A previous checkpoint also pins absent-session bootstrap to that account.
	if rawCursor != "" && a.bootstrapPending && a.config.AccountID == "" {
		a.config.AccountID = cursor.AccountID
	}
	if err := a.connect(ctx); err != nil {
		var required *ProtonAuthRequiredError
		if errors.As(err, &required) {
			a.reauthRequired = true
			a.authFailure = required
		}
		return a.failure(err)
	}
	if rawCursor != "" && cursor.AccountID != a.accountID {
		return a.failure(errors.New("Proton checkpoint account mismatch; event polling refused"))
	}
	if a.session != nil {
		if err := a.session.check(); err != nil {
			return a.failure(err)
		}
	}
	if rawCursor == "" {
		return a.snapshot(ctx, true)
	}
	observations := []Observation{}
	seen := map[string]bool{}
	eventID := cursor.EventID
	for page := 0; page < protonMaxEventPages; page++ {
		events, more, err := a.mailbox.GetEvent(ctx, eventID)
		if err != nil {
			if protonExpiredCursor(err) {
				return a.snapshot(ctx, false)
			}
			return a.failure(a.classifyAPIError(err, "Proton event polling failed"))
		}
		if len(events) == 0 {
			return a.failure(errors.New("Proton returned an incomplete event page"))
		}
		before := eventID
		for _, event := range events {
			if !validProtonID(event.EventID) {
				return a.failure(errors.New("Proton returned an invalid event checkpoint"))
			}
			if event.Refresh&proton.RefreshMail != 0 {
				return a.snapshot(ctx, false)
			}
			for _, item := range event.Messages {
				if item.Action != proton.EventCreate || !protonIncoming(item.Message) {
					continue
				}
				metadata := item.Message
				if metadata.ID == "" {
					metadata.ID = item.ID
				}
				if item.ID != "" && metadata.ID != item.ID {
					return a.failure(errors.New("Proton message identity mismatch"))
				}
				observation, err := protonObservation(metadata)
				if err != nil {
					return a.failure(err)
				}
				if !seen[observation.Key] {
					seen[observation.Key] = true
					observations = append(observations, observation)
				}
			}
			eventID = event.EventID
		}
		if !more {
			return a.batch(eventID, observations, false)
		}
		if eventID == before {
			return a.failure(errors.New("Proton event pagination did not advance"))
		}
	}
	// Bounded event pagination can commit a complete prefix. The next Poll resumes
	// from exactly this event ID, so a large backlog cannot force a reset.
	return a.batch(eventID, observations, false)
}

// Capture latest before scanning, so events arriving during reconciliation are
// replayed and deduplicated next time. EndID pagination is inclusive in the
// official API; omitting the repeated anchor avoids offset races and duplicates.
func (a *ProtonAdapter) snapshot(ctx context.Context, baseline bool) (SourceBatch, error) {
	latest, err := a.mailbox.GetLatestEventID(ctx)
	if err != nil {
		return a.failure(a.classifyAPIError(err, "Proton reconciliation checkpoint unavailable"))
	}
	if !validProtonID(latest) {
		return a.failure(errors.New("Proton reconciliation checkpoint unavailable"))
	}
	observations := []Observation{}
	seen := map[string]bool{}
	endID := ""
	for page := 0; page < protonMaxSnapshotPages; page++ {
		messages, err := a.mailbox.GetMessageMetadataPage(ctx, 0, protonPageSize, proton.MessageFilter{Desc: true, EndID: endID})
		if err != nil {
			return a.failure(a.classifyAPIError(err, "Proton metadata reconciliation failed"))
		}
		if len(messages) > protonPageSize {
			return a.failure(errors.New("Proton metadata page exceeds limit"))
		}
		for _, metadata := range messages {
			if !validProtonID(metadata.ID) {
				return a.failure(errors.New("Proton metadata identity invalid"))
			}
			if seen[metadata.ID] {
				continue
			}
			seen[metadata.ID] = true
			if !protonIncoming(metadata) {
				continue
			}
			observation, err := protonObservation(metadata)
			if err != nil {
				return a.failure(err)
			}
			observations = append(observations, observation)
		}
		if len(messages) < protonPageSize {
			return a.batch(latest, observations, baseline)
		}
		next := messages[len(messages)-1].ID
		if next == endID {
			return a.failure(errors.New("Proton metadata pagination did not advance"))
		}
		endID = next
	}
	return a.failure(errors.New("Proton mailbox exceeds reconciliation limit; checkpoint unchanged"))
}

func (a *ProtonAdapter) batch(eventID string, observations []Observation, baseline bool) (SourceBatch, error) {
	if a.session != nil {
		if err := a.session.check(); err != nil {
			return a.failure(err)
		}
	}
	encoded, err := json.Marshal(protonCursor{Version: 1, AccountID: a.accountID, EventID: eventID})
	if err != nil {
		return a.failure(errors.New("Proton checkpoint encoding failed"))
	}
	return SourceBatch{AccountID: a.accountID, Cursor: string(encoded), Observations: observations, Baseline: baseline, MinimumPoll: a.minimumPoll()}, nil
}
func (a *ProtonAdapter) minimumPoll() time.Duration {
	if a.transport != nil {
		return a.transport.minimumPoll()
	}
	return 0
}
func (a *ProtonAdapter) failure(err error) (SourceBatch, error) {
	batch := SourceBatch{AccountID: a.accountID}
	if a.transport != nil {
		batch.MinimumPoll = a.transport.minimumPoll()
	}
	return batch, err
}
func protonExpiredCursor(err error) bool {
	var apiErr *proton.APIError
	return errors.As(err, &apiErr) && (apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusGone)
}
func validProtonID(id string) bool {
	if id == "" || len(id) > 512 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '=') {
			return false
		}
	}
	return true
}
func protonIncoming(m proton.MessageMetadata) bool {
	if !m.Flags.Has(proton.MessageFlagReceived) || m.Flags.HasAny(proton.MessageFlagSent, proton.MessageFlagImported) {
		return false
	}
	for _, label := range m.LabelIDs {
		switch label {
		case proton.AllDraftsLabel, proton.DraftsLabel, proton.AllSentLabel, proton.SentLabel, proton.OutboxLabel:
			return false
		}
	}
	return true
}
func protonObservation(m proton.MessageMetadata) (Observation, error) {
	if !validProtonID(m.ID) || m.Time <= 0 {
		return Observation{}, errors.New("Proton received-message metadata invalid")
	}
	received := time.Unix(m.Time, 0).UTC()
	// A stable fingerprint makes read flags, labels, subjects, and later metadata
	// changes incapable of producing a second received event for the same ID.
	return Observation{Key: m.ID, Fingerprint: m.ID, Timestamp: received, Data: map[string]any{"message_id": m.ID, "received_at": received.Format(time.RFC3339)}}, nil
}

// The pinned SDK keeps the input session UID on Client even after refresh.
// Reject any contradictory returned identity instead of silently rebinding it.
func protonRefreshedSession(previous protonSavedSession, auth proton.Auth) protonSavedSession {
	if (auth.UID != "" && auth.UID != previous.UID) || (auth.UserID != "" && auth.UserID != previous.AccountID) {
		return protonSavedSession{}
	}
	previous.RefreshToken = auth.RefreshToken
	return previous
}

// The SDK transparently retries one expired-access-token request with refresh.
// Authentication errors which still escape it require intervention. Latching
// prevents unattended repeated refresh attempts against a revoked session.
func (a *ProtonAdapter) classifyAPIError(err error, fallback string) error {
	var apiErr *proton.APIError
	var required *ProtonAuthRequiredError
	if errors.As(err, &required) || protonAppVersionError(err) || (errors.As(err, &apiErr) && (apiErr.Status == http.StatusUnauthorized || apiErr.Code == proton.AuthRefreshTokenInvalid || apiErr.Code == proton.HumanVerificationRequired || apiErr.Code == proton.PaidPlanRequired)) {
		a.reauthRequired = true
		if required == nil {
			required = &ProtonAuthRequiredError{diagnostic: protonLoginError(context.Background(), protonStageUnknown, err)}
		}
		a.authFailure = required
		return required
	}
	return errors.New(fallback)
}
