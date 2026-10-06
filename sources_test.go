package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeSource struct {
	batch  SourceBatch
	err    error
	calls  int
	cursor string
}

func (f *fakeSource) Poll(_ context.Context, cursor string) (SourceBatch, error) {
	f.calls++
	f.cursor = cursor
	return f.batch, f.err
}
func sourceTestBridge(t *testing.T) (*Bridge, sourceConfig) {
	t.Helper()
	store, err := openStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	source := sourceConfig{Name: "gitlab", Namespace: "gitlab/test", EventName: "gitlab.todo.changed"}
	b := &Bridge{store: store, sources: []sourceConfig{source}}
	store.state.Subscriptions["new"] = Subscription{ID: "new", Name: source.EventName, Expires: time.Now().Add(time.Hour)}
	return b, source
}
func sourceObservation(id, version string) Observation {
	return Observation{Key: id, Fingerprint: version, Timestamp: time.Unix(1700000000, 0), Data: map[string]any{"id": id}}
}
func TestSourceBaselineRestartDedupAndIsolation(t *testing.T) {
	b, source := sourceTestBridge(t)
	first := SourceBatch{AccountID: "123", Cursor: "first", Observations: []Observation{sourceObservation("1", "a")}}
	if _, err := b.applySourceBatch(source, first); err != nil {
		t.Fatal(err)
	}
	if len(b.store.state.Queue) != 0 {
		t.Fatal("baseline emitted")
	}
	restarted, err := openStore(b.store.path)
	if err != nil {
		t.Fatal(err)
	}
	b.store = restarted
	second := SourceBatch{AccountID: "123", Cursor: "second", Observations: []Observation{sourceObservation("1", "a"), sourceObservation("2", "b"), sourceObservation("2", "b")}}
	stats, err := b.applySourceBatch(source, second)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Enqueued != 1 || len(b.store.state.Queue) != 1 {
		t.Fatalf("duplicate batch: %+v", stats)
	}
	eventID := b.store.state.Queue[0].Event.ID
	if _, err = b.applySourceBatch(source, second); err != nil {
		t.Fatal(err)
	}
	if len(b.store.state.Queue) != 1 || b.store.state.Queue[0].Event.ID != eventID {
		t.Fatal("retry duplicated event")
	}
	other := source
	other.Name = "proton"
	other.Namespace = "proton/test"
	other.EventName = "proton.mail.received"
	if _, err = b.applySourceBatch(other, second); err != nil {
		t.Fatal(err)
	}
	if len(b.store.state.Queue) != 1 || !b.store.state.Sources[other.Namespace].Baseline {
		t.Fatal("source namespace contaminated")
	}
	changed := second
	changed.AccountID = "456"
	changed.Cursor = "forbidden"
	if _, err = b.applySourceBatch(source, changed); err == nil {
		t.Fatal("account change accepted")
	}
	if b.store.state.Sources[source.Namespace].Cursor != "second" {
		t.Fatal("account mismatch advanced cursor")
	}
}
func TestSourceQueueCapacityRollsBackCheckpoint(t *testing.T) {
	b, source := sourceTestBridge(t)
	if _, err := b.applySourceBatch(source, SourceBatch{AccountID: "123", Cursor: "baseline"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxQueue; i++ {
		b.store.state.Queue = append(b.store.state.Queue, Pending{SubscriptionID: "new", Event: Event{ID: "existing"}})
	}
	if _, err := b.applySourceBatch(source, SourceBatch{AccountID: "123", Cursor: "next", Observations: []Observation{sourceObservation("2", "b")}}); err == nil {
		t.Fatal("overflow accepted")
	}
	if b.store.state.Sources[source.Namespace].Cursor != "baseline" || len(b.store.state.Seen) != 0 {
		t.Fatal("failed batch advanced snapshot")
	}
}
func TestSourceMalformedBatchIsAtomic(t *testing.T) {
	b, source := sourceTestBridge(t)
	_, err := b.applySourceBatch(source, SourceBatch{AccountID: "123", Cursor: "x", Observations: []Observation{sourceObservation("1", "a"), {Key: "bad"}}})
	if err == nil || len(b.store.state.Seen) != 0 || len(b.store.state.Sources) != 0 {
		t.Fatal("partial malformed snapshot committed")
	}
}
func TestSourceErrorsAreIsolatedAndSanitized(t *testing.T) {
	b, source := sourceTestBridge(t)
	f := &fakeSource{err: errors.New("https://secret.invalid/?token=secret"), batch: SourceBatch{MinimumPoll: time.Hour}}
	source.Adapter = f
	delay, failures := b.sourcePollOnce(context.Background(), source, time.Minute, 0)
	if delay < time.Hour || failures != 1 {
		t.Fatal("source retry hint ignored")
	}
	state := b.store.state.Sources[source.Namespace]
	if strings.Contains(state.LastError, "secret") || state.Cursor != "" || !b.store.state.LastPoll.IsZero() || b.store.state.LastError != "" {
		t.Fatal("source status leaked or contaminated GitHub")
	}
	f.err = nil
	f.batch = SourceBatch{AccountID: "123", Cursor: "good"}
	_, failures = b.sourcePollOnce(context.Background(), source, time.Minute, failures)
	if failures != 0 || b.store.state.Sources[source.Namespace].LastError != "" {
		t.Fatal("recovery failed")
	}
}
func TestSourceCanceledLoopStopsWithoutPolling(t *testing.T) {
	b, source := sourceTestBridge(t)
	f := &fakeSource{batch: SourceBatch{AccountID: "123"}}
	source.Adapter = f
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { b.sourceLoop(ctx, source, time.Hour); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop did not stop")
	}
}
func TestLegacyStateLoadsWithoutMigrationOrLoss(t *testing.T) {
	b, _ := sourceTestBridge(t)
	b.store.state.Seen["notifications/123/github:account:123:notification:4"] = "old"
	b.store.state.Baselines["notifications/123"] = true
	b.store.state.Subscriptions["legacy"] = Subscription{ID: "legacy", Name: "github.notification.changed", Expires: time.Now().Add(time.Hour)}
	if err := b.store.save(b.store.state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(b.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Sources") {
		t.Fatal("nil additive field not omitted")
	}
	reopened, err := openStore(b.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.state.Version != 1 || len(reopened.state.Seen) != 1 || !reopened.state.Baselines["notifications/123"] || reopened.state.Subscriptions["legacy"].Name != "github.notification.changed" {
		t.Fatal("legacy state lost")
	}
}
func TestDisabledSourcesIgnoreBrokenCredentialPaths(t *testing.T) {
	t.Setenv("GITLAB_ENABLED", "false")
	t.Setenv("GITLAB_TOKEN_FILE", "/missing/token")
	t.Setenv("PROTON_ENABLED", "false")
	t.Setenv("PROTON_SESSION_FILE", "/missing/session")
	if len(configuredSources()) != 0 {
		t.Fatal("disabled source initialized")
	}
}
func TestOptionalSubscriptionsSurviveMaintenanceWhileDisabled(t *testing.T) {
	b, source := sourceTestBridge(t)
	b.sources = nil
	b.pruneState(&b.store.state, time.Now())
	if b.store.state.Subscriptions["new"].Name != source.EventName {
		t.Fatal("temporary disable deleted subscription")
	}
	if b.eventEnabled(source.EventName) {
		t.Fatal("disabled source permits new subscription")
	}
}

func TestSourceMissingProtonCheckpointFailsClosed(t *testing.T) {
	b, source := sourceTestBridge(t)
	source.Name = "proton"
	source.Namespace = "proton/test"
	source.EventName = "proton.mail.received"
	f := &fakeSource{batch: SourceBatch{AccountID: "123", Cursor: "new", Baseline: true}}
	source.Adapter = f
	b.store.state.Sources = map[string]SourceState{source.Namespace: {AccountID: "123", Baseline: true}}
	_, failures := b.sourcePollOnce(context.Background(), source, time.Minute, 0)
	if failures != 1 || f.calls != 0 || b.store.state.Sources[source.Namespace].Cursor != "" {
		t.Fatal("missing checkpoint silently reset baseline")
	}
}

func TestSourceRepeatedTransitionHasDistinctEventIDs(t *testing.T) {
	b, source := sourceTestBridge(t)
	for _, version := range []string{"baseline", "b", "c", "b"} {
		if _, err := b.applySourceBatch(source, SourceBatch{AccountID: "123", Observations: []Observation{sourceObservation("item", version)}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.store.state.Queue) != 3 {
		t.Fatal("missing state transition")
	}
	ids := map[string]bool{}
	for _, pending := range b.store.state.Queue {
		if ids[pending.Event.ID] {
			t.Fatal("event ID reused for a new transition")
		}
		ids[pending.Event.ID] = true
	}
}

func TestOptionalDiscoveryAndHealth(t *testing.T) {
	b, _ := sourceTestBridge(t)
	b.sources = []sourceConfig{{Name: "gitlab", Namespace: "gitlab/a", EventName: "gitlab.todo.changed", InitError: true}, {Name: "proton", Namespace: "proton/a", EventName: "proton.mail.received", InitError: true}}
	definitions := b.eventDefinitions()
	if len(definitions) != 4 {
		t.Fatalf("want four configured events, got %d", len(definitions))
	}
	b.githubDisabled = true
	if len(b.eventDefinitions()) != 3 {
		t.Fatal("disabled GitHub still advertised")
	}
	status := b.sourceStatusesLocked()
	if status["github"].Enabled || !status["gitlab"].Enabled || status["proton"].LastError == "" {
		t.Fatalf("wrong statuses: %+v", status)
	}
	b.sources = nil
	if len(b.eventDefinitions()) != 1 {
		t.Fatal("disabled sources advertised")
	}
}
func TestGitLabConfigurationCanonicalizesOrigin(t *testing.T) {
	t.Setenv("GITLAB_ENABLED", "true")
	t.Setenv("PROTON_ENABLED", "false")
	t.Setenv("GITLAB_ACCOUNT", "Example")
	t.Setenv("GITLAB_TOKEN", "synthetic-token")
	t.Setenv("GITLAB_TOKEN_FILE", "")
	t.Setenv("GITLAB_URL", "https://GITLAB.example/")
	first := configuredSources()
	t.Setenv("GITLAB_URL", "https://gitlab.example")
	second := configuredSources()
	if len(first) != 1 || first[0].InitError || first[0].Namespace != second[0].Namespace {
		t.Fatal("equivalent origin reset checkpoint namespace")
	}
	t.Setenv("GITLAB_URL", "https://gitlab.example/api/v4")
	if !configuredSources()[0].InitError {
		t.Fatal("invalid API origin accepted")
	}
}
func TestSourceTokenFilePrecedenceAndSafeErrors(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "synthetic-env")
	path := filepath.Join(t.TempDir(), "private-token")
	t.Setenv("GITLAB_TOKEN_FILE", path)
	if _, err := loadSourceToken("GITLAB"); err == nil || strings.Contains(err.Error(), path) {
		t.Fatal("file failure fell back or leaked path")
	}
	if err := os.WriteFile(path, []byte(" synthetic-file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	token, err := loadSourceToken("GITLAB")
	if err != nil || token != "synthetic-file" {
		t.Fatal("file precedence failed")
	}
	if err := os.WriteFile(path, []byte("broken\nsecret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSourceToken("GITLAB"); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("malformed token accepted or leaked")
	}
}

type stoppingSource struct{ started, closed chan struct{} }

func (s *stoppingSource) Poll(ctx context.Context, _ string) (SourceBatch, error) {
	close(s.started)
	<-ctx.Done()
	return SourceBatch{}, ctx.Err()
}
func (s *stoppingSource) Close() { close(s.closed) }
func TestRunJoinsInterruptedSourcesAndClosesAdapters(t *testing.T) {
	b, source := sourceTestBridge(t)
	b.githubDisabled = true
	adapter := &stoppingSource{started: make(chan struct{}), closed: make(chan struct{})}
	source.Adapter = adapter
	b.sources = []sourceConfig{source}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { b.run(ctx, nil, "", time.Hour); close(done) }()
	select {
	case <-adapter.started:
	case <-time.After(time.Second):
		t.Fatal("source did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runner failed to join canceled poll")
	}
	select {
	case <-adapter.closed:
	default:
		t.Fatal("adapter not closed")
	}
}

func TestSourceAuthenticationRequiresActionWithoutLeakingSecrets(t *testing.T) {
	b, source := sourceTestBridge(t)
	source.Name = "proton"
	source.Namespace = "proton"
	source.EventName = "proton.mail.received"
	source.Adapter = &fakeSource{err: &ProtonAuthRequiredError{}}
	b.sources = []sourceConfig{source}
	b.sourcePollOnce(context.Background(), source, time.Minute, 0)
	status := b.sourceStatusesLocked()["proton"]
	if !status.NeedsAction || !strings.Contains(status.LastError, "operator action") {
		t.Fatalf("missing action signal: %+v", status)
	}
	source.Adapter = &fakeSource{batch: SourceBatch{AccountID: "account", Cursor: "checkpoint"}}
	b.sourcePollOnce(context.Background(), source, time.Minute, 1)
	if b.sourceStatusesLocked()["proton"].NeedsAction {
		t.Fatal("action signal survived recovery")
	}
}

func TestProtonStoragePathsRejectFreshAliasesAndHardlinks(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	t.Setenv("STATE_FILE", state)
	t.Setenv("OAUTH_STATE_FILE", filepath.Join(dir, "oauth.json"))
	t.Setenv("OWNER_PASSWORD_FILE", "")
	config := ProtonConfig{SessionFile: filepath.Join(dir, "proton.json"), SessionKeyFile: filepath.Join(dir, "key")}
	if err := protonStoragePathsSafe(config); err != nil {
		t.Fatal(err)
	}
	changed := config
	changed.SessionFile = state
	if err := protonStoragePathsSafe(changed); err == nil {
		t.Fatal("fresh shared state collision accepted")
	}
	if err := os.Symlink(dir, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	changed.SessionFile = filepath.Join(dir, "alias", "state.json")
	if err := protonStoragePathsSafe(changed); err == nil {
		t.Fatal("symlink-parent alias accepted")
	}
	if err := os.WriteFile(state, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked")
	if err := os.Link(state, linked); err != nil {
		t.Fatal(err)
	}
	changed.SessionFile = linked
	if err := protonStoragePathsSafe(changed); err == nil {
		t.Fatal("hardlinked state accepted")
	}
	changed = config
	changed.SessionKeyFile = config.SessionFile
	if err := protonStoragePathsSafe(changed); err == nil {
		t.Fatal("session-key alias accepted")
	}
	t.Setenv("STATE_FILE", config.SessionFile+".lock")
	if err := protonStoragePathsSafe(config); err == nil {
		t.Fatal("state-lock alias accepted")
	}
}

func TestSourceTokenFIFORejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readSourceTokenFile(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO blocked startup")
	}
}
