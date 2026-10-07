package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
)

func TestProtonAppVersionConservativeValidation(t *testing.T) {
	// Known client conventions and unknown explicit identifiers must reach the
	// provider for validation; these are not a claim of product acceptance.
	for _, value := range []string{"Other", "linux-test@1.0.0", "macos-test@5.0.134.11", "external-test-client@1.0.0-stable+build", "test@1", "unknown-identity"} {
		if !validProtonAppVersion(value) {
			t.Errorf("well-formed synthetic identity rejected: %q", value)
		}
	}
	for _, value := range []string{"", "5.0.134.11", "123", "linux-test@1\n", "linux-test@1\x00", "linux-test@1\x7f", "linux-test@é", strings.Repeat("x", 129)} {
		if validProtonAppVersion(value) {
			t.Errorf("malformed identity accepted: %q", value)
		}
		err := RunProtonAuth(context.Background(), ProtonConfig{SessionFile: "unused", SessionKeyFile: "unused-key", AppVersion: value}, nil, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "invalid Proton application-version configuration") {
			t.Fatalf("configuration not rejected before terminal/session access: %v", err)
		}
	}
}

func TestProtonDiagnosticClassificationAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		code proton.Code
		want string
	}{
		{protonAppVersionInvalidCode, "invalid Proton application-version configuration"},
		{protonAppVersionFormatCode, "invalid Proton application-version configuration"},
		{proton.AppVersionMissingCode, "application-version configuration"},
		{proton.AppVersionBadCode, "application-version configuration"},
		{proton.HumanVerificationRequired, "human verification"},
		{proton.PaidPlanRequired, "API access"},
		{proton.PasswordWrong, "authentication failed"},
		{proton.Code(98765), "authentication failed"},
	} {
		err := fmt.Errorf("PRIVATE_URL PRIVATE_USERNAME: %w", &proton.APIError{Status: 422, Code: tc.code, Message: "PRIVATE_PASSWORD", Details: []byte(`{"Token":"PRIVATE_TOKEN","Email":"PRIVATE_EMAIL"}`)})
		diagnostic := protonLoginError(context.Background(), protonStageAuthInfo, err)
		if !strings.Contains(diagnostic.Error(), tc.want) || !strings.Contains(diagnostic.Error(), fmt.Sprintf("stage=auth-info http_status=422 api_code=%d", tc.code)) {
			t.Fatalf("wrong diagnostic: %v", diagnostic)
		}
		for _, formatted := range []string{fmt.Sprint(diagnostic), fmt.Sprintf("%+v", diagnostic), fmt.Sprintf("%#v", diagnostic)} {
			if strings.Contains(formatted, "PRIVATE") {
				t.Fatal("upstream diagnostic retained sensitive content")
			}
		}
		if errors.Unwrap(diagnostic) != nil {
			t.Fatal("unsafe upstream error chain retained")
		}
	}
	diagnostic := protonLoginError(context.Background(), protonAuthStage(255), &proton.APIError{Status: -1, Code: -1, Message: "PRIVATE"})
	if !strings.Contains(diagnostic.Error(), "stage=unknown http_status=0 api_code=0") {
		t.Fatalf("invalid diagnostic values passed through: %v", diagnostic)
	}
}

func TestProtonSDKAuthenticationStagesAndStatus(t *testing.T) {
	for _, tc := range []struct {
		stage protonAuthStage
		run   func(context.Context, *proton.Manager) error
	}{
		{protonStageAuthInfo, func(ctx context.Context, m *proton.Manager) error {
			_, _, err := m.NewClientWithLogin(ctx, "PRIVATE_USERNAME", []byte("PRIVATE_PASSWORD"))
			return err
		}},
		{protonStageModulus, func(ctx context.Context, m *proton.Manager) error {
			_, err := m.AuthModulus(ctx)
			return err
		}},
		{protonStageRefresh, func(ctx context.Context, m *proton.Manager) error {
			_, _, err := m.NewClientWithRefresh(ctx, "PRIVATE_UID", "PRIVATE_TOKEN")
			return err
		}},
		{protonStageTOTP, func(ctx context.Context, m *proton.Manager) error {
			c := m.NewClient("PRIVATE_UID", "PRIVATE_ACCESS", "PRIVATE_REFRESH")
			defer c.Close()
			return c.Auth2FA(ctx, proton.Auth2FAReq{TwoFactorCode: "PRIVATE_TOTP"})
		}},
		{protonStageUser, func(ctx context.Context, m *proton.Manager) error {
			c := m.NewClient("PRIVATE_UID", "PRIVATE_ACCESS", "PRIVATE_REFRESH")
			defer c.Close()
			_, err := c.GetUser(ctx)
			return err
		}},
	} {
		t.Run(tc.stage.String(), func(t *testing.T) {
			transport := &protonTransport{base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return protonTestResponse(request, 400, `{"Code":2064,"Error":"PRIVATE_PASSWORD","Details":{"Token":"PRIVATE_TOKEN"}}`), nil
			})}
			manager := proton.New(proton.WithTransport(transport), proton.WithAppVersion("linux-test@1.0.0"), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
			defer manager.Close()
			ctx := protonAuthContext(context.Background())
			err := tc.run(ctx, manager)
			if err == nil {
				t.Fatal("SDK accepted error response")
			}
			diagnostic := protonLoginError(ctx, protonStageLogin, err)
			if diagnostic.stage != tc.stage || diagnostic.httpStatus != 400 || diagnostic.apiCode != protonAppVersionInvalidCode || strings.Contains(diagnostic.Error(), "PRIVATE") {
				t.Fatalf("wrong SDK diagnostic: %v", diagnostic)
			}
		})
	}
}

func TestProtonDiagnosticTransportAndMalformedBody(t *testing.T) {
	for _, status := range []int{0, 502} {
		transport := &protonTransport{base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if status == 0 {
				return nil, errors.New("PRIVATE_NETWORK_URL")
			}
			return protonTestResponse(request, status, `PRIVATE_MALFORMED_BODY`), nil
		})}
		manager := proton.New(proton.WithTransport(transport), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
		ctx := protonAuthContext(context.Background())
		_, _, err := manager.NewClientWithLogin(ctx, "PRIVATE_USERNAME", []byte("PRIVATE_PASSWORD"))
		manager.Close()
		if err == nil {
			t.Fatal("failed request accepted")
		}
		diagnostic := protonLoginError(ctx, protonStageLogin, err)
		if diagnostic.stage != protonStageAuthInfo || diagnostic.httpStatus != status || diagnostic.apiCode != 0 || strings.Contains(diagnostic.Error(), "PRIVATE") {
			t.Fatalf("unsafe transport diagnostic: %v", diagnostic)
		}
	}
}

func TestProtonDiagnosticTraceIsScopedAndAllowlisted(t *testing.T) {
	var wg sync.WaitGroup
	for _, path := range []string{"/api/auth/v4", "/api/auth/v4/info", "/api/PRIVATE_USERNAME"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			ctx := protonAuthContext(context.Background())
			request, _ := http.NewRequestWithContext(ctx, "POST", "https://mail.proton.me"+path+"?PRIVATE_TOKEN=1", nil)
			recordProtonAuthResponse(request, 422)
			diagnostic := protonLoginError(ctx, protonStageLogin, errors.New("PRIVATE_ERROR"))
			want := protonRequestStage(request)
			if want == protonStageUnknown {
				want = protonStageLogin
			}
			if diagnostic.stage != want || diagnostic.httpStatus != 422 || strings.Contains(diagnostic.Error(), "PRIVATE") {
				t.Errorf("request trace leaked or mixed: %v", diagnostic)
			}
		}(path)
	}
	wg.Wait()
	diagnostic := protonLoginError(protonAuthContext(context.Background()), protonStageTOTP, errors.New("PRIVATE_LOCAL_ERROR"))
	if diagnostic.stage != protonStageTOTP || diagnostic.httpStatus != 0 || diagnostic.apiCode != 0 {
		t.Fatalf("previous trace reused: %v", diagnostic)
	}
}

func TestProtonDiagnosticTraceResetsStatusForLaterRequest(t *testing.T) {
	ctx := protonAuthContext(context.Background())
	transport := &protonTransport{base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/auth/v4/info" {
			return protonTestResponse(request, 200, `{"Code":1000}`), nil
		}
		return nil, errors.New("PRIVATE_NETWORK_ERROR")
	})}
	info, _ := http.NewRequestWithContext(ctx, "POST", "https://mail.proton.me/api/auth/v4/info", nil)
	response, err := transport.RoundTrip(info)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	auth, _ := http.NewRequestWithContext(ctx, "POST", "https://mail.proton.me/api/auth/v4", nil)
	_, err = transport.RoundTrip(auth)
	diagnostic := protonLoginError(ctx, protonStageLogin, err)
	if diagnostic.stage != protonStageAuth || diagnostic.httpStatus != 0 || diagnostic.apiCode != 0 || strings.Contains(diagnostic.Error(), "PRIVATE") {
		t.Fatalf("earlier request status survived transport failure: %v", diagnostic)
	}
}

func TestProtonBootstrapRetainsConfigurationFailureAndDoesNotRetry(t *testing.T) {
	a, _ := bootstrapProtonAdapter(t)
	requests := 0
	a.transport.base = protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return protonTestResponse(request, 400, `{"Code":2064,"Error":"PRIVATE_PASSWORD"}`), nil
	})
	for i := 0; i < 2; i++ {
		_, err := a.Poll(context.Background(), "")
		var required *ProtonAuthRequiredError
		if !errors.As(err, &required) || !strings.Contains(err.Error(), "invalid Proton application-version configuration") || !strings.Contains(err.Error(), "stage=auth-info http_status=400 api_code=2064") || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("configuration failure lost: %v", err)
		}
	}
	if requests != 1 || a.config.Password != "" {
		t.Fatalf("bootstrap retried or retained password: requests=%d", requests)
	}
	if _, err := os.Stat(a.config.SessionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected bootstrap saved a session")
	}
}

func TestProtonRefreshConfigurationFailurePreservesSession(t *testing.T) {
	store, path, _ := protonTestStore(t)
	if err := store.save(protonSavedSession{AccountID: "account", UID: "session", RefreshToken: "PRIVATE_REFRESH"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	transport := &protonTransport{session: store, base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return protonTestResponse(request, 400, `{"Code":5002,"Error":"PRIVATE_RESPONSE"}`), nil
	})}
	manager := proton.New(proton.WithTransport(transport), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
	a := &ProtonAdapter{config: ProtonConfig{AccountID: "account"}, session: store, manager: manager, transport: transport}
	defer a.Close()
	for i := 0; i < 2; i++ {
		_, err := a.Poll(context.Background(), "")
		var required *ProtonAuthRequiredError
		if !errors.As(err, &required) || !strings.Contains(err.Error(), "stage=refresh http_status=400 api_code=5002") || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("refresh failure lost: %v", err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || requests != 1 {
		t.Fatalf("failed refresh overwrote session or retried: %v requests=%d", err, requests)
	}
}

func TestProtonRefreshTransientFailuresRemainRetryable(t *testing.T) {
	for _, status := range []int{0, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			store, path, _ := protonTestStore(t)
			if err := store.save(protonSavedSession{AccountID: "account", UID: "session", RefreshToken: "PRIVATE_REFRESH"}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			requests := 0
			transport := &protonTransport{session: store, base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests++
				if status == 0 {
					return nil, errors.New("PRIVATE_NETWORK_ERROR")
				}
				return protonTestResponse(request, status, `{"Code":98765,"Error":"PRIVATE_RESPONSE"}`), nil
			})}
			manager := proton.New(proton.WithTransport(transport), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
			a := &ProtonAdapter{config: ProtonConfig{AccountID: "account"}, session: store, manager: manager, transport: transport}
			defer a.Close()
			for i := 0; i < 2; i++ {
				_, err := a.Poll(context.Background(), "")
				var required *ProtonAuthRequiredError
				if err == nil || errors.As(err, &required) || a.reauthRequired || a.authFailure != nil || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatalf("transient failure latched or leaked: %v", err)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) || requests != 2 {
				t.Fatalf("transient failure changed session or was not retryable: %v requests=%d", err, requests)
			}
		})
	}
}

func TestProtonLocalConfigurationDiagnosticSurvivesServiceInitialization(t *testing.T) {
	logs := captureOperationalLogs(t)
	b, _ := sourceTestBridge(t)
	dir := t.TempDir()
	t.Setenv("GITLAB_ENABLED", "false")
	t.Setenv("PROTON_ENABLED", "true")
	t.Setenv("PROTON_APP_VERSION", "5.0.134.11")
	t.Setenv("PROTON_SESSION_FILE", filepath.Join(dir, "PRIVATE_SESSION"))
	t.Setenv("PROTON_SESSION_KEY_FILE", filepath.Join(dir, "PRIVATE_KEY"))
	t.Setenv("STATE_FILE", b.store.path)
	t.Setenv("OAUTH_STATE_FILE", filepath.Join(dir, "PRIVATE_OAUTH"))
	t.Setenv("OWNER_PASSWORD_FILE", "")
	t.Setenv("PROTON_USERNAME_FILE", filepath.Join(dir, "PRIVATE_USERNAME"))
	t.Setenv("PROTON_PASSWORD_FILE", filepath.Join(dir, "PRIVATE_PASSWORD"))
	b.sources = configuredSources()
	if len(b.sources) != 1 || !b.sources[0].InitError || b.sources[0].InitDiagnostic != sourceInitProtonAppVersion {
		t.Fatal("local application-version reason was discarded")
	}
	assertStatus := func() {
		t.Helper()
		status := b.sourceStatusesLocked()["proton"]
		if !status.NeedsAction || !strings.Contains(status.LastError, "invalid Proton application-version configuration") || !strings.Contains(status.LastError, "stage=configuration http_status=0 api_code=0") || strings.Contains(status.LastError, "PRIVATE") {
			t.Fatalf("unsafe or missing local configuration status: %+v", status)
		}
	}
	assertStatus()
	b.sourcePollOnce(context.Background(), b.sources[0], time.Minute, 0)
	assertStatus()
	if !strings.Contains(logs.String(), "reason=invalid_application_version stage=configuration http_status=0 api_code=0") || strings.Contains(logs.String(), "PRIVATE") {
		t.Fatalf("unsafe or missing local configuration log: %s", logs)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("invalid app version accessed session or credentials")
	}
	// Other initializer failures keep the generic allowlisted error, never a
	// filesystem path or arbitrary upstream message.
	t.Setenv("PROTON_APP_VERSION", "Other")
	b.sources = configuredSources()
	if len(b.sources) != 1 || !b.sources[0].InitError || b.sources[0].InitDiagnostic != sourceInitUnknown || b.sourceStatusesLocked()["proton"].LastError != "source configuration unavailable" {
		t.Fatal("unrelated initialization failure was exposed or misclassified")
	}
}

func TestProtonSourceStatusAndLogsContainOnlySafeDiagnostics(t *testing.T) {
	logs := captureOperationalLogs(t)
	b, source := sourceTestBridge(t)
	source.Name, source.Namespace, source.EventName = "proton", "proton", "proton.mail.received"
	diagnostic := protonLoginError(context.Background(), protonStageAuthInfo, &proton.APIError{Status: 400, Code: protonAppVersionInvalidCode, Message: "PRIVATE_PASSWORD", Details: []byte("PRIVATE_RESPONSE")})
	source.Adapter = &fakeSource{err: &ProtonAuthRequiredError{diagnostic: diagnostic}}
	b.sources = []sourceConfig{source}
	b.sourcePollOnce(context.Background(), source, time.Minute, 0)
	status := b.sourceStatusesLocked()["proton"]
	if !status.NeedsAction || !strings.Contains(status.LastError, "stage=auth-info http_status=400 api_code=2064") || !strings.Contains(logs.String(), "stage=auth-info http_status=400 api_code=2064") {
		t.Fatalf("safe diagnostic missing: %+v logs=%s", status, logs)
	}
	raw, err := os.ReadFile(b.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String()+status.LastError+string(raw), "PRIVATE") {
		t.Fatal("upstream secret reached logs or persisted source status")
	}
}
