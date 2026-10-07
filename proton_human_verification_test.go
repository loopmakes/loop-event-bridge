package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
)

func TestProtonHumanVerificationMethodDiagnosticsAreAllowlisted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		details string
		want    string
	}{
		{"email", `{"HumanVerificationMethods":["email"],"HumanVerificationToken":"PRIVATE_TOKEN","Email":"PRIVATE_EMAIL"}`, "email"},
		{"all", `{"HumanVerificationMethods":["ownership-sms","coupon","sms","email","captcha","payment","invite","ownership-email","email","PRIVATE_METHOD"]}`, "email,captcha,sms,payment,invite,coupon,ownership-email,ownership-sms,unknown"},
		{"unknown", `{"HumanVerificationMethods":["PRIVATE_METHOD","Email","email\nPRIVATE"]}`, "unknown"},
		{"absent", `{}`, "unavailable"},
		{"empty", `{"HumanVerificationMethods":[]}`, "unavailable"},
		{"null", `null`, "unavailable"},
		{"malformed", `PRIVATE_NOT_JSON`, "unavailable"},
		{"wrongtype", `{"HumanVerificationMethods":"email"}`, "unavailable"},
		{"oversize", strings.Repeat("PRIVATE", 10000), "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := &proton.APIError{Status: 422, Code: proton.HumanVerificationRequired, Message: "PRIVATE_MESSAGE", Details: []byte(tc.details)}
			diagnostic := protonLoginError(context.Background(), protonStageAuth, fmt.Errorf("PRIVATE_URL: %w", upstream))
			if !strings.Contains(diagnostic.Error(), "stage=auth http_status=422 api_code=9001 offered_methods="+tc.want+")") {
				t.Fatalf("incorrect method diagnostic: %v", diagnostic)
			}
			for _, output := range []string{diagnostic.Error(), fmt.Sprintf("%+v", diagnostic), fmt.Sprintf("%#v", diagnostic)} {
				if strings.Contains(output, "PRIVATE") {
					t.Fatal("provider details escaped safe method flags")
				}
			}
			if errors.Unwrap(diagnostic) != nil {
				t.Fatal("provider error retained")
			}
		})
	}
	apiErr := &proton.APIError{Code: proton.PasswordWrong, Details: []byte(`{"HumanVerificationMethods":["email"]}`)}
	if protonOfferedHVMethods(apiErr) != 0 || strings.Contains(protonLoginError(context.Background(), protonStageAuth, apiErr).Error(), "offered_methods") {
		t.Fatal("non-challenge error acquired verification methods")
	}
}

type protonTestInteractiveManager struct {
	login  func(context.Context, string, []byte) (*proton.Client, proton.Auth, error)
	replay func(context.Context, string, []byte, *proton.APIHVDetails) (*proton.Client, proton.Auth, error)
	send   func(context.Context, proton.SendVerificationCodeReq) error
}

func (m *protonTestInteractiveManager) NewClientWithLogin(ctx context.Context, username string, password []byte) (*proton.Client, proton.Auth, error) {
	return m.login(ctx, username, password)
}

func (m *protonTestInteractiveManager) NewClientWithLoginWithHVToken(ctx context.Context, username string, password []byte, hv *proton.APIHVDetails) (*proton.Client, proton.Auth, error) {
	return m.replay(ctx, username, password, hv)
}

func (m *protonTestInteractiveManager) SendVerificationCode(ctx context.Context, req proton.SendVerificationCodeReq) error {
	return m.send(ctx, req)
}

func recordProtonTestAuthStage(ctx context.Context, path string, status int) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://mail.proton.me"+path, nil)
	recordProtonAuthResponse(request, status)
}

type protonInteractiveHarness struct {
	config      ProtonConfig
	manager     *protonTestInteractiveManager
	output      bytes.Buffer
	inputs      []string
	inputBytes  [][]byte
	prompts     int
	logins      int
	emails      int
	replays     int
	deletes     int
	userReads   int
	initialPath string
	initialErr  error
	sendErr     error
	replayErr   error
	userStatus  int
	userID      string
	twoFA       proton.TwoFAStatus
	totpStatus  int
	promptErrAt int
	onPrompt    func(int)
	initialCtx  context.Context
}

func newProtonInteractiveHarness(t *testing.T) *protonInteractiveHarness {
	t.Helper()
	store, path, key := protonTestStore(t)
	store.close()
	h := &protonInteractiveHarness{
		config:      ProtonConfig{SessionFile: path, SessionKeyFile: key, AppVersion: "Other"},
		inputs:      []string{"PRIVATE_USERNAME", "PRIVATE_PASSWORD", "private-email@example.test", "746291", "PRIVATE_TOTP"},
		initialPath: "/api/auth/v4",
		initialErr:  &proton.APIError{Status: 422, Code: proton.HumanVerificationRequired, Message: "PRIVATE_RESPONSE", Details: []byte(`{"HumanVerificationMethods":["email","captcha"],"HumanVerificationToken":"PRIVATE_HV_TOKEN"}`)},
		userStatus:  http.StatusOK,
		userID:      "account",
		totpStatus:  http.StatusOK,
		promptErrAt: -1,
	}
	transport := &protonTransport{base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.Method + " " + request.URL.Path {
		case "GET /api/core/v4/users":
			h.userReads++
			return protonTestResponse(request, h.userStatus, fmt.Sprintf(`{"Code":1000,"User":{"ID":%q}}`, h.userID)), nil
		case "DELETE /api/auth/v4":
			h.deletes++
			return protonTestResponse(request, 200, `{"Code":1000}`), nil
		case "POST /api/auth/v4/2fa":
			return protonTestResponse(request, h.totpStatus, `{"Code":8002,"Error":"PRIVATE_TOTP"}`), nil
		default:
			t.Fatal("unexpected interactive SDK route")
			return nil, errors.New("unexpected route")
		}
	})}
	sdk := proton.New(proton.WithTransport(transport), proton.WithAppVersion("Other"), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
	t.Cleanup(sdk.Close)
	newClient := func() (*proton.Client, proton.Auth, error) {
		return sdk.NewClient("session", "PRIVATE_ACCESS", "PRIVATE_REFRESH"), proton.Auth{UserID: "account", UID: "session", RefreshToken: "PRIVATE_REFRESH", TwoFA: proton.TwoFAInfo{Enabled: h.twoFA}}, nil
	}
	checkRequest := func(ctx context.Context) {
		t.Helper()
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Minute {
			t.Fatal("network request is not separately bounded")
		}
	}
	h.manager = &protonTestInteractiveManager{
		login: func(ctx context.Context, username string, password []byte) (*proton.Client, proton.Auth, error) {
			h.logins++
			checkRequest(ctx)
			if username != h.inputs[0] || string(password) != h.inputs[1] {
				t.Fatal("initial credentials changed")
			}
			h.initialCtx = ctx
			if h.initialErr == nil {
				return newClient()
			}
			recordProtonTestAuthStage(ctx, h.initialPath, 422)
			return nil, proton.Auth{}, h.initialErr
		},
		send: func(ctx context.Context, req proton.SendVerificationCodeReq) error {
			h.emails++
			checkRequest(ctx)
			if ctx == h.initialCtx || req.Username != h.inputs[0] || req.Type != proton.EmailTokenType || req.Destination.Address != h.inputs[2] || req.Destination.Phone != "" {
				t.Fatal("incorrect email request or reused request context")
			}
			recordProtonTestAuthStage(ctx, "/api/core/v4/users/code", 200)
			return h.sendErr
		},
		replay: func(ctx context.Context, username string, password []byte, hv *proton.APIHVDetails) (*proton.Client, proton.Auth, error) {
			h.replays++
			checkRequest(ctx)
			if ctx == h.initialCtx || username != h.inputs[0] || string(password) != h.inputs[1] || hv == nil || len(hv.Methods) != 1 || hv.Methods[0] != "email" || hv.Token != h.inputs[2]+":"+h.inputs[3] {
				t.Fatal("incorrect SDK verification proof or expired request context")
			}
			if h.replayErr != nil {
				recordProtonTestAuthStage(ctx, "/api/auth/v4", 422)
				return nil, proton.Auth{}, h.replayErr
			}
			return newClient()
		},
	}
	return h
}

func (h *protonInteractiveHarness) run(ctx context.Context) error {
	return runProtonInteractiveAuth(ctx, h.config, &h.output, func(label string) ([]byte, error) {
		h.output.WriteString(label)
		index := h.prompts
		h.prompts++
		if h.onPrompt != nil {
			h.onPrompt(index)
		}
		if index == h.promptErrAt || index >= len(h.inputs) {
			return nil, errors.New("PRIVATE_TERMINAL_ERROR")
		}
		value := []byte(h.inputs[index])
		h.inputBytes = append(h.inputBytes, value)
		return value, nil
	}, h.manager)
}

func (h *protonInteractiveHarness) assertPrivate(t *testing.T, err error) {
	t.Helper()
	output := h.output.String() + fmt.Sprintf("%+v %#v", err, err)
	for _, secret := range []string{"PRIVATE", "private-email@", "746291"} {
		if strings.Contains(output, secret) {
			t.Fatal("interactive diagnostics leaked sensitive data")
		}
	}
	for _, input := range h.inputBytes {
		if !bytes.Equal(input, make([]byte, len(input))) {
			t.Fatal("interactive input bytes retained after return")
		}
	}
}

func TestProtonInteractiveEmailSuccessSavesOnlyEncryptedAuthenticatedSession(t *testing.T) {
	h := newProtonInteractiveHarness(t)
	h.onPrompt = func(index int) {
		if index >= 2 && h.initialCtx.Err() == nil {
			t.Fatal("request deadline remained active while waiting for operator")
		}
		if _, err := os.Stat(h.config.SessionFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("session saved before authentication finished")
		}
	}
	if err := h.run(context.Background()); err != nil {
		t.Fatalf("interactive authentication failed: %v", err)
	}
	h.assertPrivate(t, nil)
	if h.logins != 1 || h.emails != 1 || h.replays != 1 || h.userReads != 1 || h.deletes != 0 || h.prompts != 4 {
		t.Fatal("unexpected successful flow or extra authentication attempt")
	}
	if !strings.Contains(h.output.String(), "offered_methods=email,captcha") || !strings.Contains(h.output.String(), "Encrypted Proton session saved") {
		t.Fatal("challenge methods or success were not reported")
	}
	store, err := openProtonSessionStore(h.config.SessionFile, h.config.SessionKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	saved, err := store.load()
	if err != nil || saved.AccountID != "account" || saved.RefreshToken != "PRIVATE_REFRESH" || saved.LoginHash != protonUsernameHash(h.inputs[0]) {
		t.Fatal("verified session was not saved correctly")
	}
	raw, err := os.ReadFile(h.config.SessionFile)
	if err != nil || bytes.Contains(raw, []byte("PRIVATE")) || bytes.Contains(raw, []byte(h.inputs[2])) || bytes.Contains(raw, []byte(h.inputs[3])) {
		t.Fatal("session plaintext leaked")
	}
}

func TestProtonInteractiveEmailFailuresDoNotRetryOrChangeSession(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*protonInteractiveHarness)
		emails   int
		replays  int
		deletes  int
		contains string
	}{
		{"wrong-password", func(h *protonInteractiveHarness) {
			h.initialErr = &proton.APIError{Status: 401, Code: proton.PasswordWrong}
		}, 0, 0, 0, "api_code=8002"},
		{"captcha-only", func(h *protonInteractiveHarness) {
			h.initialErr.(*proton.APIError).Details = []byte(`{"HumanVerificationMethods":["captcha"]}`)
		}, 0, 0, 0, "offered_methods=captcha"},
		{"ownership-email", func(h *protonInteractiveHarness) {
			h.initialErr.(*proton.APIError).Details = []byte(`{"HumanVerificationMethods":["ownership-email"]}`)
		}, 0, 0, 0, "offered_methods=ownership-email"},
		{"unknown-method", func(h *protonInteractiveHarness) {
			h.initialErr.(*proton.APIError).Details = []byte(`{"HumanVerificationMethods":["PRIVATE_METHOD"]}`)
		}, 0, 0, 0, "offered_methods=unknown"},
		{"null-details", func(h *protonInteractiveHarness) { h.initialErr.(*proton.APIError).Details = []byte(`null`) }, 0, 0, 0, "offered_methods=unavailable"},
		{"malformed-details", func(h *protonInteractiveHarness) { h.initialErr.(*proton.APIError).Details = []byte(`PRIVATE`) }, 0, 0, 0, "offered_methods=unavailable"},
		{"auth-info-challenge", func(h *protonInteractiveHarness) { h.initialPath = "/api/auth/v4/info" }, 0, 0, 0, "stage=auth-info"},
		{"cancel-address", func(h *protonInteractiveHarness) { h.promptErrAt = 2 }, 0, 0, 0, "cancelled"},
		{"invalid-address", func(h *protonInteractiveHarness) { h.inputs[2] = "PRIVATE_INVALID_EMAIL" }, 0, 0, 0, "address is invalid"},
		{"email-rejected", func(h *protonInteractiveHarness) {
			h.sendErr = &proton.APIError{Status: 429, Code: 98765, Message: "PRIVATE_RESPONSE"}
		}, 1, 0, 0, "stage=verification-email http_status=429"},
		{"cancel-code", func(h *protonInteractiveHarness) { h.promptErrAt = 3 }, 1, 0, 0, "cancelled"},
		{"blank-code", func(h *protonInteractiveHarness) { h.inputs[3] = "" }, 1, 0, 0, "cancelled"},
		{"invalid-code", func(h *protonInteractiveHarness) { h.inputs[3] = "PRIVATE_INVALID_CODE" }, 1, 0, 0, "code is invalid"},
		{"wrong-code", func(h *protonInteractiveHarness) {
			h.replayErr = &proton.APIError{Status: 422, Code: proton.HumanValidationInvalidToken, Message: "PRIVATE_RESPONSE"}
		}, 1, 1, 0, "api_code=12087"},
		{"second-challenge", func(h *protonInteractiveHarness) { h.replayErr = h.initialErr }, 1, 1, 0, "api_code=9001"},
		{"network-failure", func(h *protonInteractiveHarness) { h.replayErr = errors.New("PRIVATE_NETWORK_URL") }, 1, 1, 0, "no resend"},
		{"user-failed", func(h *protonInteractiveHarness) { h.userStatus = 503 }, 1, 1, 1, "stage=user http_status=503"},
		{"wrong-account", func(h *protonInteractiveHarness) { h.userID = "other-account"; h.config.AccountID = "account" }, 1, 1, 1, "account"},
		{"fido-only", func(h *protonInteractiveHarness) { h.twoFA = proton.HasFIDO2 }, 1, 1, 1, "FIDO2-only"},
		{"totp-failed", func(h *protonInteractiveHarness) { h.twoFA = proton.HasTOTP; h.totpStatus = 422 }, 1, 1, 1, "stage=totp"},
	} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", tc.name, existing), func(t *testing.T) {
				h := newProtonInteractiveHarness(t)
				var before []byte
				if existing {
					store, err := openProtonSessionStore(h.config.SessionFile, h.config.SessionKeyFile)
					if err != nil {
						t.Fatal(err)
					}
					if err := store.save(protonSavedSession{AccountID: "account", UID: "prior-session", RefreshToken: "PRIVATE_PRIOR_REFRESH"}); err != nil {
						t.Fatal(err)
					}
					store.close()
					before, err = os.ReadFile(h.config.SessionFile)
					if err != nil {
						t.Fatal(err)
					}
				}
				tc.mutate(h)
				err := h.run(context.Background())
				if err == nil || !strings.Contains(err.Error(), tc.contains) {
					t.Fatalf("missing expected safe failure: %v", err)
				}
				h.assertPrivate(t, err)
				if h.logins != 1 || h.emails != tc.emails || h.replays != tc.replays || h.deletes != tc.deletes {
					t.Fatalf("unexpected retries or cleanup: login=%d email=%d replay=%d delete=%d", h.logins, h.emails, h.replays, h.deletes)
				}
				after, readErr := os.ReadFile(h.config.SessionFile)
				if existing {
					if readErr != nil || !bytes.Equal(before, after) {
						t.Fatal("failed authentication changed existing session")
					}
				} else if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatal("failed authentication created a session")
				}
			})
		}
	}
}

func TestProtonInteractiveContextCancellationDoesNotSubmit(t *testing.T) {
	for _, index := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			h := newProtonInteractiveHarness(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.onPrompt = func(current int) {
				if current == index {
					cancel()
				}
			}
			err := h.run(ctx)
			if err == nil || !strings.Contains(err.Error(), "cancelled") || h.replays != 0 {
				t.Fatal("cancelled challenge was submitted")
			}
			if index < 3 && h.emails != 0 {
				t.Fatal("cancelled address sent verification email")
			}
			if _, err := os.Stat(h.config.SessionFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cancelled authentication saved session")
			}
			h.assertPrivate(t, err)
		})
	}
}

func TestProtonInteractiveWithoutChallengeDoesNotPromptForEmail(t *testing.T) {
	h := newProtonInteractiveHarness(t)
	h.initialErr = nil
	if err := h.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.prompts != 2 || h.logins != 1 || h.emails != 0 || h.replays != 0 || strings.Contains(h.output.String(), "verification") {
		t.Fatal("email was inferred without an offered challenge")
	}
	h.assertPrivate(t, nil)
}

func TestProtonInteractiveEmailThenTOTP(t *testing.T) {
	h := newProtonInteractiveHarness(t)
	h.twoFA = proton.HasTOTP
	if err := h.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.prompts != 5 || h.logins != 1 || h.emails != 1 || h.replays != 1 || h.userReads != 1 {
		t.Fatal("email verification incorrectly replaced configured TOTP")
	}
	h.assertPrivate(t, nil)
}

func TestProtonUnattendedHumanVerificationReportsMethodsWithoutRetry(t *testing.T) {
	a, _ := bootstrapProtonAdapter(t)
	requests := 0
	a.transport.base = protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return protonTestResponse(request, 422, `{"Code":9001,"Error":"PRIVATE_RESPONSE","Details":{"HumanVerificationMethods":["email","ownership-email","PRIVATE_METHOD"],"HumanVerificationToken":"PRIVATE_TOKEN"}}`), nil
	})
	for i := 0; i < 2; i++ {
		_, err := a.Poll(context.Background(), "")
		var required *ProtonAuthRequiredError
		if !errors.As(err, &required) || !strings.Contains(err.Error(), "api_code=9001 offered_methods=email,ownership-email,unknown") || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("safe unattended method information lost: %v", err)
		}
	}
	if requests != 1 {
		t.Fatal("unattended challenge triggered additional requests")
	}
	if _, err := os.Stat(a.config.SessionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unattended human-verification failure saved session")
	}
}

func TestProtonVerificationInputValidation(t *testing.T) {
	for _, value := range []string{"", "PRIVATE", "Name <test@example.test>", "a@example.test\r\nPRIVATE", "a:b@example.test", "a b@example.test", strings.Repeat("a", 255) + "@example.test"} {
		if validProtonVerificationAddress(value) {
			t.Fatal("invalid email destination accepted")
		}
	}
	if !validProtonVerificationAddress("test+verification@example.test") || !validProtonVerificationCode("012345") {
		t.Fatal("valid verification input rejected")
	}
	for _, value := range []string{"", "12345", "1234567", "12345a", "123:45", "123\n45", "１２３４５６"} {
		if validProtonVerificationCode(value) {
			t.Fatal("invalid verification code accepted")
		}
	}
}

func TestProtonSDKVerificationEmailRequestAndFailureAreSanitized(t *testing.T) {
	requests := 0
	transport := &protonTransport{base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodPost || request.URL.Path != "/api/core/v4/users/code" || request.Header.Get("x-pm-human-verification-token") != "" {
			t.Fatal("incorrect SDK email verification endpoint or leaked challenge token")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || !bytes.Contains(body, []byte(`"Type":"email"`)) || !bytes.Contains(body, []byte(`"Address":"private-email@example.test"`)) {
			t.Fatal("incorrect SDK verification request body")
		}
		return protonTestResponse(request, 429, `{"Code":98765,"Error":"PRIVATE_RESPONSE","Details":{"Token":"PRIVATE_TOKEN"}}`), nil
	})}
	manager := proton.New(proton.WithTransport(transport), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
	defer manager.Close()
	ctx := protonAuthContext(context.Background())
	err := manager.SendVerificationCode(ctx, proton.SendVerificationCodeReq{Username: "PRIVATE_USERNAME", Type: proton.EmailTokenType, Destination: proton.TokenDestination{Address: "private-email@example.test"}})
	diagnostic := protonLoginError(ctx, protonStageUnknown, err)
	if requests != 1 || diagnostic.stage != protonStageVerificationEmail || diagnostic.httpStatus != 429 || diagnostic.apiCode != 98765 || strings.Contains(diagnostic.Error(), "PRIVATE") {
		t.Fatalf("SDK email request retried or lost safe diagnostics: requests=%d %v", requests, diagnostic)
	}
}

func TestProtonSDKHumanVerificationLoginHeaders(t *testing.T) {
	// Public synthetic SRP values from go-srp v0.0.7, with its MIT notice next
	// to the fixture. No live account, proof-validation override, or network.
	info, err := os.ReadFile("testdata/proton-auth-info.json")
	if err != nil {
		t.Fatal(err)
	}
	requests, auths, emails := 0, 0, 0
	transport := &protonTransport{base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		token := request.Header.Get("x-pm-human-verification-token")
		method := request.Header.Get("x-pm-human-verification-token-type")
		switch request.Method + " " + request.URL.Path {
		case "POST /api/auth/v4/info":
			if token != "" || method != "" {
				t.Fatal("verification proof reached auth-info")
			}
			return protonTestResponse(request, 200, string(info)), nil
		case "POST /api/core/v4/users/code":
			emails++
			if token != "" || method != "" {
				t.Fatal("verification proof or challenge token leaked into email request")
			}
			return protonTestResponse(request, 200, `{"Code":1000}`), nil
		case "POST /api/auth/v4":
			auths++
			if auths == 1 {
				if token != "" || method != "" {
					t.Fatal("initial login sent unrequested verification headers")
				}
				return protonTestResponse(request, 422, `{"Code":9001,"Error":"PRIVATE_ERROR","Details":{"HumanVerificationMethods":["email"],"HumanVerificationToken":"PRIVATE_CHALLENGE_TOKEN"}}`), nil
			}
			if auths != 2 || token != "private-email@example.test:746291" || method != "email" {
				t.Fatal("SDK human-verification continuation used wrong proof or retried")
			}
			return protonTestResponse(request, 422, `{"Code":12087,"Error":"PRIVATE_ERROR"}`), nil
		default:
			t.Fatal("unexpected SDK human-verification route")
			return nil, errors.New("unexpected route")
		}
	})}
	manager := proton.New(proton.WithTransport(transport), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
	defer manager.Close()
	prompts := 0
	var output bytes.Buffer
	client, _, err := protonInteractiveLogin(context.Background(), manager, "PRIVATE_USERNAME", []byte("PRIVATE_PASSWORD"), func(string) ([]byte, error) {
		prompts++
		switch prompts {
		case 1:
			return []byte("private-email@example.test"), nil
		case 2:
			return []byte("746291"), nil
		default:
			t.Fatal("SDK flow repeated operator challenge")
			return nil, errors.New("unexpected prompt")
		}
	}, &output)
	if client != nil || err == nil || !strings.Contains(err.Error(), "stage=auth http_status=422 api_code=12087") || requests != 5 || auths != 2 || emails != 1 || prompts != 2 {
		t.Fatalf("SDK verification flow did not reach bounded continuation: requests=%d auths=%d emails=%d prompts=%d err=%v", requests, auths, emails, prompts, err)
	}
	if strings.Contains(output.String()+err.Error(), "PRIVATE") || strings.Contains(output.String()+err.Error(), "private-email") || strings.Contains(output.String()+err.Error(), "746291") {
		t.Fatal("SDK flow leaked a credential, destination, code, or token")
	}
}
