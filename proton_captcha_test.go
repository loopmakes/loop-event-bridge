package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	proton "github.com/ProtonMail/go-proton-api"
)

func newProtonCaptchaHarness(t *testing.T) *protonInteractiveHarness {
	t.Helper()
	h := newProtonInteractiveHarness(t)
	h.hvMethod, h.hvToken = "captcha", "PRIVATE_HV_TOKEN"
	h.initialErr.(*proton.APIError).Details = []byte(`{"HumanVerificationMethods":["captcha"],"HumanVerificationToken":"PRIVATE_HV_TOKEN","WebUrl":"https://PRIVATE_EVIL.invalid"}`)
	h.inputs = []string{"PRIVATE_USERNAME", "PRIVATE_PASSWORD", "", "PRIVATE_TOTP"}
	return h
}

func assertProtonCaptchaPrivate(t *testing.T, h *protonInteractiveHarness, err error) {
	t.Helper()
	// The one displayed URL intentionally contains the challenge token. All
	// other terminal text, returned errors, and saved data must exclude it.
	output := h.output.String()
	link := "https://verify.proton.me/?methods=captcha&token=" + url.QueryEscape(h.hvToken)
	if strings.Count(output, link) > 1 {
		t.Fatal("private link was displayed more than once")
	}
	h.output.Reset()
	h.output.WriteString(strings.ReplaceAll(output, link, "[private handoff]"))
	h.assertPrivate(t, err)
	h.output.Reset()
	h.output.WriteString(output)
}

func TestProtonInteractiveCaptchaSuccessAndTOTP(t *testing.T) {
	for _, withTOTP := range []bool{false, true} {
		t.Run(fmt.Sprint(withTOTP), func(t *testing.T) {
			h := newProtonCaptchaHarness(t)
			if withTOTP {
				h.twoFA = proton.HasTOTP
			}
			h.onPrompt = func(index int) {
				if index >= 2 && h.initialCtx.Err() == nil {
					t.Fatal("request timeout remained active during human verification")
				}
				if _, err := os.Stat(h.config.SessionFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("session saved before authentication finished")
				}
			}
			if err := h.run(context.Background()); err != nil {
				t.Fatal(err)
			}
			wantPrompts := 3
			if withTOTP {
				wantPrompts++
			}
			if h.logins != 1 || h.replays != 1 || h.emails != 0 || h.prompts != wantPrompts || h.userReads != 1 || h.deletes != 0 {
				t.Fatal("CAPTCHA did not follow one bounded continuation and normal account verification")
			}
			if !strings.Contains(h.output.String(), "Press Enter after Proton confirms verification") || !strings.Contains(h.output.String(), "https://verify.proton.me/?methods=captcha&token=PRIVATE_HV_TOKEN") {
				t.Fatal("manual browser handoff missing")
			}
			assertProtonCaptchaPrivate(t, h, nil)
			store, err := openProtonSessionStore(h.config.SessionFile, h.config.SessionKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			saved, err := store.load()
			if err != nil || saved.AccountID != "account" || saved.UID != "session" || saved.RefreshToken != "PRIVATE_REFRESH" {
				t.Fatal("verified session missing")
			}
			plaintext, _ := json.Marshal(saved)
			raw, readErr := os.ReadFile(h.config.SessionFile)
			if readErr != nil || bytes.Contains(raw, []byte("PRIVATE")) || bytes.Contains(plaintext, []byte(h.hvToken)) || bytes.Contains(plaintext, []byte("verify.proton.me")) {
				t.Fatal("challenge or plaintext credentials persisted")
			}
		})
	}
}

func TestProtonInteractiveCaptchaFailuresPreserveSession(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		mutate                   func(*protonInteractiveHarness)
		wantReplays, wantDeletes int
		contains                 string
	}{
		{"cancel", func(h *protonInteractiveHarness) { h.promptErrAt = 2 }, 0, 0, "cancelled"},
		{"typed-text", func(h *protonInteractiveHarness) { h.inputs[2] = "PRIVATE_INPUT" }, 0, 0, "expected Enter"},
		{"expired-or-unsolved", func(h *protonInteractiveHarness) {
			h.replayErr = &proton.APIError{Status: 422, Code: proton.HumanValidationInvalidToken, Message: "PRIVATE_RESPONSE"}
		}, 1, 0, "api_code=12087"},
		{"second-challenge", func(h *protonInteractiveHarness) { h.replayErr = h.initialErr }, 1, 0, "api_code=9001"},
		{"network-failure", func(h *protonInteractiveHarness) { h.replayErr = errors.New("PRIVATE_URL") }, 1, 0, "no further login"},
		{"wrong-account", func(h *protonInteractiveHarness) { h.userID = "another"; h.config.AccountID = "account" }, 1, 1, "account"},
		{"user-read-failure", func(h *protonInteractiveHarness) { h.userStatus = 503 }, 1, 1, "stage=user"},
		{"totp-failure", func(h *protonInteractiveHarness) { h.twoFA = proton.HasTOTP; h.totpStatus = 422 }, 1, 1, "stage=totp"},
	} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", tc.name, existing), func(t *testing.T) {
				h := newProtonCaptchaHarness(t)
				var before []byte
				if existing {
					store, err := openProtonSessionStore(h.config.SessionFile, h.config.SessionKeyFile)
					if err != nil {
						t.Fatal(err)
					}
					if err := store.save(protonSavedSession{AccountID: "account", UID: "prior-session", RefreshToken: "PRIVATE_PRIOR"}); err != nil {
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
				if err == nil || !strings.Contains(err.Error(), tc.contains) || h.logins != 1 || h.replays != tc.wantReplays || h.deletes != tc.wantDeletes || h.emails != 0 {
					t.Fatalf("incorrect bounded CAPTCHA failure: %v", err)
				}
				assertProtonCaptchaPrivate(t, h, err)
				after, readErr := os.ReadFile(h.config.SessionFile)
				if existing {
					if readErr != nil || !bytes.Equal(before, after) {
						t.Fatal("failed login changed existing ciphertext")
					}
				} else if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatal("failed login saved session")
				}
			})
		}
	}
}

func TestProtonInteractiveCaptchaCancellationDoesNotContinue(t *testing.T) {
	h := newProtonCaptchaHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.onPrompt = func(index int) {
		if index == 2 {
			cancel()
		}
	}
	err := h.run(ctx)
	if err == nil || !strings.Contains(err.Error(), "cancelled") || h.replays != 0 || h.emails != 0 {
		t.Fatal("cancelled browser handoff continued")
	}
	assertProtonCaptchaPrivate(t, h, err)
}

func TestProtonCaptchaChallengeValidationAndQueryEncoding(t *testing.T) {
	for _, token := range []string{"", "has space", "PRIVATE\r\nHeader:x", "PRIVATE\x1b[2J", "PRIVATE\x7f", "PRIVATEé", strings.Repeat("A", 4097)} {
		raw, _ := json.Marshal(proton.APIHVDetails{Methods: []string{"captcha"}, Token: token})
		hv, link := protonCaptchaChallenge(&proton.APIError{Code: proton.HumanVerificationRequired, Details: raw})
		if hv != nil || link != "" {
			t.Fatal("invalid token accepted")
		}
	}
	for _, details := range []string{`null`, `{}`, `PRIVATE`, `{"HumanVerificationMethods":["Captcha"],"HumanVerificationToken":"PRIVATE"}`, `{"HumanVerificationMethods":["email"],"HumanVerificationToken":"PRIVATE"}`} {
		hv, link := protonCaptchaChallenge(&proton.APIError{Code: proton.HumanVerificationRequired, Details: []byte(details)})
		if hv != nil || link != "" {
			t.Fatal("unoffered or malformed challenge accepted")
		}
	}
	token := "PRIVATE/?x=1&methods=email#frag+%"
	raw, _ := json.Marshal(map[string]any{"HumanVerificationMethods": []string{"captcha", "sms", "PRIVATE_METHOD"}, "HumanVerificationToken": token, "WebUrl": "https://PRIVATE_EVIL.invalid"})
	hv, link := protonCaptchaChallenge(fmt.Errorf("PRIVATE_URL: %w", &proton.APIError{Code: proton.HumanVerificationRequired, Details: raw}))
	u, err := url.Parse(link)
	if err != nil || hv == nil || hv.Token != token || len(hv.Methods) != 1 || hv.Methods[0] != "captcha" || u.Scheme != "https" || u.Host != "verify.proton.me" || u.User != nil || u.Path != "/" || u.Fragment != "" || len(u.Query()) != 2 || u.Query().Get("token") != token || u.Query().Get("methods") != "captcha" {
		t.Fatal("challenge URL/header construction changed host, method, or token")
	}
}

func TestProtonCaptchaInvalidDetailsAndUnsupportedStagesDoNotDisplayURL(t *testing.T) {
	for _, tc := range []struct{ name, details, path string }{
		{"missing-token", `{"HumanVerificationMethods":["captcha"]}`, "/api/auth/v4"},
		{"invalid-token", `{"HumanVerificationMethods":["captcha"],"HumanVerificationToken":"PRIVATE\n"}`, "/api/auth/v4"},
		{"auth-info", `{"HumanVerificationMethods":["captcha"],"HumanVerificationToken":"PRIVATE"}`, "/api/auth/v4/info"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newProtonCaptchaHarness(t)
			h.initialErr.(*proton.APIError).Details = []byte(tc.details)
			h.initialPath = tc.path
			err := h.run(context.Background())
			if err == nil || h.prompts != 2 || h.replays != 0 || h.emails != 0 || strings.Contains(h.output.String(), "https://") {
				t.Fatal("invalid or unsupported challenge exposed a handoff")
			}
			h.assertPrivate(t, err)
		})
	}
}

func TestProtonSDKCaptchaContinuationUsesOriginalTokenOnlyAtAuth(t *testing.T) {
	info, err := os.ReadFile("testdata/proton-auth-info.json")
	if err != nil {
		t.Fatal(err)
	}
	requests, auths, prompts := 0, 0, 0
	transport := &protonTransport{base: protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		token, method := request.Header.Get("x-pm-human-verification-token"), request.Header.Get("x-pm-human-verification-token-type")
		switch request.Method + " " + request.URL.Path {
		case "POST /api/auth/v4/info":
			if token != "" || method != "" {
				t.Fatal("CAPTCHA token leaked to auth-info")
			}
			return protonTestResponse(request, 200, string(info)), nil
		case "POST /api/auth/v4":
			auths++
			if auths == 1 {
				if token != "" || method != "" {
					t.Fatal("initial login included unrequested verification")
				}
				return protonTestResponse(request, 422, `{"Code":9001,"Error":"PRIVATE_ERROR","Details":{"HumanVerificationMethods":["captcha","sms"],"HumanVerificationToken":"PRIVATE_HV_TOKEN"}}`), nil
			}
			if auths != 2 || prompts != 1 || token != "PRIVATE_HV_TOKEN" || method != "captcha" {
				t.Fatal("incorrect or repeated CAPTCHA continuation")
			}
			return protonTestResponse(request, 422, `{"Code":12087,"Error":"PRIVATE_ERROR"}`), nil
		default:
			t.Fatal("unexpected request: browser challenge must remain manual")
			return nil, errors.New("unexpected route")
		}
	})}
	manager := proton.New(proton.WithTransport(transport), proton.WithRetryCount(0), proton.WithLogger(protonQuietLogger{}))
	defer manager.Close()
	var output bytes.Buffer
	client, _, err := protonInteractiveLogin(context.Background(), manager, "PRIVATE_USERNAME", []byte("PRIVATE_PASSWORD"), func(string) ([]byte, error) {
		prompts++
		if requests != 2 || prompts != 1 {
			t.Fatal("browser wait repeated or continuation began before human input")
		}
		return nil, nil
	}, &output)
	if client != nil || err == nil || requests != 4 || auths != 2 || prompts != 1 || !strings.Contains(err.Error(), "stage=auth http_status=422 api_code=12087") || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("SDK CAPTCHA continuation failed safe bounds: %v", err)
	}
	clean := strings.ReplaceAll(output.String(), "https://verify.proton.me/?methods=captcha&token=PRIVATE_HV_TOKEN", "[private handoff]")
	if strings.Contains(clean, "PRIVATE") {
		t.Fatal("provider secrets leaked outside private handoff")
	}
}

func TestProtonCaptchaOutputFailureDoesNotContinue(t *testing.T) {
	h := newProtonCaptchaHarness(t)
	_, _, err := protonInteractiveLogin(context.Background(), h.manager, h.inputs[0], []byte(h.inputs[1]), func(string) ([]byte, error) { t.Fatal("prompt after output failure"); return nil, nil }, protonFailingWriter{})
	if err == nil || strings.Contains(err.Error(), "PRIVATE") || h.replays != 0 {
		t.Fatal("output failure continued or leaked writer error")
	}
}

func TestProtonUnattendedCaptchaNeverDisplaysURLOrRetries(t *testing.T) {
	a, _ := bootstrapProtonAdapter(t)
	requests := 0
	a.transport.base = protonRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return protonTestResponse(request, 422, `{"Code":9001,"Error":"PRIVATE_RESPONSE","Details":{"HumanVerificationMethods":["captcha"],"HumanVerificationToken":"PRIVATE_HV_TOKEN","WebUrl":"https://PRIVATE_EVIL.invalid"}}`), nil
	})
	for i := 0; i < 2; i++ {
		_, err := a.Poll(context.Background(), "")
		var required *ProtonAuthRequiredError
		if !errors.As(err, &required) || !strings.Contains(err.Error(), "offered_methods=captcha") || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "PRIVATE") || strings.Contains(err.Error(), "https://") {
			t.Fatal("unattended CAPTCHA diagnostic exposed private handoff data")
		}
	}
	if requests != 1 {
		t.Fatal("unattended CAPTCHA retried")
	}
	if _, err := os.Stat(a.config.SessionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unattended CAPTCHA saved a session")
	}
}

type protonFailingWriter struct{}

func (protonFailingWriter) Write([]byte) (int, error) { return 0, errors.New("PRIVATE_OUTPUT_ERROR") }

var _ io.Writer = protonFailingWriter{}
