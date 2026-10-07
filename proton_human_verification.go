package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"strings"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
)

// Only exact, documented method names may reach diagnostics. The interactive
// browser handoff alone displays a validated, encoded token in its official URL.
type protonHVMethods uint16

const (
	protonHVEmail protonHVMethods = 1 << iota
	protonHVCaptcha
	protonHVSMS
	protonHVPayment
	protonHVInvite
	protonHVCoupon
	protonHVOwnershipEmail
	protonHVOwnershipSMS
	protonHVUnknown
)

var protonHVMethodNames = [...]struct {
	flag protonHVMethods
	name string
}{
	{protonHVEmail, "email"},
	{protonHVCaptcha, "captcha"},
	{protonHVSMS, "sms"},
	{protonHVPayment, "payment"},
	{protonHVInvite, "invite"},
	{protonHVCoupon, "coupon"},
	{protonHVOwnershipEmail, "ownership-email"},
	{protonHVOwnershipSMS, "ownership-sms"},
}

func protonOfferedHVMethods(apiErr *proton.APIError) protonHVMethods {
	if apiErr == nil || apiErr.Code != proton.HumanVerificationRequired || len(apiErr.Details) > 64<<10 {
		return 0
	}
	details, err := apiErr.GetHVDetails()
	if err != nil || details == nil || len(details.Methods) > 64 {
		return 0
	}
	var methods protonHVMethods
	for _, method := range details.Methods {
		flag := protonHVUnknown
		for _, known := range protonHVMethodNames {
			if method == known.name {
				flag = known.flag
				break
			}
		}
		methods |= flag
	}
	return methods
}

func (methods protonHVMethods) String() string {
	var names []string
	for _, known := range protonHVMethodNames {
		if methods&known.flag != 0 {
			names = append(names, known.name)
		}
	}
	if methods&protonHVUnknown != 0 {
		names = append(names, "unknown")
	}
	if len(names) == 0 {
		return "unavailable"
	}
	return strings.Join(names, ",")
}

type protonInteractiveManager interface {
	NewClientWithLogin(context.Context, string, []byte) (*proton.Client, proton.Auth, error)
	NewClientWithLoginWithHVToken(context.Context, string, []byte, *proton.APIHVDetails) (*proton.Client, proton.Auth, error)
	SendVerificationCode(context.Context, proton.SendVerificationCodeReq) error
}

// One initial login and one human-verification continuation. Email permits one
// explicitly requested message and code; CAPTCHA is solved manually in a browser.
// This is the SDK's normal human-verification continuation, not a retry loop.
// Human input sits outside request timeouts; every network operation is bounded.
func protonInteractiveLogin(ctx context.Context, manager protonInteractiveManager, username string, password []byte, prompt protonAuthPrompt, out io.Writer) (*proton.Client, proton.Auth, error) {
	requestCtx, cancel := context.WithTimeout(protonAuthContext(ctx), time.Minute)
	client, auth, err := manager.NewClientWithLogin(requestCtx, username, password)
	cancel()
	if err == nil {
		return client, auth, nil
	}
	diagnostic := protonLoginError(requestCtx, protonStageLogin, err)
	if diagnostic.apiCode != proton.HumanVerificationRequired {
		return nil, proton.Auth{}, diagnostic
	}
	if diagnostic.methods&(protonHVEmail|protonHVCaptcha) == 0 {
		return nil, proton.Auth{}, protonHVFailure(diagnostic, "Only the exact email or captcha methods are supported by this CLI; no verification request or retry was made")
	}
	// The SDK attaches human-verification headers only to POST /auth/v4.
	// In particular an auth-info challenge cannot be completed by this flow.
	if diagnostic.stage != protonStageAuth {
		return nil, proton.Auth{}, protonHVFailure(diagnostic, "Human verification at this authentication stage is unsupported; no verification request or retry was made")
	}
	// Preserve the existing email path when both supported methods are offered.
	if diagnostic.methods&protonHVEmail == 0 {
		return protonInteractiveCaptcha(ctx, manager, username, password, prompt, out, err, diagnostic)
	}
	if _, err := fmt.Fprintf(out, "%s\nUsing the offered email method. Enter an address to request one verification email from Proton. Blank input or Ctrl-C cancels.\n", diagnostic); err != nil {
		return nil, proton.Auth{}, errors.New("Proton terminal unavailable")
	}
	addressInput, err := readProtonAuthInput(ctx, prompt, "Send verification email to address (hidden): ")
	if err != nil {
		return nil, proton.Auth{}, err
	}
	defer clear(addressInput)
	address := strings.TrimSpace(string(addressInput))
	if !validProtonVerificationAddress(address) {
		return nil, proton.Auth{}, errors.New("Proton verification email address is invalid; no email was requested")
	}
	requestCtx, cancel = context.WithTimeout(protonAuthContext(ctx), time.Minute)
	err = manager.SendVerificationCode(requestCtx, proton.SendVerificationCodeReq{
		Username:    username,
		Type:        proton.EmailTokenType,
		Destination: proton.TokenDestination{Address: address},
	})
	cancel()
	if err != nil {
		return nil, proton.Auth{}, protonLoginError(requestCtx, protonStageVerificationEmail, err)
	}
	codeInput, err := readProtonAuthInput(ctx, prompt, "Proton email verification code (6 digits, hidden; one attempt): ")
	if err != nil {
		return nil, proton.Auth{}, err
	}
	defer clear(codeInput)
	code := strings.TrimSpace(string(codeInput))
	if !validProtonVerificationCode(code) {
		return nil, proton.Auth{}, errors.New("Proton email verification code is invalid; no code was submitted")
	}
	// Proton's plain email flow uses address:code. The challenge's original
	// HumanVerificationToken is NOT that proof; ownership-email is a different,
	// token-bound flow and is intentionally not treated as email.
	hv := &proton.APIHVDetails{Methods: []string{"email"}, Token: address + ":" + code}
	defer func() { hv.Token = "" }()
	requestCtx, cancel = context.WithTimeout(protonAuthContext(ctx), time.Minute)
	client, auth, err = manager.NewClientWithLoginWithHVToken(requestCtx, username, password, hv)
	cancel()
	if err != nil {
		return nil, proton.Auth{}, protonHVFailure(protonLoginError(requestCtx, protonStageLogin, err), "Email verification did not complete; no resend or further login attempt was made")
	}
	return client, auth, nil
}

// The official Proton Bridge CLI uses this external-browser handoff: display
// the original challenge URL, wait for the operator, then continue with the same
// token. Proton's non-embedded verify app grants a redeemable proof on that
// token after the human solves the CAPTCHA. No browser cookies, callback server,
// CAPTCHA solver, or copied browser response token are needed.
func protonInteractiveCaptcha(ctx context.Context, manager protonInteractiveManager, username string, password []byte, prompt protonAuthPrompt, out io.Writer, loginErr error, diagnostic *protonAuthError) (*proton.Client, proton.Auth, error) {
	hv, verificationURL := protonCaptchaChallenge(loginErr)
	if hv == nil {
		return nil, proton.Auth{}, protonHVFailure(diagnostic, "Proton browser verification details are unavailable or invalid; no URL was displayed or login retry made")
	}
	defer func() { hv.Token = "" }()
	if ctx.Err() != nil {
		return nil, proton.Auth{}, errors.New("Proton interactive authentication cancelled")
	}
	if _, err := fmt.Fprintf(out, "%s\nOpen this private Proton link in your own browser and complete the CAPTCHA. Keep the link out of logs, screenshots, and messages. Return here afterward; Ctrl-C cancels.\n\n%s\n\n", diagnostic, verificationURL); err != nil {
		return nil, proton.Auth{}, errors.New("Proton terminal unavailable")
	}
	// Empty input means continue only at this explicit prompt. Passwords, email
	// destinations, and codes still use readProtonAuthInput's nonempty check.
	value, err := prompt("Press Enter after Proton confirms verification (one login continuation): ")
	defer clear(value)
	if ctx.Err() != nil || err != nil {
		return nil, proton.Auth{}, errors.New("Proton interactive authentication cancelled or input unavailable")
	}
	if len(value) != 0 {
		return nil, proton.Auth{}, errors.New("Proton browser verification cancelled: expected Enter without text; no login retry made")
	}
	requestCtx, cancel := context.WithTimeout(protonAuthContext(ctx), time.Minute)
	defer cancel()
	client, auth, err := manager.NewClientWithLoginWithHVToken(requestCtx, username, password, hv)
	if err != nil {
		return nil, proton.Auth{}, protonHVFailure(protonLoginError(requestCtx, protonStageLogin, err), "Browser verification did not complete; no further login attempt was made")
	}
	return client, auth, nil
}

func protonCaptchaChallenge(err error) (*proton.APIHVDetails, string) {
	var apiErr *proton.APIError
	if !errors.As(err, &apiErr) || protonOfferedHVMethods(apiErr)&protonHVCaptcha == 0 {
		return nil, ""
	}
	details, parseErr := apiErr.GetHVDetails()
	if parseErr != nil || details == nil || len(details.Token) == 0 || len(details.Token) > 4096 {
		return nil, ""
	}
	// The token later becomes an HTTP header: reject whitespace, controls, and
	// non-ASCII rather than passing unexpected bytes to HTTP or the terminal.
	for _, ch := range details.Token {
		if ch <= ' ' || ch >= 127 {
			return nil, ""
		}
	}
	// Never trust a provider WebUrl or forward arbitrary method names. The fixed
	// Proton origin and query encoding prevent host/query/terminal injection.
	hv := &proton.APIHVDetails{Methods: []string{"captcha"}, Token: details.Token}
	query := url.Values{"methods": {"captcha"}, "token": {hv.Token}}
	return hv, "https://verify.proton.me/?" + query.Encode()
}

func protonHVFailure(diagnostic *protonAuthError, message string) error {
	// Both arguments contain only local wording and allowlisted scalar fields.
	// Never attach an SDK error as an underlying cause.
	return errors.New(message + "; " + diagnostic.Error())
}

func validProtonVerificationAddress(value string) bool {
	if len(value) == 0 || len(value) > 254 || strings.ContainsAny(value, ":<>") {
		return false
	}
	for _, char := range value {
		if char <= ' ' || char >= 127 {
			return false
		}
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value
}

func validProtonVerificationCode(value string) bool {
	if len(value) != 6 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
