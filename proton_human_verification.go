package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
)

// Only exact, documented method names may reach operator output. Unknown
// provider strings, challenge tokens, destinations, and raw Details never do.
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

// One initial login, one explicitly requested email, and one code submission.
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
	if diagnostic.methods&protonHVEmail == 0 {
		return nil, proton.Auth{}, protonHVFailure(diagnostic, "Only the exact email method is supported by this CLI; no verification request or retry was made")
	}
	// The SDK attaches human-verification headers only to POST /auth/v4.
	// In particular an auth-info challenge cannot be completed by this flow.
	if diagnostic.stage != protonStageAuth {
		return nil, proton.Auth{}, protonHVFailure(diagnostic, "Email verification at this authentication stage is unsupported; no verification request or retry was made")
	}
	if _, err := fmt.Fprintf(out, "%s\nOnly email is supported here. Enter an address to request one verification email from Proton; other offered methods are unsupported. Blank input or Ctrl-C cancels.\n", diagnostic); err != nil {
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
