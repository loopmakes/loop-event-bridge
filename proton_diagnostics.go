package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	proton "github.com/ProtonMail/go-proton-api"
)

// The pinned SDK does not name these codes. Proton uses them for invalid
// platform/product/version identities, including structurally valid products
// that the server rejects. They do not imply incorrect account credentials.
const (
	protonAppVersionInvalidCode proton.Code = 2064
	protonAppVersionFormatCode  proton.Code = 5002
)

// A typed, constant local error allows source status to retain this specific
// configuration diagnosis without trusting arbitrary initializer messages.
type protonAppVersionConfigError struct{}

func (*protonAppVersionConfigError) Error() string {
	return "invalid Proton application-version configuration; PROTON_APP_VERSION requires an integration identity, not a bare frontend version; see docs/proton.md (stage=configuration http_status=0 api_code=0)"
}

// Stages are local enum values, never provider strings, URLs, or error text.
type protonAuthStage uint8

const (
	protonStageUnknown protonAuthStage = iota
	protonStageLogin
	protonStageAuthInfo
	protonStageAuth
	protonStageTOTP
	protonStageUser
	protonStageRefresh
	protonStageModulus
)

func (s protonAuthStage) String() string {
	switch s {
	case protonStageLogin:
		return "login"
	case protonStageAuthInfo:
		return "auth-info"
	case protonStageAuth:
		return "auth"
	case protonStageTOTP:
		return "totp"
	case protonStageUser:
		return "user"
	case protonStageRefresh:
		return "refresh"
	case protonStageModulus:
		return "modulus"
	default:
		return "unknown"
	}
}

func protonRequestStage(request *http.Request) protonAuthStage {
	switch request.Method + " " + request.URL.Path {
	case "POST /api/auth/v4/info":
		return protonStageAuthInfo
	case "POST /api/auth/v4":
		return protonStageAuth
	case "POST /api/auth/v4/2fa":
		return protonStageTOTP
	case "GET /api/core/v4/users":
		return protonStageUser
	case "POST /api/auth/v4/refresh":
		return protonStageRefresh
	case "GET /api/auth/v4/modulus":
		return protonStageModulus
	default:
		return protonStageUnknown
	}
}

// An operation-local trace captures only the last allowlisted request stage and
// numeric status. It never reads a body or retains a request, response, or error.
// Context scoping prevents concurrent/earlier authentication leaking its state.
type protonAuthTrace struct {
	mu     sync.Mutex
	stage  protonAuthStage
	status int
}

type protonAuthTraceKey struct{}

func protonAuthContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, protonAuthTraceKey{}, new(protonAuthTrace))
}

func recordProtonAuthResponse(request *http.Request, status int) {
	if trace, ok := request.Context().Value(protonAuthTraceKey{}).(*protonAuthTrace); ok {
		trace.mu.Lock()
		defer trace.mu.Unlock()
		trace.stage = protonRequestStage(request)
		trace.status = safeProtonHTTPStatus(status)
	}
}

func safeProtonHTTPStatus(status int) int {
	if status >= 100 && status <= 599 {
		return status
	}
	return 0
}

// This error has no underlying cause/Unwrap: even verbose formatting cannot
// expose an SDK error's URL, response body, credentials, or verification token.
type protonAuthError struct {
	stage      protonAuthStage
	httpStatus int
	apiCode    proton.Code
}

func (e *protonAuthError) Error() string {
	message := "Proton authentication failed; check account access and credentials, then retry manually"
	switch e.apiCode {
	case proton.HumanVerificationRequired:
		message = "Proton requires human verification, which may include email verification; this integration cannot complete that challenge"
	case proton.PaidPlanRequired:
		message = "Proton rejected this account's API access; no paid-account workaround is enabled"
	case protonAppVersionInvalidCode, protonAppVersionFormatCode:
		message = "invalid Proton application-version configuration; Proton rejected the platform/product/version identity in PROTON_APP_VERSION; see docs/proton.md"
	case proton.AppVersionBadCode, proton.AppVersionMissingCode:
		message = "Proton rejected the application-version configuration; see docs/proton.md for integration identity requirements"
	}
	return fmt.Sprintf("%s (stage=%s http_status=%d api_code=%d)", message, e.stage, e.httpStatus, e.apiCode)
}

func protonLoginError(ctx context.Context, stage protonAuthStage, err error) *protonAuthError {
	diagnostic := &protonAuthError{stage: stage}
	if trace, ok := ctx.Value(protonAuthTraceKey{}).(*protonAuthTrace); ok {
		trace.mu.Lock()
		if trace.stage != protonStageUnknown {
			diagnostic.stage = trace.stage
		}
		diagnostic.httpStatus = trace.status
		trace.mu.Unlock()
	}
	var apiErr *proton.APIError
	if errors.As(err, &apiErr) {
		if status := safeProtonHTTPStatus(apiErr.Status); status != 0 {
			diagnostic.httpStatus = status
		}
		if apiErr.Code > 0 {
			diagnostic.apiCode = apiErr.Code
		}
	}
	return diagnostic
}

func protonAppVersionError(err error) bool {
	var apiErr *proton.APIError
	return errors.As(err, &apiErr) && (apiErr.Code == protonAppVersionInvalidCode || apiErr.Code == protonAppVersionFormatCode || apiErr.Code == proton.AppVersionBadCode || apiErr.Code == proton.AppVersionMissingCode)
}
