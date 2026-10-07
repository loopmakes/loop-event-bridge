package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
)

// ProtonAuthRequiredError is safe to expose in source status. It deliberately
// carries no provider response, username, credential, path, or underlying error.
type ProtonAuthRequiredError struct {
	diagnostic *protonAuthError
}

func (e *ProtonAuthRequiredError) Error() string {
	if e.diagnostic != nil {
		return e.diagnostic.Error()
	}
	return "Proton authentication requires operator action; check bootstrap credentials or run proton-auth"
}

func protonUsernameHash(username string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username))))
	return hex.EncodeToString(sum[:])
}
func protonCredential(value, path string) ([]byte, error) {
	if path != "" {
		raw, err := protonReadPrivate(path, 4096)
		if err != nil {
			return nil, &ProtonAuthRequiredError{}
		}
		// Secret files commonly end in a newline; preserve other password whitespace.
		raw = bytes.TrimRight(raw, "\r\n")
		if len(raw) == 0 {
			return nil, &ProtonAuthRequiredError{}
		}
		return raw, nil
	}
	if value == "" || len(value) > 4096 {
		return nil, &ProtonAuthRequiredError{}
	}
	return []byte(value), nil
}
func protonCheckConfiguredUsername(c ProtonConfig, saved protonSavedSession) error {
	if c.Username == "" && c.UsernameFile == "" {
		return nil
	}
	username, err := protonCredential(c.Username, c.UsernameFile)
	if err != nil {
		return err
	}
	defer clear(username)
	if protonUsernameHash(string(username)) != saved.LoginHash {
		return errors.New("Proton configured username does not match saved session")
	}
	return nil
}
func protonSessionRefreshError(ctx context.Context, err error) error {
	var apiErr *proton.APIError
	if protonAppVersionError(err) || (errors.As(err, &apiErr) && (apiErr.Code == proton.AuthRefreshTokenInvalid || apiErr.Code == proton.HumanVerificationRequired || apiErr.Code == proton.PaidPlanRequired || apiErr.Status == 400 || apiErr.Status == 401 || apiErr.Status == 422)) {
		return &ProtonAuthRequiredError{diagnostic: protonLoginError(ctx, protonStageRefresh, err)}
	}
	return protonLoginError(ctx, protonStageRefresh, err)
}

func (a *ProtonAdapter) bootstrap(ctx context.Context) error {
	if a.bootstrapAttempted {
		return &ProtonAuthRequiredError{}
	}
	a.bootstrapAttempted = true
	defer func() { a.config.Password = "" }()
	// Bootstrap is only for a genuinely absent session. Never replace a corrupt,
	// mismatched, or newly appeared file with a password login.
	if _, err := os.Lstat(a.config.SessionFile); !errors.Is(err, os.ErrNotExist) {
		return &ProtonAuthRequiredError{}
	}
	username, err := protonCredential(a.config.Username, a.config.UsernameFile)
	if err != nil {
		return err
	}
	defer clear(username)
	password, err := protonCredential(a.config.Password, a.config.PasswordFile)
	if err != nil {
		return err
	}
	defer clear(password)
	if a.login == nil {
		a.login = a.manager.NewClientWithLogin
	}
	loginCtx := protonAuthContext(ctx)
	client, auth, err := a.login(loginCtx, strings.TrimSpace(string(username)), password)
	clear(password)
	if err != nil {
		return &ProtonAuthRequiredError{diagnostic: protonLoginError(loginCtx, protonStageLogin, err)}
	}
	success := false
	defer func() {
		if !success {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = client.AuthDelete(cleanup)
			client.Close()
		}
	}()
	if auth.TwoFA.Enabled != 0 {
		return &ProtonAuthRequiredError{}
	}
	var authMu sync.Mutex
	saved := protonSavedSession{AccountID: auth.UserID, UID: auth.UID, RefreshToken: auth.RefreshToken, LoginHash: protonUsernameHash(string(username))}
	persist := false
	invalidIdentity := false
	client.AddAuthHandler(func(next proton.Auth) {
		authMu.Lock()
		defer authMu.Unlock()
		if (next.UID != "" && next.UID != saved.UID) || (next.UserID != "" && saved.AccountID != "" && next.UserID != saved.AccountID) {
			invalidIdentity = true
			if persist {
				_ = a.session.save(protonSavedSession{})
			}
			return
		}
		saved.RefreshToken = next.RefreshToken
		if persist {
			_ = a.session.save(saved)
		}
	})
	userCtx := protonAuthContext(ctx)
	user, err := client.GetUser(userCtx)
	if err != nil {
		return &ProtonAuthRequiredError{diagnostic: protonLoginError(userCtx, protonStageUser, err)}
	}
	if !validProtonID(user.ID) || (a.config.AccountID != "" && user.ID != a.config.AccountID) || (auth.UserID != "" && auth.UserID != user.ID) {
		return &ProtonAuthRequiredError{}
	}
	authMu.Lock()
	if invalidIdentity {
		authMu.Unlock()
		return &ProtonAuthRequiredError{}
	}
	saved.AccountID = user.ID
	err = a.session.save(saved)
	if err == nil {
		persist = true
	}
	authMu.Unlock()
	if err != nil {
		return err
	}
	a.client = client
	a.mailbox = client
	a.accountID = user.ID
	a.bootstrapPending = false
	success = true
	return nil
}
