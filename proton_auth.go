package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
	"golang.org/x/term"
)

// RunProtonAuth is an operator-only command. It is intentionally inaccessible
// through HTTP/MCP, and rejects pipes. This command prompts for credentials
// without echo rather than consuming bootstrap environment variables. The operator runs it on the
// server with its session volume and key secret mounted, while polling is stopped.
func RunProtonAuth(ctx context.Context, c ProtonConfig, in *os.File, out io.Writer) error {
	if err := validateProtonConfig(c, false); err != nil {
		return err
	}
	if in == nil || !term.IsTerminal(int(in.Fd())) {
		return errors.New("proton-auth requires an interactive terminal; passwords cannot be piped")
	}
	terminalOut, ok := out.(*os.File)
	if !ok || terminalOut == nil || !term.IsTerminal(int(terminalOut.Fd())) {
		return errors.New("proton-auth requires terminal output; private verification links cannot be redirected")
	}
	manager, _ := newProtonManager(c.AppVersion, nil)
	defer manager.Close()
	return runProtonInteractiveAuth(ctx, c, out, func(prompt string) ([]byte, error) {
		return protonTerminalSecret(in, out, prompt)
	}, manager)
}

type protonAuthPrompt func(string) ([]byte, error)

// Keeping the SDK boundary injectable lets synthetic tests verify failure and
// cancellation without a terminal, live credentials, or changes to SDK proofs.
func runProtonInteractiveAuth(ctx context.Context, c ProtonConfig, out io.Writer, prompt protonAuthPrompt, manager protonInteractiveManager) error {
	session, err := openProtonSessionStore(c.SessionFile, c.SessionKeyFile)
	if err != nil {
		return err
	}
	defer session.close()
	// Do not overwrite bridge state, OAuth state, corrupt ciphertext, or another
	// account merely because an operator supplied the wrong path.
	if _, err := os.Lstat(c.SessionFile); err == nil {
		existing, loadErr := session.load()
		if loadErr != nil {
			return errors.New("existing Proton session cannot be verified; preserve it and correct the path or deliberately move it aside before authentication")
		}
		if c.AccountID != "" && c.AccountID != existing.AccountID {
			return errors.New("existing Proton session does not match configured account")
		}
		c.AccountID = existing.AccountID
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("Proton session target unavailable")
	}
	username, err := readProtonAuthInput(ctx, prompt, "Proton username (hidden): ")
	if err != nil {
		return err
	}
	defer clear(username)
	password, err := readProtonAuthInput(ctx, prompt, "Proton password (hidden): ")
	if err != nil {
		return err
	}
	defer clear(password)
	client, auth, err := protonInteractiveLogin(ctx, manager, strings.TrimSpace(string(username)), password, prompt, out)
	clear(password)
	if err != nil {
		return err
	}
	defer client.Close()
	var authMu sync.Mutex
	current := protonSavedSession{AccountID: auth.UserID, UID: auth.UID, RefreshToken: auth.RefreshToken}
	identityChanged := false
	client.AddAuthHandler(func(next proton.Auth) {
		authMu.Lock()
		defer authMu.Unlock()
		if (next.UID != "" && next.UID != current.UID) || (next.UserID != "" && current.AccountID != "" && next.UserID != current.AccountID) {
			identityChanged = true
			return
		}
		current.RefreshToken = next.RefreshToken
	})
	success := false
	defer func() {
		if !success {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = client.AuthDelete(cleanup)
		}
	}()
	switch auth.TwoFA.Enabled {
	case 0:
	case proton.HasTOTP, proton.HasFIDO2AndTOTP:
		code, err := readProtonAuthInput(ctx, prompt, "Proton TOTP code (hidden): ")
		if err != nil {
			return err
		}
		requestCtx, cancel := context.WithTimeout(protonAuthContext(ctx), time.Minute)
		err = client.Auth2FA(requestCtx, proton.Auth2FAReq{TwoFactorCode: string(code)})
		cancel()
		clear(code)
		if err != nil {
			return protonLoginError(requestCtx, protonStageTOTP, err)
		}
	default:
		return errors.New("this Proton account requires an authentication method this CLI does not support; FIDO2-only login is unavailable")
	}
	requestCtx, cancel := context.WithTimeout(protonAuthContext(ctx), time.Minute)
	user, err := client.GetUser(requestCtx)
	cancel()
	if err != nil {
		return protonLoginError(requestCtx, protonStageUser, err)
	}
	if !validProtonID(user.ID) || (c.AccountID != "" && user.ID != c.AccountID) {
		return errors.New("Proton account does not match configured account ID")
	}
	// PasswordMode is deliberately irrelevant: this source never unlocks mailbox
	// keys, decrypts messages, or requests the second/mailbox password.
	authMu.Lock()
	saved := current
	changed := identityChanged
	authMu.Unlock()
	if changed || (saved.AccountID != "" && saved.AccountID != user.ID) {
		return errors.New("Proton session identity changed during authentication")
	}
	saved.AccountID = user.ID
	saved.LoginHash = protonUsernameHash(string(username))
	if ctx.Err() != nil {
		return errors.New("Proton interactive authentication cancelled; session not saved")
	}
	if err = session.save(saved); err != nil {
		return err
	}
	success = true
	_, err = fmt.Fprintf(out, "Encrypted Proton session saved. Optional account pin: PROTON_ACCOUNT_ID=%s.\n", user.ID)
	if err != nil {
		return errors.New("Proton session saved but terminal output failed")
	}
	return nil
}

func readProtonAuthInput(ctx context.Context, prompt protonAuthPrompt, label string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, errors.New("Proton interactive authentication cancelled")
	}
	value, err := prompt(label)
	if ctx.Err() != nil || err != nil || len(value) == 0 || len(value) > 4096 {
		clear(value)
		return nil, errors.New("Proton interactive authentication cancelled or input unavailable")
	}
	return value, nil
}
func protonTerminalSecret(in *os.File, out io.Writer, prompt string) ([]byte, error) {
	if _, err := fmt.Fprint(out, prompt); err != nil {
		return nil, errors.New("Proton terminal unavailable")
	}
	value, err := term.ReadPassword(int(in.Fd()))
	_, _ = fmt.Fprintln(out)
	if err != nil || len(value) > 4096 {
		clear(value)
		return nil, errors.New("Proton interactive input unavailable or invalid")
	}
	return value, nil
}
