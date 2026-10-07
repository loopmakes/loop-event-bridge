package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func sourceEnabled(name string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name + "_ENABLED")))
	if value == "" {
		return fallback
	}
	// Invalid values enable a failed adapter rather than silently hiding it.
	return value != "false" && value != "0"
}
func sourceToggleValid(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name + "_ENABLED"))) {
	case "", "true", "false", "1", "0":
		return true
	}
	return false
}
func loadSourceToken(name string) (string, error) {
	token := os.Getenv(name + "_TOKEN")
	if file := os.Getenv(name + "_TOKEN_FILE"); file != "" {
		raw, err := readSourceTokenFile(file)
		if err != nil {
			return "", errors.New("source token file unavailable")
		}
		token = string(raw)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("source token missing")
	}
	for _, ch := range token {
		if ch <= ' ' || ch >= 127 {
			return "", errors.New("source token invalid")
		}
	}
	return token, nil
}
func protonEnvironment() ProtonConfig {
	return ProtonConfig{
		SessionFile:    env("PROTON_SESSION_FILE", "/data/proton-session.json"),
		SessionKeyFile: os.Getenv("PROTON_SESSION_KEY_FILE"),
		AccountID:      os.Getenv("PROTON_ACCOUNT_ID"),
		AppVersion:     os.Getenv("PROTON_APP_VERSION"),
		Username:       os.Getenv("PROTON_USERNAME"),
		Password:       os.Getenv("PROTON_PASSWORD"),
		UsernameFile:   os.Getenv("PROTON_USERNAME_FILE"),
		PasswordFile:   os.Getenv("PROTON_PASSWORD_FILE"),
	}
}
func configuredSources() []sourceConfig {
	sources := []sourceConfig{}
	if sourceEnabled("GITLAB", false) {
		origin := strings.TrimSuffix(env("GITLAB_URL", "https://gitlab.com"), "/")
		account := strings.TrimSpace(os.Getenv("GITLAB_ACCOUNT"))
		parsed, parseErr := gitlabOrigin(origin, false)
		if parseErr == nil {
			origin = parsed.String()
		}
		source := sourceConfig{Name: "gitlab", Namespace: "gitlab/" + digest(origin+"\x00"+strings.ToLower(account)), EventName: "gitlab.todo.changed"}
		token, err := loadSourceToken("GITLAB")
		if err != nil || parseErr != nil || account == "" || !sourceToggleValid("GITLAB") {
			source.InitError = true
		} else {
			source.Adapter = &gitlabAdapter{client: &http.Client{Timeout: 30 * time.Second}, origin: origin, token: token, account: account}
		}
		sources = append(sources, source)
	}
	if sourceEnabled("PROTON", false) {
		config := protonEnvironment()
		source := sourceConfig{Name: "proton", Namespace: "proton", EventName: "proton.mail.received"}
		if !sourceToggleValid("PROTON") || protonStoragePathsSafe(config) != nil {
			source.InitError = true
		} else {
			adapter, err := NewProtonAdapter(config)
			if err != nil {
				source.InitError = true
				var appVersionConfig *protonAppVersionConfigError
				if errors.As(err, &appVersionConfig) {
					source.InitDiagnostic = sourceInitProtonAppVersion
				}
			} else {
				source.Adapter = adapter
			}
		}
		sources = append(sources, source)
	}
	return sources
}

// Reject aliases before creating a session or lock, including a fresh shared
// state file that does not exist yet. Resolve existing parent symlinks, and use
// SameFile for existing hard links. No file contents are read here.
func canonicalStoragePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return resolveStoragePath(absolute)
}
func resolveStoragePath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	resolved, err = resolveStoragePath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}
func protonStoragePathsSafe(config ProtonConfig) error {
	paths := []string{config.SessionFile, config.SessionKeyFile, config.SessionFile + ".lock", env("STATE_FILE", "/data/state.json"), env("OAUTH_STATE_FILE", "/data/oauth.json"), os.Getenv("OWNER_PASSWORD_FILE")}
	canonical := make([]string, len(paths))
	for i, path := range paths {
		if path == "" {
			continue
		}
		value, err := canonicalStoragePath(path)
		if err != nil {
			return errors.New("Proton storage paths could not be validated")
		}
		canonical[i] = value
	}
	for i := 0; i < 3; i++ {
		if canonical[i] == "" {
			continue
		}
		for j := i + 1; j < len(paths); j++ {
			if canonical[j] == "" {
				continue
			}
			same := canonical[i] == canonical[j]
			left, errLeft := os.Stat(paths[i])
			right, errRight := os.Stat(paths[j])
			if errLeft == nil && errRight == nil && os.SameFile(left, right) {
				same = true
			}
			if same {
				return errors.New("Proton session, lock, and key must use separate paths from bridge state and credentials")
			}
		}
	}
	return nil
}

// Nonblocking open prevents a misconfigured FIFO/device from hanging startup.
// Existing token symlinks remain supported, but their target must be regular.
func readSourceTokenFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("source token file unavailable")
	}
	file := os.NewFile(uintptr(fd), "source-token")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("source token file must be regular")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errors.New("source token file unreadable or oversized")
	}
	return raw, nil
}
