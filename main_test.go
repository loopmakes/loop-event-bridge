package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEventDebugLog(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
		valid bool
	}{
		{"", false, true}, {"false", false, true}, {"0", false, true},
		{"true", true, true}, {"1", true, true},
		{"TRUE", false, false}, {"False", false, false}, {"t", false, false},
		{"yes", false, false}, {"on", false, false}, {"2", false, false},
		{" true", false, false}, {"true ", false, false}, {"\tfalse", false, false},
		{"true\n", false, false}, {"synthetic-secret-value", false, false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("EVENT_DEBUG_LOG", tc.value)
			got, err := loadEventDebugLog()
			if got != tc.want || (err == nil) != tc.valid {
				t.Fatalf("unexpected boolean or validity: %v %v", got, err)
			}
			if err != nil && err.Error() != "EVENT_DEBUG_LOG must be true, false, 1, or 0" {
				t.Fatal("configuration error must not include the environment value")
			}
		})
	}
}

func TestLoadGitHubToken(t *testing.T) {
	// All values are synthetic, deliberately not GitHub token-shaped credentials.
	for _, tc := range []struct {
		name, env, file, want, wantErr string
		configured, missing            bool
	}{
		{name: "unset"},
		{name: "environment fallback", env: "synthetic-env", want: "synthetic-env"},
		{name: "trim environment", env: " \t\nsynthetic-env\r\n ", want: "synthetic-env"},
		{name: "blank environment", env: " \t\r\n"},
		{name: "file only", configured: true, file: "synthetic-file", want: "synthetic-file"},
		{name: "file precedence and trimming", configured: true, env: "synthetic-env", file: " \t\nsynthetic-file\r\n ", want: "synthetic-file"},
		{name: "file ignores invalid environment", configured: true, env: "invalid\nvalue", file: "synthetic-file", want: "synthetic-file"},
		{name: "missing file never falls back", configured: true, missing: true, env: "synthetic-env", wantErr: "GITHUB_TOKEN_FILE could not be read"},
		{name: "empty file never falls back", configured: true, env: "synthetic-env", wantErr: "GITHUB_TOKEN_FILE must contain a non-empty token"},
		{name: "blank file never falls back", configured: true, env: "synthetic-env", file: " \t\r\n", wantErr: "GITHUB_TOKEN_FILE must contain a non-empty token"},
		{name: "malformed file never falls back", configured: true, env: "synthetic-env", file: "synthetic\nfile", wantErr: "GITHUB_TOKEN_FILE must contain a single ASCII token without whitespace or control characters"},
		{name: "file control character", configured: true, env: "synthetic-env", file: "synthetic\x00file", wantErr: "GITHUB_TOKEN_FILE must contain a single ASCII token without whitespace or control characters"},
		{name: "environment internal space", env: "synthetic env", wantErr: "GITHUB_TOKEN must contain a single ASCII token without whitespace or control characters"},
		{name: "environment control character", env: "synthetic\x7fenv", wantErr: "GITHUB_TOKEN must contain a single ASCII token without whitespace or control characters"},
		{name: "environment non-ASCII", env: "synthetic-\u00e9", wantErr: "GITHUB_TOKEN must contain a single ASCII token without whitespace or control characters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", tc.env)
			t.Setenv("GITHUB_TOKEN_FILE", "")
			if tc.configured {
				path := filepath.Join(t.TempDir(), "synthetic-token-file")
				if !tc.missing {
					if err := os.WriteFile(path, []byte(tc.file), 0600); err != nil {
						t.Fatal("could not create synthetic token file")
					}
				}
				t.Setenv("GITHUB_TOKEN_FILE", path)
			}
			got, err := loadGitHubToken()
			if got != tc.want {
				t.Error("unexpected token selection or trimming")
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Error("unexpected token configuration error")
				}
			} else if err == nil || err.Error() != tc.wantErr {
				// Exact comparison also ensures paths and token values stay out of errors.
				t.Error("expected sanitized token configuration error")
			}
		})
	}
}
