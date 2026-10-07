package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// loadGitHubToken prefers a configured file and never exposes its path or contents
// in errors. A broken file configuration must not silently select another token.
func loadGitHubToken() (string, error) {
	source := "GITHUB_TOKEN"
	token := os.Getenv(source)
	if file := os.Getenv("GITHUB_TOKEN_FILE"); file != "" {
		source = "GITHUB_TOKEN_FILE"
		raw, err := readSourceTokenFile(file)
		if err != nil {
			return "", errors.New("GITHUB_TOKEN_FILE could not be read")
		}
		token = string(raw)
	}
	token = strings.TrimSpace(token)
	if token == "" && source == "GITHUB_TOKEN_FILE" {
		return "", errors.New("GITHUB_TOKEN_FILE must contain a non-empty token")
	}
	for _, ch := range token {
		if ch <= ' ' || ch >= 127 {
			return "", fmt.Errorf("%s must contain a single ASCII token without whitespace or control characters", source)
		}
	}
	return token, nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "proton-auth":
			config := protonEnvironment()
			if e := protonStoragePathsSafe(config); e != nil {
				log.Fatal(e)
			}
			if e := RunProtonAuth(context.Background(), config, os.Stdin, os.Stdout); e != nil {
				log.Fatal("proton-auth: ", e)
			}
			return
		case "healthcheck":
			r, e := http.Get("http://127.0.0.1:8081/healthz")
			if e != nil {
				os.Exit(1)
			}
			r.Body.Close()
			if r.StatusCode != 200 {
				os.Exit(1)
			}
			return
		case "emit-test":
			c := &http.Client{Timeout: 5 * time.Second}
			r, e := c.Post("http://127.0.0.1:8081/test", "application/json", nil)
			if e != nil {
				log.Fatal("local admin endpoint unavailable")
			}
			defer r.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
			fmt.Print(string(body))
			if r.StatusCode != 202 {
				os.Exit(1)
			}
			return
		default:
			log.Fatal("usage: loop-event-bridge [healthcheck|emit-test|proton-auth]")
		}
	}
	resource := strings.TrimSuffix(os.Getenv("PUBLIC_URL"), "/")
	issuer := resource
	oauth, e := NewEmbeddedOAuth(EmbeddedOAuthConfig{PublicURL: resource, ClientID: os.Getenv("OAUTH_CLIENT_ID"), RedirectURI: os.Getenv("OAUTH_REDIRECT_URI"), OwnerPasswordFile: os.Getenv("OWNER_PASSWORD_FILE"), StateFile: env("OAUTH_STATE_FILE", "/data/oauth.json")})
	if e != nil {
		log.Fatal("OAuth configuration invalid: ", e)
	}
	account := strings.TrimSpace(os.Getenv("GITHUB_ACCOUNT"))
	githubEnabled := sourceEnabled("GITHUB", true)
	if githubEnabled && (account == "" || strings.ContainsAny(account, " /?#") || !sourceToggleValid("GITHUB")) {
		log.Print("GitHub source configuration requires a valid account and enabled flag")
		account = ""
	}
	hosts := map[string]bool{}
	for _, h := range strings.Split(os.Getenv("CALLBACK_HOSTS"), ",") {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			if strings.ContainsAny(h, "/:*@ ") {
				log.Fatal("CALLBACK_HOSTS must contain exact hostnames")
			}
			hosts[h] = true
		}
	}
	if len(hosts) == 0 {
		log.Print("CALLBACK_HOSTS empty: discovery available, subscriptions fail closed until configured")
	}
	st, e := openStore(env("STATE_FILE", "/data/state.json"))
	if e != nil {
		log.Fatal("state could not be loaded; refusing fresh baseline")
	}
	b := &Bridge{store: st, auth: oauth.Authenticate, authorizedOwner: oauth.AuthorizedOwner, callbacks: callbackClient(), hosts: hosts, account: account, resource: resource, issuer: issuer, verified: map[string]time.Time{}}
	b.githubDisabled = !githubEnabled
	b.sources = configuredSources()
	var token string
	if githubEnabled {
		token, e = loadGitHubToken()
		if e != nil {
			log.Print("GitHub token configuration unavailable")
		}
	}
	secs, e := strconv.Atoi(env("POLL_INTERVAL_SECONDS", "300"))
	if e != nil || secs < 60 || secs > 86400 {
		log.Fatal("POLL_INTERVAL_SECONDS must be 60..86400")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	admin := http.NewServeMux()
	admin.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok\n")) })
	admin.HandleFunc("POST /test", func(w http.ResponseWriter, r *http.Request) {
		if e := b.enqueueTest(); e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		w.WriteHeader(202)
		_, _ = w.Write([]byte("test event queued\n"))
	})
	public := http.NewServeMux()
	public.Handle("/oauth/", oauth)
	public.Handle("/.well-known/oauth-authorization-server", oauth)
	public.Handle("/", b)
	servers := []*http.Server{{Addr: ":8080", Handler: public, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}, {Addr: "127.0.0.1:8081", Handler: admin, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}}
	for _, srv := range servers {
		go func(s *http.Server) {
			if e := s.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
				log.Print("HTTP server failed")
				stop()
			}
		}(srv)
	}
	version, revision := buildIdentity()
	log.Printf("experimental event bridge started version=%s revision=%s poll_interval=%s; account integration requires end-to-end verification", version, revision, time.Duration(secs)*time.Second)
	runnerDone := make(chan struct{})
	go func() {
		defer close(runnerDone)
		b.run(ctx, &http.Client{Timeout: 30 * time.Second}, token, time.Duration(secs)*time.Second)
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	select {
	case <-runnerDone:
	case <-shutdown.Done():
		log.Print("source shutdown timeout")
	}
}
