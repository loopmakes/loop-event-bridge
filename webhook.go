package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func secretKey(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "whsec_") {
		return nil, errors.New("invalid signing secret")
	}
	b, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "whsec_"))
	if e != nil || len(b) < 24 || len(b) > 64 {
		return nil, errors.New("invalid signing secret")
	}
	return b, nil
}
func signature(secret, id, stamp string, body []byte) string {
	k, _ := secretKey(secret)
	m := hmac.New(sha256.New, k)
	m.Write([]byte(id + "." + stamp + "."))
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}
func randomID() string {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func digest(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }
func validCallback(raw string, hosts map[string]bool) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") || !hosts[strings.ToLower(u.Hostname())] {
		return errors.New("callback must use an explicitly allowed HTTPS host on port 443")
	}
	return nil
}

// Conservative public-address test also excludes special-use/documentation ranges.
func publicIP(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return false
	}
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10"} {
		if netip.MustParsePrefix(s).Contains(a) {
			return false
		}
	}
	return true
}
func callbackClient() *http.Client {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("callback DNS failed")
		}
		for _, ip := range ips {
			if !publicIP(ip) {
				return nil, errors.New("callback destination is not public")
			}
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}}
	return &http.Client{Timeout: 10 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func postSigned(ctx context.Context, c *http.Client, s Subscription, id string, body []byte) (int, []byte, error) {
	status, response, _, err := postSignedObserved(ctx, c, s, id, body)
	return status, response, err
}

type callbackDiagnostic struct {
	ContentType      string
	ResponseBytes    int
	ResponseComplete bool
	ErrorClass       string
}

// Classify rather than print arbitrary headers (including their parameters),
// error strings or response content, all of which may contain credentials.
func callbackContentType(raw string) string {
	if raw == "" {
		return "none"
	}
	media, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return "invalid"
	}
	switch media {
	case "application/json", "application/problem+json", "text/plain", "text/html":
		return media
	default:
		return "other"
	}
}

// Preserve postSigned's status/body/error semantics, including acknowledgment of
// a 2xx with an unreadable body; the new fields are observational only.
func postSignedObserved(ctx context.Context, c *http.Client, s Subscription, id string, body []byte) (int, []byte, callbackDiagnostic, error) {
	diagnostic := callbackDiagnostic{ContentType: "none", ErrorClass: "none"}
	if _, err := secretKey(s.Delivery.Secret); err != nil {
		diagnostic.ErrorClass = "invalid_signing_secret"
		return 0, nil, diagnostic, err
	}
	if len(body) > 262144 {
		diagnostic.ErrorClass = "payload_too_large"
		return 413, nil, diagnostic, errors.New("payload too large")
	}
	req, e := http.NewRequestWithContext(ctx, "POST", s.Delivery.URL, bytes.NewReader(body))
	if e != nil {
		diagnostic.ErrorClass = "request_invalid"
		return 0, nil, diagnostic, e
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := signature(s.Delivery.Secret, id, stamp, body)
	if s.OldSecret != "" && time.Now().Before(s.RotateUntil) {
		sig += " " + signature(s.OldSecret, id, stamp, body)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", stamp)
	req.Header.Set("webhook-signature", sig)
	req.Header.Set("X-MCP-Subscription-Id", s.ID)
	res, e := c.Do(req)
	if e != nil {
		diagnostic.ErrorClass = "request_failed"
		return 0, nil, diagnostic, errors.New("callback request failed")
	}
	defer res.Body.Close()
	diagnostic.ContentType = callbackContentType(res.Header.Get("Content-Type"))
	b, e := io.ReadAll(io.LimitReader(res.Body, 8193))
	diagnostic.ResponseBytes = len(b)
	if e != nil || len(b) > 8192 {
		diagnostic.ErrorClass = "response_invalid"
		return res.StatusCode, nil, diagnostic, errors.New("callback response invalid")
	}
	diagnostic.ResponseComplete = true
	return res.StatusCode, b, diagnostic, nil
}
func verifyCallback(ctx context.Context, c *http.Client, s Subscription) error {
	challenge := randomID()
	b, _ := json.Marshal(map[string]string{"type": "verification", "challenge": challenge})
	status, raw, e := postSigned(ctx, c, s, "verify_"+randomID(), b)
	if e != nil {
		return e
	}
	var result struct {
		Challenge string `json:"challenge"`
	}
	if status < 200 || status >= 300 || json.Unmarshal(raw, &result) != nil || subtle.ConstantTimeCompare([]byte(challenge), []byte(result.Challenge)) != 1 {
		return fmt.Errorf("challenge_failed")
	}
	return nil
}
