package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Bridge struct {
	authorizedOwner           func(string) bool
	store                     *Store
	auth                      func(*http.Request) (string, error)
	callbacks                 *http.Client
	hosts                     map[string]bool
	account, resource, issuer string
	verifyMu                  sync.Mutex
	verified                  map[string]time.Time
}
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}
type subscriptionRequest struct {
	Name      string          `json:"name"`
	Arguments Arguments       `json:"arguments"`
	Delivery  Delivery        `json:"delivery"`
	TTL       json.RawMessage `json:"ttlMs"`
	Cursor    json.RawMessage `json:"cursor"`
	Meta      json.RawMessage `json:"_meta"`
}
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func decode(raw []byte, v any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/.well-known/oauth-protected-resource" && r.Method == "GET" {
		writeJSON(w, map[string]any{"resource": b.resource, "authorization_servers": []string{b.issuer}, "scopes_supported": []string{"events:read"}})
		return
	}
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != b.resource {
		http.Error(w, "origin denied", 403)
		return
	}
	owner, e := b.auth(r)
	if e != nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource", scope="events:read"`, b.resource))
		http.Error(w, "authentication required", 401)
		return
	}
	if media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || media != "application/json" {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 32768))
	if e != nil {
		http.Error(w, "request too large", 413)
		return
	}
	var q rpcRequest
	if decode(raw, &q) != nil || q.JSONRPC != "2.0" || !validRPCID(q.ID) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": nil, "error": rpcError{-32600, "Invalid Request", nil}})
		return
	}
	if status, transportErr := validateTransport(r, &q); transportErr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": transportErr})
		return
	}
	result, rpcErr := b.call(r.Context(), owner, q.Method, q.Params)
	out := map[string]any{"jsonrpc": "2.0", "id": q.ID}
	if rpcErr != nil {
		out["error"] = rpcErr
		if rpcErr.Code == -32601 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
		}
	} else {
		if m, ok := result.(map[string]any); ok {
			m["resultType"] = "complete"
		}
		out["result"] = result
	}
	writeJSON(w, out)
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func objectSchema(props map[string]any, required []string) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}
func (b *Bridge) eventDefinitions() []any {
	str := map[string]any{"type": "string"}
	input := objectSchema(map[string]any{}, []string{})
	return []any{
		map[string]any{"name": "bridge.test", "description": "Operator-triggered connectivity test; no GitHub changes.", "delivery": []string{"webhook"}, "inputSchema": input, "payloadSchema": objectSchema(map[string]any{"message": str}, []string{"message"})},
		map[string]any{"name": "github.notification.changed", "description": "A new or updated notification in the configured GitHub account's complete Notifications inbox. Covers all repositories, subject types and reasons without marking anything read. This is the account's subscribed/participating inbox, not every GitHub event. Snapshot polling may coalesce changes; no historical replay.", "delivery": []string{"webhook"}, "inputSchema": input, "payloadSchema": map[string]any{"type": "object", "properties": map[string]any{"account_login": str, "account_id": str, "notification_id": str, "repository": str, "subject_type": str, "title": str, "reason": str, "unread": map[string]any{"type": "boolean"}, "updated_at": str, "api_url": str}, "required": []string{"account_login", "account_id", "notification_id", "repository", "subject_type", "title", "reason", "unread", "updated_at", "api_url"}, "additionalProperties": true}},
	}
}

func (b *Bridge) call(ctx context.Context, owner, method string, raw json.RawMessage) (any, *rpcError) {
	bad := func(msg string) (any, *rpcError) { return nil, &rpcError{-32602, msg, nil} }
	switch method {
	case "server/discover":
		return map[string]any{"supportedVersions": []string{"2026-07-28"}, "capabilities": map[string]any{"events": map[string]any{}, "tools": map[string]any{}}, "_meta": map[string]any{"io.modelcontextprotocol/serverInfo": map[string]string{"name": "loop-event-bridge", "version": "0.1.0"}}}, nil
	case "events/list":
		return map[string]any{"events": b.eventDefinitions()}, nil
	case "tools/list":
		return map[string]any{"tools": []any{map[string]any{"name": "bridge_status", "description": "Read bridge polling and delivery health. Never returns secrets or callback URLs.", "inputSchema": objectSchema(map[string]any{}, []string{}), "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false}, "securitySchemes": []any{map[string]any{"type": "oauth2", "scopes": []string{"events:read"}}}}}, "ttlMs": 60000, "cacheScope": "private"}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments map[string]any  `json:"arguments"`
			Meta      json.RawMessage `json:"_meta"`
		}
		if decode(raw, &p) != nil || p.Name != "bridge_status" || len(p.Arguments) != 0 {
			return bad("unknown tool or arguments")
		}
		b.store.mu.Lock()
		dead := 0
		for _, p := range b.store.state.Queue {
			if p.Dead {
				dead++
			}
		}
		status := map[string]any{"deadLetters": dead, "subscriptions": len(b.store.state.Subscriptions), "queued": len(b.store.state.Queue), "lastPoll": b.store.state.LastPoll, "lastError": b.store.state.LastError, "experimental": true, "githubAccount": b.account}
		b.store.mu.Unlock()
		data, _ := json.Marshal(status)
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(data)}}, "isError": false}, nil
	case "events/subscribe", "events/unsubscribe":
		var p subscriptionRequest
		if decode(raw, &p) != nil {
			return bad("invalid subscription parameters")
		}
		if (p.Name != "bridge.test" && p.Name != "github.notification.changed") || p.Delivery.Mode != "webhook" {
			return bad("event is not supported or delivery mode is invalid")
		}
		if validCallback(p.Delivery.URL, b.hosts) != nil {
			u, _ := url.Parse(p.Delivery.URL)
			host := ""
			if u != nil {
				host = u.Hostname()
			}
			if method == "events/subscribe" {
				// Only the parsed hostname is safe to log; URLs and parse errors may contain secrets.
				log.Printf("events/subscribe callback denied: requestedHost=%q", host)
			}
			return nil, &rpcError{-32602, "callback denied; verify its host and configure CALLBACK_HOSTS", map[string]string{"requestedHost": host}}
		}
		args, _ := json.Marshal(p.Arguments)
		id := "sub_" + digest(owner+"\x00"+p.Delivery.URL+"\x00"+p.Name+"\x00"+string(args))
		if method == "events/unsubscribe" {
			b.store.mu.Lock()
			defer b.store.mu.Unlock()
			next := b.store.copy()
			delete(next.Subscriptions, id)
			queue := next.Queue[:0]
			for _, v := range next.Queue {
				if v.SubscriptionID != id {
					queue = append(queue, v)
				}
			}
			next.Queue = queue
			if b.store.save(next) != nil {
				return nil, &rpcError{-32603, "storage unavailable", nil}
			}
			return map[string]any{}, nil
		}
		if _, e := secretKey(p.Delivery.Secret); e != nil {
			return bad("invalid signing secret")
		}
		ttl := time.Hour
		if len(p.TTL) > 0 && string(p.TTL) != "null" {
			var ms int64
			if json.Unmarshal(p.TTL, &ms) != nil || ms < 1000 {
				return bad("ttlMs must be at least 1000")
			}
			if ms < int64(ttl/time.Millisecond) {
				ttl = time.Duration(ms) * time.Millisecond
			}
		}
		s := Subscription{ID: id, Owner: owner, Name: p.Name, Arguments: p.Arguments, Delivery: p.Delivery, Expires: time.Now().UTC().Add(ttl)}
		b.verifyMu.Lock()
		defer b.verifyMu.Unlock()
		for k, until := range b.verified {
			if !until.After(time.Now()) {
				delete(b.verified, k)
			}
		}
		if len(b.verified) >= 1000 {
			return bad("verification cache capacity reached")
		}
		cacheKey := owner + "\x00" + p.Delivery.URL + "\x00" + digest(p.Delivery.Secret)
		if time.Now().After(b.verified[cacheKey]) {
			if e := verifyCallback(ctx, b.callbacks, s); e != nil {
				return nil, &rpcError{-32015, "CallbackEndpointError", map[string]string{"reason": "challenge_failed"}}
			}
			b.verified[cacheKey] = time.Now().Add(5 * time.Minute)
		}
		b.store.mu.Lock()
		defer b.store.mu.Unlock()
		next := b.store.copy()
		b.pruneState(&next, time.Now())
		if len(next.Subscriptions) >= 100 {
			if _, ok := next.Subscriptions[id]; !ok {
				return bad("subscription capacity reached")
			}
		}
		if old, ok := next.Subscriptions[id]; ok && old.Delivery.Secret != s.Delivery.Secret {
			s.OldSecret = old.Delivery.Secret
			s.RotateUntil = time.Now().Add(5 * time.Minute)
		}
		if old, ok := next.Subscriptions[id]; ok && old.Delivery.Secret == s.Delivery.Secret && old.RotateUntil.After(time.Now()) {
			s.OldSecret = old.OldSecret
			s.RotateUntil = old.RotateUntil
		}
		s.Expires = time.Now().UTC().Add(ttl)
		next.Subscriptions[id] = s
		if b.store.save(next) != nil {
			return nil, &rpcError{-32603, "storage unavailable", nil}
		}
		return map[string]any{"id": id, "refreshBefore": s.Expires, "cursor": nil, "truncated": len(p.Cursor) > 0 && string(p.Cursor) != "null"}, nil
	default:
		return nil, &rpcError{-32601, "Method not found", nil}
	}
}

func validRPCID(raw json.RawMessage) bool {
	var id any
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if d.Decode(&id) != nil {
		return false
	}
	switch id.(type) {
	case string, json.Number:
		return true
	}
	return false
}
