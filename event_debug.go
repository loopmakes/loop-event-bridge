package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// The bound covers the message, excluding the standard logger's timestamp/prefix.
const eventDebugMaxBytes = 8 << 10

type eventDebugEnvelope struct {
	ID        string          `json:"eventId"`
	Name      string          `json:"name"`
	Timestamp string          `json:"timestamp,omitempty"`
	Data      map[string]any  `json:"data"`
	Cursor    json.RawMessage `json:"cursor,omitempty"`
}

type eventDebugRecord struct {
	EventID        string          `json:"event_id"`
	EventName      string          `json:"event_name"`
	Source         string          `json:"source"`
	Subscription   string          `json:"subscription_ref"`
	OmittedFields  int             `json:"omitted_data_fields"`
	OmittedCursor  bool            `json:"cursor_omitted,omitempty"`
	SanitizedBytes int             `json:"sanitized_bytes"`
	Truncated      bool            `json:"truncated"`
	SanitizedHash  string          `json:"sanitized_sha256,omitempty"`
	Event          json.RawMessage `json:"event,omitempty"`
	Excerpt        string          `json:"sanitized_excerpt,omitempty"`
}

// This is an explicit list of the primitive metadata emitted by the current
// adapters, including their documented additional properties. It is deliberately
// independent of arbitrary keys or objects in imported state. Cursor, credentials,
// callback settings, signatures and HTTP response bodies are never inspected.
func eventDebugData(event Event) (map[string]any, int) {
	var stringsAllowed, urlsAllowed []string
	switch event.Name {
	case "bridge.test":
		stringsAllowed = []string{"message"}
	case "github.notification.changed":
		stringsAllowed = []string{"kind", "account_login", "account_id", "notification_id", "repository", "subject_type", "title", "reason", "updated_at", "last_read_at"}
		urlsAllowed = []string{"api_url", "subject_api_url", "latest_comment_api_url", "url"}
	case "gitlab.todo.changed":
		stringsAllowed = []string{"kind", "account_id", "todo_id", "account_username", "project", "target_type", "title", "action", "state", "created_at", "updated_at"}
		urlsAllowed = []string{"instance_url", "url"}
	case "proton.mail.received":
		stringsAllowed = []string{"message_id", "received_at"}
	}
	data := make(map[string]any)
	for _, key := range stringsAllowed {
		if value, ok := event.Data[key].(string); ok {
			data[key] = eventDebugText(value)
		}
	}
	for _, key := range urlsAllowed {
		if value, ok := event.Data[key].(string); ok {
			if safe, ok := eventDebugURL(value); ok {
				data[key] = safe
			}
		}
	}
	if event.Name == "github.notification.changed" {
		if value, ok := event.Data["unread"].(bool); ok {
			data["unread"] = value
		}
		if value, ok := event.Data["last_read_at"]; ok && value == nil {
			data["last_read_at"] = nil
		}
	}
	return data, len(event.Data) - len(data)
}

// Free text remains actual user content. Omit common URL-like spans altogether,
// including their paths: merely stripping a query would not remove callback or
// reset tokens embedded in a path. This is NOT a general-purpose secret scrubber;
// prose, identifiers and metadata URL paths may still contain sensitive content.
var eventDebugTextURL = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*://|www\.|mailto:|data:|javascript:)[^\s<>"']*`)

func eventDebugText(value string) string {
	return eventDebugTextURL.ReplaceAllString(value, "[URL omitted]")
}

// Only HTTP(S) metadata URLs are useful here. Preserve their host/path, but strip
// user information, query and fragment. Reject malformed URLs and raw/decoded
// control characters rather than logging the parsing error (which includes input).
func eventDebugURL(raw string) (string, bool) {
	if !utf8.ValidString(raw) || strings.Contains(raw, "\\") || strings.ContainsFunc(raw, func(r rune) bool { return eventDebugControl(r) || unicode.IsSpace(r) }) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || strings.ContainsFunc(u.Path, func(r rune) bool { return eventDebugControl(r) || r == '\\' }) {
		return "", false
	}
	u.User = nil
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	u.ForceQuery = false
	return u.String(), true
}

func (b *Bridge) logEventDebug(event Event, subscriptionID string) {
	if !b.eventDebug {
		return
	}
	name, source := eventLogLabels(event.Name)
	data, omitted := eventDebugData(event)
	envelope := eventDebugEnvelope{ID: eventLogID(event.ID), Name: name, Data: data}
	if event.Cursor == nil {
		envelope.Cursor = json.RawMessage("null")
	}
	// Use UTC to avoid arbitrary location names. Invalid times are omitted.
	if stamp, err := event.Timestamp.UTC().MarshalText(); err == nil {
		envelope.Timestamp = string(stamp)
	}
	sanitized := eventDebugJSON(envelope) // only plain strings, bools and nil
	record := eventDebugRecord{
		EventID: envelope.ID, EventName: name, Source: source,
		Subscription: subscriptionLogRef(subscriptionID), OmittedFields: omitted,
		OmittedCursor:  event.Cursor != nil,
		SanitizedBytes: len(sanitized), Event: sanitized,
	}
	const prefix = "event debug "
	const budget = eventDebugMaxBytes - len(prefix)
	encoded := eventDebugJSON(record)
	if len(encoded) > budget {
		record.Event = nil
		record.Truncated = true
		// Hash only the allowlisted, sanitized envelope, never the raw event.
		record.SanitizedHash = digest(string(sanitized))
		// The excerpt is a JSON string, not an incomplete raw JSON object. Find
		// the largest prefix which still fits after JSON re-escaping it.
		low, high := 0, min(len(sanitized), budget)
		for low < high {
			mid := low + (high-low+1)/2
			record.Excerpt = eventDebugUTF8Prefix(sanitized, mid)
			candidate := eventDebugJSON(record)
			if len(candidate) <= budget {
				low = mid
			} else {
				high = mid - 1
			}
		}
		record.Excerpt = eventDebugUTF8Prefix(sanitized, low)
		encoded = eventDebugJSON(record)
	}
	log.Print(prefix + string(encoded))
}

// encoding/json escapes ASCII controls and line separators, but leaves C1
// controls and formatting controls (for example bidirectional overrides) intact.
// Escape those too so logs remain single-line and cannot alter terminal layout.
func eventDebugJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	var safe strings.Builder
	for _, r := range string(encoded) {
		if eventDebugControl(r) {
			if r > 0xffff {
				high, low := utf16.EncodeRune(r)
				fmt.Fprintf(&safe, "\\u%04x\\u%04x", high, low)
			} else {
				fmt.Fprintf(&safe, "\\u%04x", r)
			}
		} else {
			safe.WriteRune(r)
		}
	}
	return []byte(safe.String())
}

func eventDebugControl(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }

func eventDebugUTF8Prefix(value []byte, limit int) string {
	for limit > 0 && limit < len(value) && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return string(value[:limit])
}
