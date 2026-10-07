package main

import (
	"log"
	"sort"
	"strings"
	"time"
)

// Correlation identifiers are not credentials. Only bridge-generated event IDs
// are printed verbatim; malformed/legacy IDs and subscription IDs are hashed so
// imported state cannot inject content or control characters into the log.
func eventLogID(id string) string {
	if len(id) == 52 && strings.HasPrefix(id, "evt_") {
		valid := true
		for _, c := range id[4:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				valid = false
				break
			}
		}
		if valid {
			return id
		}
	}
	return "event_sha256_" + digest(id)[:24]
}

func subscriptionLogRef(id string) string { return "sub_sha256_" + digest(id)[:24] }

func eventLogLabels(name string) (eventName, source string) {
	switch name {
	case "bridge.test":
		return name, "bridge"
	case "github.notification.changed":
		return name, "github"
	case "gitlab.todo.changed":
		return name, "gitlab"
	case "proton.mail.received":
		return name, "proton"
	default:
		return "unknown", "unknown"
	}
}

// Report only schema-defined key names that are actually present. Unknown keys
// can themselves contain private content, so count them instead of printing them.
func eventLogDataFields(event Event) (fields string, other int) {
	var allowed []string
	switch event.Name {
	case "bridge.test":
		allowed = []string{"message"}
	case "github.notification.changed":
		allowed = []string{"account_login", "account_id", "notification_id", "repository", "subject_type", "title", "reason", "unread", "updated_at", "api_url"}
	case "gitlab.todo.changed":
		allowed = []string{"account_id", "todo_id"}
	case "proton.mail.received":
		allowed = []string{"message_id", "received_at"}
	}
	var present []string
	for _, key := range allowed {
		if _, ok := event.Data[key]; ok {
			present = append(present, key)
		}
	}
	sort.Strings(present)
	fields = strings.Join(present, ",")
	if fields == "" {
		fields = "none"
	}
	return fields, len(event.Data) - len(present)
}

// Call only after the outbox and source checkpoint were saved successfully.
func logEnqueuedEvents(entries []Pending) {
	for _, item := range entries {
		name, source := eventLogLabels(item.Event.Name)
		log.Printf("event enqueued event_id=%s event_name=%s source=%s subscription_ref=%s state_saved=true", eventLogID(item.Event.ID), name, source, subscriptionLogRef(item.SubscriptionID))
	}
}

// Discovery has no provider data. Coalesce repeated client probes, but report
// a changed advertised set immediately. Unknown names never enter the log.
func (b *Bridge) logEventDiscovery(definitions []any) {
	set := map[string]bool{}
	for _, definition := range definitions {
		entry, _ := definition.(map[string]any)
		name, _ := entry["name"].(string)
		label, _ := eventLogLabels(name)
		set[label] = true
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	labels := strings.Join(names, ",")
	b.discoveryMu.Lock()
	defer b.discoveryMu.Unlock()
	now := time.Now()
	if labels == b.discoveryNames && now.Sub(b.discoveryLastLog) < time.Minute {
		b.discoverySuppressed++
		return
	}
	log.Printf("event discovery method=events/list event_count=%d event_names=%s suppressed_since_last=%d", len(definitions), labels, b.discoverySuppressed)
	b.discoveryLastLog, b.discoveryNames, b.discoverySuppressed = now, labels, 0
}
