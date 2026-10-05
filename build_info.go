package main

import (
	"runtime/debug"
	"strings"
)

// Release builds supply these via -ldflags; ordinary builds retain honest
// development defaults and use Go's VCS metadata when it is available.
var buildVersion = "dev"
var buildRevision = "unknown"

func buildIdentity() (version, revision string) {
	version, revision = buildVersion, buildRevision
	if info, ok := debug.ReadBuildInfo(); ok && revision == "unknown" {
		dirty := false
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				revision = setting.Value
			}
			if setting.Key == "vcs.modified" {
				dirty = setting.Value == "true"
			}
		}
		if dirty && revision != "unknown" {
			revision += "-dirty"
		}
	}
	return safeBuildLabel(version, "dev"), safeBuildLabel(revision, "unknown")
}

func safeBuildLabel(value, fallback string) string {
	if value == "" || len(value) > 80 || strings.Trim(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-") != "" {
		return fallback
	}
	return value
}
