package main

import "testing"

func TestVersionString(t *testing.T) {
	oldVersion := version
	oldCommit := commit
	oldDate := date
	t.Cleanup(func() {
		version = oldVersion
		commit = oldCommit
		date = oldDate
	})

	version = "v1.2.3"
	commit = "abc123"
	date = "2026-05-29T10:00:00Z"

	got := versionString()
	want := "mcp-audit v1.2.3 (commit abc123, built 2026-05-29T10:00:00Z)"
	if got != want {
		t.Fatalf("version string = %q, want %q", got, want)
	}
}
