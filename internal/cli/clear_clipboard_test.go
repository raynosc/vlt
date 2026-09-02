package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/atotto/clipboard"
)

// TestClearClipboardCmd_AcceptsNoArgs is a guard against the regression of
// S-06: passing the expected clipboard value as an argv argument leaked it
// to `ps`/`/proc/<pid>/cmdline`. The command must accept no positional
// arguments — the value is read from stdin instead.
func TestClearClipboardCmd_AcceptsNoArgs(t *testing.T) {
	cmd := newClearClipboardCmd()

	// cobra.NoArgs returns an error when called with any positional arg.
	if err := cmd.Args(cmd, []string{"a-secret"}); err == nil {
		t.Fatalf("expected an error when passing a positional argument; the command must read from stdin")
	}
}

// TestClearClipboardCmd_ReadsFromStdin verifies the new flow end-to-end:
// stdin contains the secret, the clipboard initially contains the same
// secret, the timer fires (we set delay=0 for the test) and the clipboard
// is cleared because contents matched.
func TestClearClipboardCmd_ReadsFromStdin(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a clipboard backend; skip in short mode")
	}
	// Some CI containers don't have a clipboard daemon. Skip if WriteAll
	// fails up front rather than reporting a misleading test failure.
	if err := clipboard.WriteAll("vlt-test-precheck"); err != nil {
		t.Skipf("clipboard unavailable in this environment: %v", err)
	}

	const secret = "super-secret-token-xyz"
	if err := clipboard.WriteAll(secret); err != nil {
		t.Fatalf("seed clipboard: %v", err)
	}

	// Make the test deterministic: clear immediately instead of waiting 30s.
	old := clipboardClearDelay
	clipboardClearDelay = 0
	t.Cleanup(func() { clipboardClearDelay = old })

	cmd := newClearClipboardCmd()
	cmd.SetIn(bytes.NewBufferString(secret))
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{})

	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("__clear-clipboard did not return in time")
	}

	got, err := clipboard.ReadAll()
	if err != nil {
		t.Fatalf("read clipboard: %v", err)
	}
	if got != "" {
		t.Fatalf("clipboard should have been cleared, still contains: %q", got)
	}
}

// TestClearClipboardCmd_DoesNotClearIfChanged ensures we never wipe something
// the user copied AFTER our secret — the auto-clear is a no-op if contents
// changed.
func TestClearClipboardCmd_DoesNotClearIfChanged(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a clipboard backend; skip in short mode")
	}
	if err := clipboard.WriteAll("vlt-test-precheck"); err != nil {
		t.Skipf("clipboard unavailable in this environment: %v", err)
	}

	const secret = "old-secret"
	const updated = "user-copied-this-later"

	if err := clipboard.WriteAll(updated); err != nil {
		t.Fatalf("seed clipboard: %v", err)
	}

	old := clipboardClearDelay
	clipboardClearDelay = 0
	t.Cleanup(func() { clipboardClearDelay = old })

	cmd := newClearClipboardCmd()
	cmd.SetIn(strings.NewReader(secret + "\n")) // trailing newline must be trimmed
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got, _ := clipboard.ReadAll()
	if got != updated {
		t.Fatalf("clipboard should still contain %q (user-supplied), got %q", updated, got)
	}
}
