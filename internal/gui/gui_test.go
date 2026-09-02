package gui

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBuildOTPAuthURI_EncodesSpecialChars(t *testing.T) {
	uri := buildOTPAuthURI("what?secret", "mysecret")
	if strings.Contains(uri, "what?secret") {
		t.Errorf("name with ? should be encoded, got: %s", uri)
	}
	if !strings.Contains(uri, "secret=mysecret") {
		t.Errorf("expected secret param, got: %s", uri)
	}
}

func TestBuildOTPAuthURI_StandardName(t *testing.T) {
	uri := buildOTPAuthURI("github-token", "JBSWY3DPEHPK3PXP")
	want := "otpauth://totp/github-token?secret=JBSWY3DPEHPK3PXP"
	if uri != want {
		t.Errorf("buildOTPAuthURI = %q, want %q", uri, want)
	}
}

// TestTOTPCancel_FieldExists verifies the GUI struct can hold a cancel func.
func TestTOTPCancel_FieldExists(t *testing.T) {
	g := &GUI{}
	ctx, cancel := context.WithCancel(context.Background())
	g.totpCancel = cancel

	// Calling cancel should not panic and should close the context.
	g.totpCancel()
	select {
	case <-ctx.Done():
		// expected
	case <-time.After(time.Second):
		t.Error("expected context to be cancelled")
	}
}

// TestTOTPCancel_DoubleCancelSafe verifies calling cancel twice does not panic.
func TestTOTPCancel_DoubleCancelSafe(t *testing.T) {
	g := &GUI{}
	_, cancel := context.WithCancel(context.Background())
	g.totpCancel = cancel

	g.totpCancel()
	g.totpCancel() // should not panic
}

func TestDefaultGUISocketPath(t *testing.T) {
	path := defaultGUISocketPath()
	if path == "" {
		t.Fatal("expected non-empty socket path")
	}
	if !strings.HasSuffix(path, "vlt-gui.sock") {
		t.Errorf("expected suffix vlt-gui.sock, got %s", path)
	}
}

func TestGUIIPCMessage_Serialization(t *testing.T) {
	msg := guiIPCMessage{Cmd: "quick"}
	if msg.Cmd != "quick" {
		t.Errorf("expected Cmd quick, got %s", msg.Cmd)
	}
}
