package version

import "testing"

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version must not be empty")
	}
	if Version != "0.2.1" {
		t.Errorf("Version = %q, want %q", Version, "0.2.1")
	}
}
