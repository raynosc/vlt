package version

import "testing"

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version must not be empty")
	}
	if Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", Version, "1.0.0")
	}
}
