package cli

import "testing"

func TestExitCodes(t *testing.T) {
	if ExitOK != 0 {
		t.Errorf("ExitOK = %d, want 0", ExitOK)
	}
	if ExitErr != 1 {
		t.Errorf("ExitErr = %d, want 1", ExitErr)
	}
	if ExitQuickErr != 2 {
		t.Errorf("ExitQuickErr = %d, want 2", ExitQuickErr)
	}
}
