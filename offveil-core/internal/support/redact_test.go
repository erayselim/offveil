package support

import (
	"os"
	"strings"
	"testing"
)

func TestSetupIdentityRedaction(t *testing.T) {
	t.Setenv("USER", "testaccount")
	host, _ := os.Hostname()
	message := RedactLocalError("setup: user=testaccount on " + host + " /Users/testaccount/file 203.0.113.1")
	if strings.Contains(message, "testaccount") || strings.Contains(message, "203.0.113.1") || (host != "" && strings.Contains(message, host)) {
		t.Fatal("local identity remained in setup error")
	}
	if !strings.Contains(message, "setup:") {
		t.Fatal("error context was lost")
	}
}
