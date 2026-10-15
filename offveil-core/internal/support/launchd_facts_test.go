package support

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLaunchdFactsExcludeEnvironmentAndExecutablePaths(t *testing.T) {
	output := "system/offveil-core = {\n" +
		"\tstate = running\n\tpid = 123\n\truns = 2\n\tlast exit code = -9\n" +
		"\tprogram = /Users/private/Downloads/offveil.app/Contents/MacOS/offveil-core\n" +
		"\tenvironment = {\n\t\tTOKEN = secret\n\t\tstate = private\n\t}\n}"
	facts := launchdFacts(output)
	if facts["state"] != "running" || facts["pid"] != 123 || facts["last_exit_code"] != -9 || facts["program_is_canonical"] != false {
		t.Fatalf("%+v", facts)
	}
	raw, _ := json.Marshal(facts)
	for _, private := range []string{"/Users", "private", "TOKEN", "secret", "Downloads"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("private data in launchd facts: %s", raw)
		}
	}
	if launchdFacts("\tprogram = /Library/Application Support/offveil/offveil-core")["program_is_canonical"] != true {
		t.Fatal("canonical executable not recognized")
	}
	if launchdFacts("\tstate = /Users/private\n\tpid = secret")["state"] != "other" {
		t.Fatal("unrecognized state was not filtered")
	}
}
