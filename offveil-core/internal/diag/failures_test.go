package diag

import "testing"

func TestFailureHistorySurvivesReadersAndStaysBounded(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	for i := range maxFailures + 5 {
		if err := RecordFailure(Failure{Component: "desync", Event: "unavailable", Attempt: i}); err != nil {
			t.Fatal(err)
		}
	}
	history := ReadFailures()
	if len(history) != maxFailures || history[0].Attempt != 5 || history[maxFailures-1].At == "" {
		t.Fatalf("history=%+v", history)
	}
	history[0].Component = "changed"
	if ReadFailures()[0].Component != "desync" {
		t.Fatal("readers share history state")
	}
}
