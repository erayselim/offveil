package support

import (
	"strconv"
	"strings"
)

// Keep only selected top-level fields. launchctl print also contains process
// environment and user paths, which must never enter a support archive.
func launchdFacts(output string) map[string]any {
	facts := map[string]any{"loaded": true}
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch key {
		case "state":
			switch value {
			case "running", "not running", "waiting", "spawn scheduled":
				facts["state"] = value
			default:
				facts["state"] = "other"
			}
		case "pid", "runs", "last exit code":
			if n, err := strconv.Atoi(value); err == nil {
				facts[strings.ReplaceAll(key, " ", "_")] = n
			}
		case "program":
			facts["program_is_canonical"] = value == "/Library/Application Support/offveil/offveil-core"
		}
	}
	return facts
}
