package support

import (
	"os"
	"regexp"
	"strings"

	"github.com/erayselim/offveil/offveil-core/internal/diag"
)

// RedactLocalError covers identities in sudo/setup errors as well as home paths.
// Raw setup output is never attached as a general log file.
func RedactLocalError(message string) string {
	message = diag.Scrub(message)
	host, _ := os.Hostname()
	shortHost, _, _ := strings.Cut(host, ".")
	for _, identity := range []string{os.Getenv("USER"), os.Getenv("LOGNAME"), os.Getenv("USERNAME"), host, shortHost} {
		if len(identity) < 3 || identity == "root" || identity == "localhost" || identity == "SYSTEM" {
			continue
		}
		pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(identity) + `\b`)
		message = pattern.ReplaceAllString(message, "_")
	}
	return message
}
