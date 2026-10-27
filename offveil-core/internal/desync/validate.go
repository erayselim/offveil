package desync

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ValidateNativeArguments parses every native strategy with the real sidecar,
// both as written and in its deployed pass-through-first form. --help follows
// the strategy so getopt must parse all production arguments.
func ValidateNativeArguments(ctx context.Context, binary string, extra ...Strategy) error {
	var all []Strategy
	for _, strategy := range append(NativeScanCandidates(), extra...) {
		all = append(all, strategy, PassThroughFirst(strategy))
	}
	for _, strategy := range all {
		args := append(BuildArgsBind("127.0.0.1", 18080, strategy, "127.0.0.1"), "--help")
		check, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, err := exec.CommandContext(check, binary, args...).CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("%s: sidecar rejects native arguments: %s (%w)", strategy.ID, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}
