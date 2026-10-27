package desync

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/erayselim/offveil/offveil-core/internal/ruleset"
)

// PassThroughSuffix marks a strategy whose first ByeDPI group leaves the
// connection untouched. Unfiltered sites never pay for split/disorder.
const PassThroughSuffix = "+pass"

// autoTriggers fires the next group on a reset/timeout after the first request
// or on a missing ServerHello. ByeDPI reconnects and replays the request.
const autoTriggers = "torst,ssl_err"

// globalFlags are ByeDPI options that apply to the whole process, not a group.
var globalFlags = map[string]bool{"--no-domain": false, "-N": false, "--timeout": true, "-T": true}

// PassThroughFirst inserts an empty first group. Detection relies on ByeDPI's
// own triggers, so blocked destinations get the strategy on the same
// connection and the IP is cached for later ones.
func PassThroughFirst(s Strategy) Strategy {
	if IsPassThrough(s) || len(s.Args) == 0 {
		return s
	}
	var globals, groups []string
	for i := 0; i < len(s.Args); i++ {
		arg := s.Args[i]
		name, _, inline := strings.Cut(arg, "=")
		takesValue, global := globalFlags[name]
		if !global {
			groups = append(groups, arg)
			continue
		}
		globals = append(globals, arg)
		if takesValue && !inline && i+1 < len(s.Args) {
			i++
			globals = append(globals, s.Args[i])
		}
	}
	if len(groups) == 0 {
		return s
	}
	args := append(append(globals, "--auto", autoTriggers), groups...)
	return Strategy{ID: s.ID + PassThroughSuffix, Args: args, Note: "pass-through first; " + s.Note}
}

// IsPassThrough reports whether s was built by PassThroughFirst.
func IsPassThrough(s Strategy) bool { return strings.HasSuffix(s.ID, PassThroughSuffix) }

// BaseID strips the pass-through marker for scan/cache bookkeeping.
func BaseID(id string) string { return strings.TrimSuffix(id, PassThroughSuffix) }

// strategyFlags lists the ByeDPI options a signed ruleset may use. Listen,
// bind, daemon and file options are never accepted from remote data.
var strategyFlags = map[string]bool{
	"--split": true, "-s": true,
	"--disorder": true, "-d": true,
	"--oob": true, "-o": true,
	"--disoob": true, "-q": true,
	"--fake": true, "-f": true,
	"--ttl": true, "-t": true,
	"--fake-offset": true, "-O": true,
	"--fake-sni": true, "-n": true,
	"--fake-tls-mod": true, "-Q": true,
	"--mod-http": true, "-M": true,
	"--tlsrec": true, "-r": true,
	"--tlsminor": true, "-m": true,
	"--auto": true, "-A": true,
	"--auto-mode": true, "-L": true,
	"--proto": true, "-K": true,
	"--pf": true, "-V": true,
	"--round": true, "-R": true,
	"--udp-fake": true, "-a": true,
	"--oob-data": true, "-e": true,
	"--timeout": true, "-T": true,
	"--no-domain": false, "-N": false,
}

func validValue(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("+-:,._=?#*", c)) {
			return false
		}
	}
	return true
}

// ValidateStrategyArgs accepts only allowlisted flags with plain values.
func ValidateStrategyArgs(args []string, goos string) error {
	if len(args) == 0 {
		return fmt.Errorf("empty strategy")
	}
	for i := 0; i < len(args); i++ {
		name, value, inline := strings.Cut(args[i], "=")
		takesValue, ok := strategyFlags[name]
		if !ok {
			return fmt.Errorf("flag %q is not allowed", name)
		}
		if !takesValue {
			if inline {
				return fmt.Errorf("flag %q takes no value", name)
			}
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				return fmt.Errorf("flag %q needs a value", name)
			}
			i++
			value = args[i]
		}
		if !validValue(value) {
			return fmt.Errorf("flag %q has an invalid value", name)
		}
	}
	if goos == "darwin" && ContainsDarwinUnsupported(args) {
		return fmt.Errorf("strategy uses TTL operations unsupported on macOS")
	}
	return nil
}

// FromSpec turns a signed ruleset candidate into a runnable strategy with the
// same process-wide options as the built-in set.
func FromSpec(id string, args []string) (Strategy, error) {
	if err := ValidateStrategyArgs(args, runtime.GOOS); err != nil {
		return Strategy{}, fmt.Errorf("%s: %w", id, err)
	}
	prefix := []string{"--no-domain"}
	if runtime.GOOS != "darwin" && !hasFlag(args, "--timeout", "-T") {
		prefix = append(prefix, "--timeout", "3")
	}
	return Strategy{ID: id, Args: append(prefix, args...), Note: "signed ruleset candidate"}, nil
}

// CandidatesFrom converts signed ruleset specs for this OS. Invalid specs are
// skipped and reported; one bad entry cannot disable the built-in set.
func CandidatesFrom(specs []ruleset.StrategySpec) ([]Strategy, []error) {
	var out []Strategy
	var errs []error
	for _, spec := range specs {
		if spec.Platform != "" && spec.Platform != runtime.GOOS {
			continue
		}
		s, err := FromSpec(spec.ID, spec.Args)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, s)
	}
	return out, errs
}

// MergeCandidates keeps the first strategy for each ID.
func MergeCandidates(groups ...[]Strategy) []Strategy {
	seen := map[string]bool{}
	var out []Strategy
	for _, group := range groups {
		for _, s := range group {
			if s.ID == "" || seen[s.ID] {
				continue
			}
			seen[s.ID] = true
			out = append(out, s)
		}
	}
	return out
}

func hasFlag(args []string, names ...string) bool {
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		for _, want := range names {
			if name == want {
				return true
			}
		}
	}
	return false
}
