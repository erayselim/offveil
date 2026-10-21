package tunnel

import "github.com/erayselim/offveil/offveil-core/internal/ruleset"

func defaultProtectedDomains() []string {
	return ruleset.MustLoadEmbedded().Doc.ProtectedDomains()
}
