//go:build darwin

package repair

import (
	"github.com/erayselim/offveil/offveil-core/internal/capture"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
)

func network(r *Result) {
	r.add("nrpt", nil, "skipped")

	armed := offdns.NRPTPresent() || capture.AdapterPresent()
	dnsDetail, err := offdns.RestoreLeftoverDNS(armed)
	r.add("dns", err, dnsDetail)

	detail, err := capture.ClearLeftoverRoutes()
	r.add("adapter", err, detail)

	offdns.FlushResolverCache()
	r.add("flush", nil, "mdnsresponder")
}
