//go:build windows

package repair

import (
	"github.com/erayselim/offveil/offveil-core/internal/capture"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
)

func network(r *Result) {
	nrptWas := offdns.NRPTPresent()
	adapterWas := capture.AdapterPresent()

	detail := "absent"
	err := offdns.RemoveNRPT()
	if err == nil && nrptWas {
		detail = "removed"
	}
	r.add("nrpt", err, detail)

	armed := nrptWas || adapterWas
	dnsDetail, err := offdns.RestoreLeftoverDNS(armed)
	r.add("dns", err, dnsDetail)

	detail = "absent"
	err = capture.CloseOrphanAdapter()
	if err == nil && adapterWas {
		detail = "removed"
	}
	r.add("adapter", err, detail)

	offdns.FlushResolverCache()
	r.add("flush", nil, "")
}
