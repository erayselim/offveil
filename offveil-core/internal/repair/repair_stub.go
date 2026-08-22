//go:build !windows

package repair

func network(r *Result) {
	r.add("nrpt", nil, "skipped")
	r.add("dns", nil, "skipped")
	r.add("adapter", nil, "skipped")
	r.add("flush", nil, "skipped")
}
