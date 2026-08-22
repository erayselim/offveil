package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	mdns "github.com/miekg/dns"
)

// Plain UDP resolvers used when DoH/443 is unreachable.
// Never use the system resolver here - after leak-guard it points at our stub (loop).
var defaultPlainUDP = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
}

const plainUDPBudget = 3 * time.Second

// ExchangePlain races plain DNS/UDP upstreams; first success wins.
func ExchangePlain(ctx context.Context, msg *mdns.Msg, upstreams []string) (*mdns.Msg, string, error) {
	if len(upstreams) == 0 {
		upstreams = defaultPlainUDP
	}
	ctx, cancel := context.WithTimeout(ctx, plainUDPBudget)
	defer cancel()

	type res struct {
		resp *mdns.Msg
		ep   string
		err  error
	}
	ch := make(chan res, len(upstreams))
	for _, ep := range upstreams {
		go func(ep string) {
			client := &mdns.Client{
				Net:     "udp",
				Timeout: plainUDPBudget,
				Dialer:  &net.Dialer{Timeout: 2 * time.Second},
			}
			resp, _, err := client.ExchangeContext(ctx, msg.Copy(), ep)
			ch <- res{resp: resp, ep: ep, err: err}
		}(ep)
	}

	var lastErr error
	remaining := len(upstreams)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return nil, "", fmt.Errorf("plain DNS timeout: %w", lastErr)
		case r := <-ch:
			remaining--
			if r.err != nil || r.resp == nil {
				if r.err != nil {
					lastErr = r.err
				}
				continue
			}
			cancel()
			return r.resp, r.ep, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all plain DNS upstreams failed")
	}
	return nil, "", lastErr
}

// filterPoisonAnswers removes known censorship A records from a DNS answer section.
func filterPoisonAnswers(poison *PoisonSet, answer []mdns.RR) (clean []mdns.RR, poisonID string, poisoned bool) {
	clean = answer[:0]
	for _, rr := range answer {
		a, ok := rr.(*mdns.A)
		if !ok {
			clean = append(clean, rr)
			continue
		}
		ip4 := a.A.To4()
		if ip4 == nil {
			continue
		}
		addr := netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
		if id, hit := poison.Match(addr); hit {
			poisoned = true
			poisonID = id
			continue
		}
		clean = append(clean, rr)
	}
	return clean, poisonID, poisoned
}
