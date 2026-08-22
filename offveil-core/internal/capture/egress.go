package capture

// PickEgress chooses the best physical NIC for loop-prevention bind.
// Lowest IPv4 metric among up adapters that have a gateway and are not TUN-like.
func PickEgress(adapters []AdapterInfo) *EgressInfo {
	var best *AdapterInfo
	for i := range adapters {
		a := &adapters[i]
		if a.OperStatus != "up" || a.IsTUNLike || len(a.Gateways) == 0 {
			continue
		}
		if best == nil || a.IPv4Metric < best.IPv4Metric {
			best = a
		}
	}
	if best == nil {
		return nil
	}
	gw := ""
	if len(best.Gateways) > 0 {
		gw = best.Gateways[0]
	}
	return &EgressInfo{
		Name:    best.Name,
		IfIndex: best.IfIndex,
		LUID:    best.LUID,
		Gateway: gw,
	}
}
