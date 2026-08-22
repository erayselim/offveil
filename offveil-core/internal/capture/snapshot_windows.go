//go:build windows

package capture

import (
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	gaaFlagIncludeGateways = 0x0080
	gaaFlagIncludePrefix   = 0x0010
	ifTypeSoftwareLoopback = 24
	ifTypeTunnel           = 131
	ifOperStatusUp         = 1
)

// TakeSnapshot enumerates adapters for multi-NIC fail-safe and picks egress.
func TakeSnapshot() (*Snapshot, error) {
	adapters, err := listAdapters()
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		TakenAt:  time.Now().UTC(),
		Adapters: adapters,
		Egress:   PickEgress(adapters),
	}, nil
}

// FindAdapterLUIDByName returns the LUID of a live adapter with the given friendly name.
func FindAdapterLUIDByName(name string) (uint64, error) {
	if name == "" {
		return 0, fmt.Errorf("empty adapter name")
	}
	adapters, err := listAdapters()
	if err != nil {
		return 0, err
	}
	for _, a := range adapters {
		if a.Name == name {
			return a.LUID, nil
		}
	}
	return 0, fmt.Errorf("adapter %q not found", name)
}

func listAdapters() ([]AdapterInfo, error) {
	var size uint32 = 15000
	var buf []byte
	var err error
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		err = windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			gaaFlagIncludeGateways|gaaFlagIncludePrefix,
			0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])),
			&size,
		)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	var out []AdapterInfo
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		info := AdapterInfo{
			Name:        windows.UTF16PtrToString(aa.FriendlyName),
			Description: windows.UTF16PtrToString(aa.Description),
			IfIndex:     aa.IfIndex,
			LUID:        aa.Luid,
			IPv4Metric:  aa.Ipv4Metric,
			OperStatus:  operStatusString(aa.OperStatus),
			IsTUNLike:   aa.IfType == ifTypeTunnel || aa.IfType == ifTypeSoftwareLoopback,
		}
		for addr := aa.FirstUnicastAddress; addr != nil; addr = addr.Next {
			if ip := addr.Address.IP(); ip != nil {
				if a, ok := netip.AddrFromSlice(ip); ok {
					info.UnicastAddrs = append(info.UnicastAddrs, a.String())
				}
			}
		}
		for gw := aa.FirstGatewayAddress; gw != nil; gw = gw.Next {
			if ip := gw.Address.IP(); ip != nil {
				if a, ok := netip.AddrFromSlice(ip); ok {
					info.Gateways = append(info.Gateways, a.String())
				}
			}
		}
		out = append(out, info)
	}
	return out, nil
}

func operStatusString(s uint32) string {
	switch s {
	case ifOperStatusUp:
		return "up"
	case 2:
		return "down"
	default:
		return fmt.Sprintf("%d", s)
	}
}
