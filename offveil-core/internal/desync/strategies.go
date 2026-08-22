package desync

import "strconv"

// DefaultSafeStrategy is the Windows-safe ByeDPI argument set.
//
// Sources:
//   - Official dist/windows/byedpi.bat:
//     --split 1 --disorder 3+s --mod-http=h,d --auto=torst --tlsrec 1+s
//   - Upstream README Windows notes:
//     split+disorder preferred; fake via --disorder 1 --fake -1
//   - --auto cascades: torst (timeout/RST) → tlsrec; ssl_err → fake+ttl
//
// --no-domain: ByeDPI must not use the system resolver (DoH owns DNS).
// Clients CONNECT with IP; TLS SNI carries the name.
//
// Never pass --no-udp / -U. Discord voice media uses SOCKS5 UDP
// ASSOCIATE (ciadpi default). Voice RTP must not get --udp-fake injection.
func DefaultSafeStrategy() Strategy {
	return Strategy{
		ID: "byedpi:windows-safe",
		Args: []string{
			"--no-domain",
			"--timeout", "3",
			// Primary: Windows-safe split + disorder + HTTP header mix.
			"--split", "1",
			"--disorder", "3+s",
			"--mod-http", "h,d",
			// On timeout / RST after first request → TLS record split in SNI.
			"--auto", "torst",
			"--tlsrec", "1+s",
			// On ssl_err → Windows fake+disorder (README).
			"--auto", "ssl_err",
			"--disorder", "1",
			"--fake", "-1",
			"--ttl", "8",
		},
		Note: "Official Windows bat + README fake fallback via --auto; UDP ASSOCIATE on (voice)",
	}
}

// SafeStrategySet documents the named groups embedded in DefaultSafeStrategy.
// Prefer ScanCandidates() for auto-strategy.
func SafeStrategySet() []Strategy {
	return []Strategy{
		{
			ID:   "byedpi:split-disorder",
			Args: []string{"--split", "1", "--disorder", "3+s", "--mod-http", "h,d"},
			Note: "Primary Windows path (byedpi.bat)",
		},
		{
			ID:   "byedpi:tlsrec-on-torst",
			Args: []string{"--auto", "torst", "--tlsrec", "1+s"},
			Note: "Fallback when timeout/RST after ClientHello",
		},
		{
			ID:   "byedpi:fake-on-ssl-err",
			Args: []string{"--auto", "ssl_err", "--disorder", "1", "--fake", "-1", "--ttl", "8"},
			Note: "Fallback when ServerHello missing / bad session_id",
		},
	}
}

// BuildArgs returns full ciadpi argv (without binary): listen + strategy.
// Strips any accidental --no-udp / -U so Discord voice UDP ASSOCIATE stays on.
func BuildArgs(listenIP string, listenPort int, s Strategy) []string {
	args := []string{
		"--ip", listenIP,
		"--port", strconv.Itoa(listenPort),
	}
	for _, a := range s.Args {
		if a == "--no-udp" || a == "-U" {
			continue
		}
		args = append(args, a)
	}
	return args
}

// UDPEnabled reports whether argv keeps SOCKS5 UDP ASSOCIATE.
func UDPEnabled(args []string) bool {
	for _, a := range args {
		if a == "--no-udp" || a == "-U" {
			return false
		}
	}
	return true
}
