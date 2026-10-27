# Packet-level UDP regression

This separate test module exercises the sing-tun, sing and gVisor versions
used by the pinned sing-box 1.13.14 binary. It does not add these dependencies
to the production core module or installer. Licenses are listed in
[THIRD_PARTY.md](../../../THIRD_PARTY.md).

The test supplies an in-memory Wintun-compatible device. Synthetic packets
use documentation addresses and opaque payloads, with no game names or public
endpoints. It starts a disposable loopback TCP listener required by the
system/mixed stack, but creates no adapter or system route and changes no DNS.

Windows, from the repository root:

```powershell
./scripts/test-tun-udp.ps1
./scripts/test-tun-udp.ps1 -Race
```

The wrapper stages the checksum-verified upstream module under ignored
`offveil-core/dist/`, generates a private module file and replaces only the
Windows automatic firewall-rule installer with a no-op fixture. It leaves
the shared module cache and bundled binary intact. A fixture-only compile
symbol prevents Windows tests from accidentally installing a firewall rule
when run without the wrapper. The temporary test source is not app code.

macOS/Linux, from this directory (the shipped-config case skips Linux):

```sh
go test -tags=with_gvisor -timeout=60s ./...
```

The legacy system case first passes a small control packet, then reproduces
loss of a fragmented 1300-byte UDP payload. The configured-stack cases use
the stack/MTU from offveil's selective gateway generator and verify 64, 1200,
1252, 1253, 1300 and 4096 bytes plus the configured MTU's IPv4 UDP boundary
(MTU−28, MTU−27, MTU+100) in both directions, including reversed fragment
order. The 1252/1253 cases still straddle the 1280 boundary used inside WireGuard.

When changing the pinned sing-box version, review its `go.mod` and update
this module and the Windows wrapper together. The test must keep following
the runtime stack implementation.
