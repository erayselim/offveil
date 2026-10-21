# Pinned sing-box source build

The sidecar keeps upstream v1.13.14 (commit
`25a600db24f7680ad9806ce5427bd0ab8afe1114`). Its upstream source is unmodified.
This separate Go module locks security updates to its dependencies without
linking GPL code into offveil-core. Both supported platforms use Go 1.26.10,
CGO disabled and `with_gvisor,with_quic,with_wireguard,with_utls`.
Optional upstream features that offveil does not configure are not enabled.

From this directory, run:

```sh
go run build.go ../../third_party/sing-box
```

The builder checks the upstream module checksum, verifies downloaded modules,
runs govulncheck against the actual tagged source on the host platform, then
builds with `-mod=readonly -trimpath`. A scan or build failure stops packaging.
The Windows and Darwin fetch entry points invoke this builder; the Darwin
wrapper also ad-hoc signs the executable before staging it.

GitHub releases include `sing-box-1.13.14-source.zip`, the exact upstream Go
module source archive. Dependency versions/checksums and the full build recipe
are in this directory in the same offveil release tag. Dependencies are fetched
through Go's module checksum verification. To rebuild manually, from this
directory with Go 1.26.10, run (use `.exe` on Windows):

```sh
CGO_ENABLED=0 go build -mod=readonly -trimpath \
  -tags with_gvisor,with_quic,with_wireguard,with_utls \
  -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.13.14' \
  -o sing-box github.com/sagernet/sing-box/cmd/sing-box
```

The upstream GPL LICENSE and COPYING files remain in both installers. The
upstream archive also contains its Go dependency declarations and license.
