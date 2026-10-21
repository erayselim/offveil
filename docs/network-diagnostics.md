# Network diagnostics

The desktop support export includes `system.network_connectivity`. It measures
DNS, TCP, certificate-verified TLS, HTTP response headers and a bounded response
sample independently, over the system resolver and current OS routes. An active
offveil TUN therefore participates in these checks. HTTP proxy environment
variables are deliberately not used.

The checks never change protection, routes, DNS, strategy selection or provider
health. Provider liveness must not depend on a particular application service.
The three baseline destinations are `https://example.com/`,
`https://www.wikipedia.org/` and `https://www.mozilla.org/`. IPv4 and IPv6 run
separately; a missing AAAA record is reported as `no_address` rather than a TLS
failure.

## Explicit targets

```text
offveil-core support -check-network -output support.zip
offveil-core support -check-url https://public.example.com/resource -output support.zip
offveil-core support -check-tcp public.example.com:5223 -output support.zip
```

`-check-url` and `-check-tcp` are repeatable, with at most six additional targets
in total. Supplying either also enables the three baseline checks. No application
name, updater schema, domain prefix or port is inferred. A raw TCP check closes
after connecting without sending bytes: `tcp_connected` confirms only the TCP
handshake, not authentication or an application's protocol.

HTTPS targets must have a public hostname or public literal IP, use HTTPS, and
contain no URL credentials or fragment. An explicit valid port is supported.
DNS answers are checked before any address is dialed; loopback, private,
link-local, shared-address, documentation and relevant transition ranges are
rejected. Known DNS poison fingerprints are reported separately. The resolved
address is pinned into the TCP connection and redirects are never followed.
Each family tries at most two resolved addresses, preserving each attempt's
stages. There is no second hostname lookup while dialing.

The whole network check has a 24-second budget and at most six concurrent
checks. Each endpoint family has eight seconds, each address attempt four
seconds. Cancellation closes active connections. Response headers are bounded
to 32 KiB and the body sample to 1 KiB; a server ignoring `Range` cannot make the
collector drain an entire download. The UI command timeout is 40 seconds to
allow collection and ZIP creation as well.

## Interpreting results

Each result contains its role, hostname (or `literal_address`), protocol, port,
address family, DNS outcome and per-attempt stage outcomes and times. Numeric
HTTP status and sample byte count are recorded. TLS success remains visible
when later HTTP or body reading fails. `http_status` means that an HTTP response
arrived with a non-2xx status; for example, a redirect or access denial is not a
TCP failure. An empty valid 204 response is successful. A partial body contrary
to `Content-Length` is a body error even after a valid TLS handshake and 200
response. Transport classes distinguish certificate, reset, refused, EOF,
unexpected EOF, timeout and cancellation without saving raw error strings.

The report saves no URLs, paths, query strings, IP addresses, headers, cookies,
response text or credentials. Query parameters on an explicitly supplied URL
are used only for that request and are not included in the report. No account
or telemetry upload is involved.

A successful sample verifies that request on the collector process's current
OS route. It does not prove the original application's TLS ClientHello,
per-process firewall policy, login, WebSocket, complete download or UDP flow.
Compare the same explicit failing target on the affected network and another
connection, and with protection on and off, to identify the failing layer.
