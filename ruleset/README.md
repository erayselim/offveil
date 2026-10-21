# Network policy

`active.json` version 7 uses schema 2. The default policy applies to public
network traffic and contains no built-in destination packages or exceptions.

```json
{
  "schema_version": 2,
  "version": 7,
  "updated_at": "2026-10-21",
  "network": {
    "control_hosts": [
      "www.cloudflare.com",
      "www.microsoft.com",
      "example.com"
    ],
    "routes": []
  },
  "packages": []
}
```

`control_hosts` are independent network-health checks. They do not define which
applications receive protection. The engine evaluates the aggregate result;
a failed destination alone is not evidence that the whole network path failed.
The parser requires at least two distinct hostnames.

Optional `network.routes` entries select `direct` for explicit `domains` or
`domain_suffix` destinations. Other route paths are rejected. These are user choices;
the distributed policy starts with no routing exceptions. For example:

```json
{
  "domains": ["internal.example.test"],
  "domain_suffix": ["example.test"],
  "path": "direct"
}
```

`packages` is optional and must be empty. Nonempty legacy package lists are
rejected with a migration error; they cannot silently restore destination-based
behavior. DNS observation counts actual requests; no related hostnames are
inferred from names or bundled seed lists.

## Signed updates and migration

- `channel.json` and its embedded copy require ruleset version 7 or later.
- Every cache, local-file, and remote document must use schema 2. A valid
  signature on an older schema cannot restore the obsolete policy.
- Remote and cached files require a valid Ed25519 signature. Failed validation
  keeps the accepted local policy or falls back to the embedded network policy.
- The repository source and embedded `active.json` are identical. Release CI
  creates `active.json.sig` with its private signing secret. The old source
  signature was removed because it signed different content; no replacement
  development key or placeholder signature is supplied.
- The private key remains a CI secret. `keys/` contains the public verification
  key and key history.

`OFFVEIL_RULESET_URL` overrides the update URL for controlled tests. Production
signature verification remains required for downloaded and cached updates.
