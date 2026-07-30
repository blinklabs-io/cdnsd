# cdnsd

Resolver for Cardano-based second-level domains on Handshake top-level domains

## Features

- **Blockchain-based DNS indexer and resolver:** 
  - Supports Cardano and Handshake network integration
  - Dynamic top-level domain (TLD) discovery and management
  - ICANN root hints for non-blockchain domain resolution
- **Multi-protocol DNS service:**
  - Standard DNS over UDP and TCP
  - DNS over TLS (when enabled)
- **DNSSEC-aware recursive resolution:**
  - Validates signed answers and authenticated denial of existence
  - Supports IANA and blockchain-authenticated roots
- **Real-time monitoring:**
  - Prometheus metrics endpoint
  - Optional request-level query logging
- **Pluggable configuration:**
  - YAML file and environment variable support
  - Profile-based settings for network/TLDs
- **Debugging and Observability:**
  - Optional debug HTTP server (for pprof, etc.)
- **Persistence:**
  - Local disk database to store sync state and discovered blockchain data

## Configuration

`cdnsd` supports configuration via YAML config files, and all settings may be overridden with environment variables.

### Top-level Config Options (YAML)

| Option                  | Type         | Environment Variable              | Description |
|-------------------------|--------------|-----------------------------------|-------------|
| `logging.debug`         | bool         | `LOGGING_DEBUG`                   | Enable debug logging (default: false) |
| `logging.queryLog`      | bool         | `LOGGING_QUERY_LOG`               | Enable DNS query logging (default: true) |
| `metrics.address`       | string       | `METRICS_LISTEN_ADDRESS`          | IP/interface for Prometheus metrics listener |
| `metrics.port`          | uint         | `METRICS_LISTEN_PORT`             | TCP port for Prometheus metrics |
| `dns.address`           | string       | `DNS_LISTEN_ADDRESS`              | DNS listener IP/interface (empty = all) |
| `dns.port`              | uint         | `DNS_LISTEN_PORT`                 | DNS UDP/TCP port (default: 8053) |
| `dns.tlsPort`           | uint         | `DNS_LISTEN_TLS_PORT`             | DNS-over-TLS port (default: 8853) |
| `dns.recursionEnabled`  | bool         | `DNS_RECURSION`                   | Allow recursive DNS lookups |
| `dns.rootHints`         | string       | `DNS_ROOT_HINTS`                  | DNS root hints (PEM string) |
| `dns.rootHintsFile`     | string       | `DNS_ROOT_HINTS_FILE`             | File path to DNS root hints |
| `dns.dnssec.enabled`    | bool         | `DNSSEC_ENABLED`                  | Validate recursive DNSSEC chains (default: false) |
| `dns.dnssec.trustAnchors` | string     | `DNSSEC_TRUST_ANCHORS`            | DS or DNSKEY trust anchors in zone-file format |
| `dns.dnssec.trustAnchorsFile` | string | `DNSSEC_TRUST_ANCHORS_FILE`       | File containing DS or DNSKEY trust anchors |
| `dns.dnssec.rootAnchorRefreshInterval` | duration | `DNSSEC_ROOT_ANCHOR_REFRESH_INTERVAL` | RFC 5011 root DNSKEY refresh interval (default: 24h) |
| `dns.dnssec.rootAnchorHoldDown` | duration | `DNSSEC_ROOT_ANCHOR_HOLD_DOWN` | RFC 5011 add/remove hold-down (default: 720h) |
| `debug.address`         | string       | `DEBUG_ADDRESS`                   | Address for debug HTTP server (default: localhost) |
| `debug.port`            | uint         | `DEBUG_PORT`                      | Port for debug HTTP server |
| `indexer.network`       | string       | `INDEXER_NETWORK`                 | Cardano network name (e.g. preprod, mainnet) |
| `indexer.networkMagic`  | uint32       | `INDEXER_NETWORK_MAGIC`           | Cardano network magic value |
| `indexer.address`       | string       | `INDEXER_TCP_ADDRESS`             | Cardano node TCP address |
| `indexer.socketPath`    | string       | `INDEXER_SOCKET_PATH`             | Path to Cardano node IPC socket |
| `indexer.interceptHash` | string       | `INDEXER_INTERCEPT_HASH`          | Initial sync block hash for chain |
| `indexer.interceptSlot` | uint64       | `INDEXER_INTERCEPT_SLOT`          | Initial sync slot number |
| `indexer.verify`        | bool         | `INDEXER_VERIFY`                  | Enable indexer verification mode |
| `indexer.handshakeAddress` | string    | `INDEXER_HANDSHAKE_ADDRESS`       | Handshake peer address to connect |
| `state.dir`             | string       | `STATE_DIR`                       | Directory for persistent state (BadgerDB) |
| `tls.certFilePath`      | string       | `TLS_CERT_FILE_PATH`              | Path to TLS certificate for DNS over TLS |
| `tls.keyFilePath`       | string       | `TLS_KEY_FILE_PATH`               | Path to TLS key for DNS over TLS |
| `profiles`              | []string     | `PROFILES`                        | List of enabled network profiles |

#### Example YAML Snippet

```yaml
logging:
  debug: true
  queryLog: true
metrics:
  address: ""
  port: 9000
dns:
  address: "0.0.0.0"
  port: 8053
  tlsPort: 8853
  recursionEnabled: true
  rootHintsFile: "/etc/cdnsd/named.root"
  dnssec:
    enabled: true
    # Optional: replaces the bundled IANA root anchors.
    trustAnchorsFile: "/etc/cdnsd/root.keys"
debug:
  address: "127.0.0.1"
  port: 6060
indexer:
  network: "preprod"
  networkMagic: 1
  address: "preprod-node.local:3001"
  socketPath: ""
  interceptHash: ""
  interceptSlot: 0
  verify: false
  handshakeAddress: ""
state:
  dir: "/var/lib/cdnsd"
tls:
  certFilePath: "/etc/cdnsd/cert.pem"
  keyFilePath: "/etc/cdnsd/key.pem"
profiles:
  - "cardano-preprod-testing"
```

### DNSSEC and multiple roots

DNSSEC validation is opt-in. When enabled, cdnsd requests DNSSEC records
from authoritative servers, validates each signed delegation, returns the
Authenticated Data (`AD`) bit for secure answers, and returns `SERVFAIL`
for bogus data. Securely proven unsigned delegations continue to resolve
without the `AD` bit.

The bundled trust-anchor set contains the IANA KSK-2017 and KSK-2024
anchors. Supplying `trustAnchors` or `trustAnchorsFile` replaces that set.
Each non-comment line must be a complete `DS` or `DNSKEY` record, and
anchors for multiple zones may be listed together.

When DNSSEC is enabled, the root anchor set is refreshed from an authenticated
root DNSKEY response. New SEP keys remain `add_pending` until the configured
RFC 5011 hold-down has elapsed; missing keys enter `remove_pending`, and a
revoked key is removed immediately. The state is stored in `state.dir` and is
loaded before the first refresh, so a restart during hold-down does not reset
the timer. Failed, unsigned, or otherwise unauthenticated responses are
discarded and cannot replace the last known-good set. Refresh transitions are
logged and exposed through `dnssec_root_anchor_transition_total` and
`dnssec_root_anchor_active`.

The bundled anchors are the bootstrap. Operators should monitor the transition
metric and logs during a rollover. For manual recovery, stop cdnsd, preserve a
backup, remove the `dnssec_root_anchor_state` entry from the Badger state
directory, and restart with a verified `trustAnchorsFile`.

Cardano and Handshake records do not need to descend from the ICANN root.
When an on-chain delegation contains a `DS` record, cdnsd uses that record
as the trust anchor for the delegated zone. This creates a separate,
blockchain-authenticated DNSSEC island for each applicable root.

### Profiles

Profiles predefine settings for specific TLDs and Cardano/Handshake networks. Enable profiles via the `profiles` YAML array or `PROFILES` environment variable.

#### Example profiles:
- `cardano-preprod-testing`
- `ada-preprod`
- `hydra-preprod`

See the [profile config file](https://github.com/blinklabs-io/cdnsd/blob/main/internal/config/profile.go) for the full list and details.

## Running

Start `cdnsd` with:
```sh
cdnsd -config /etc/cdnsd/config.yaml
```
Or, override settings with environment variables, e.g.:
```sh
export DNS_LISTEN_PORT=5353
cdnsd
```

## Metrics & Observability

- Prometheus: Exposed at `/metrics` (port per config)
- Debug HTTP/pprof: If debug port is set, accessible for diagnostics
