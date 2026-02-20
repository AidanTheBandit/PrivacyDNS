# PrivacyDNS

A Node.js DNS resolver with a pluggable Securly SmartPAC bypass. It runs as a
local recursive resolver, intercepts Securly API lookups and PAC downloads, and
forwards everything else to an upstream resolver (default: Cloudflare 1.1.1.1).

---

## Features

- **UDP DNS server** listening on `127.0.0.1:53` (configurable).
- **Local overrides** via `hosts.json` (exact + wildcard `*.example.com`) and
  optional BIND-style `.zone` files in `zones/`.
- **In-memory TTL cache** for forwarded responses.
- **Securly SmartPAC bypass**:
  - Redirects `useast2-www.securly.com` to a custom PAC server (via
    `PAC_TUNNEL_HOST`).
  - Returns `NXDOMAIN` for Securly API domains
    (`*.prx.useast2.v1api.securly.com`,
    `*.pacrpc.useast2.v1api.securly.com`).
  - Hook map (`PROXY_MAP`) to override Securly proxy hosts.
  - `isSecurlyIP()` helper to detect Securly IP ranges.
- **WPAD protection**: `wpad` and `wpad.local` always return `NXDOMAIN`.
- **Structured logging** to stdout and `dns.log`.

---

## Requirements

- **Node.js 18+**
- Ability to bind port 53 (requires `sudo` or `CAP_NET_BIND_SERVICE` on Linux).

---

## Installation

```bash
git clone https://github.com/AidanTheBandit/PrivacyDNS.git
cd PrivacyDNS
npm install   # no external dependencies – this initialises package-lock.json
```

---

## Running

```bash
sudo node index.js
```

With all options:

```bash
sudo UPSTREAM=1.1.1.1:53 PAC_TUNNEL_HOST=pac-bypass.example.com node index.js
```

| Variable          | Default      | Description                                               |
|-------------------|--------------|-----------------------------------------------------------|
| `UPSTREAM`        | `1.1.1.1:53` | Upstream DNS resolver (`host:port`)                       |
| `PAC_TUNNEL_HOST` | *(none)*     | IP or hostname of the cloudflared PAC endpoint            |
| `LISTEN_ADDR`     | `127.0.0.1`  | Address the DNS server binds to                           |
| `LISTEN_PORT`     | `53`         | Port the DNS server binds to                              |
| `LOG_FILE`        | `dns.log`    | Path to the append-only query log                         |

### PAC_TUNNEL_HOST behaviour

- If it is an **IPv4 address** (e.g. `203.0.113.10`), `useast2-www.securly.com`
  is immediately mapped to that IP in the override table.
- If it is a **hostname** (e.g. `pac-bypass.example.com`), add an entry for
  both the tunnel hostname and `useast2-www.securly.com` in `hosts.json` so
  that queries are answered locally without a round-trip.

---

## Configuration Files

### `hosts.json`

Static DNS overrides loaded at startup. Supports exact and wildcard keys:

```json
{
  "useast2-www.securly.com": "203.0.113.10",
  "useast2-dp.securly.com": "127.0.0.1",
  "*.prx.useast2.v1api.securly.com": "127.0.0.1",
  "*.pacrpc.useast2.v1api.securly.com": "127.0.0.1",
  "wpad": "0.0.0.0",
  "wpad.local": "0.0.0.0"
}
```

### `zones/` directory

Place simple BIND-style zone files here (any name ending in `.zone`).
Non-`IN A` lines are silently skipped. See `zones/example.zone` for syntax.

---

## Configuring the OS to use 127.0.0.1

### macOS

```bash
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1
```

### Linux (systemd-resolved)

Edit `/etc/systemd/resolved.conf`:

```
[Resolve]
DNS=127.0.0.1
```

Then: `sudo systemctl restart systemd-resolved`

### Windows

*Network Connections → adapter properties → IPv4 → Preferred DNS: 127.0.0.1*

---

## Cloudflared / PAC Integration

1. Run a small HTTP server on the Optiplex that serves an "always DIRECT" PAC
   at `/smart.pac`:

   ```js
   function FindProxyForURL(url, host) { return "DIRECT"; }
   ```

2. Expose it via a Cloudflare Tunnel so it gets a public hostname, e.g.
   `pac-bypass.example.com`.

3. Start PrivacyDNS with:

   ```bash
   sudo PAC_TUNNEL_HOST=<tunnel-ip-or-host> node index.js
   ```

   Devices that request `https://useast2-www.securly.com/smart.pac` will now be
   directed to your tunnel instead of Securly's servers and will receive the
   DIRECT PAC.

---

## Verification

```bash
# Check that WPAD is blocked
dig @127.0.0.1 wpad A

# Check that a Securly API domain returns NXDOMAIN
dig @127.0.0.1 test.prx.useast2.v1api.securly.com A

# Check that the PAC host override is active
dig @127.0.0.1 useast2-www.securly.com A

# Check normal forwarding
dig @127.0.0.1 example.com A
```

---

## Running Tests

```bash
npm test
```

---

## Log Format

Every query is appended to `dns.log` (and printed to stdout):

```
2024-01-01T12:00:00.000Z [QUERY]             example.com                          192.168.1.5:12345
2024-01-01T12:00:00.001Z [OVERRIDE]          example.com                          -> 93.184.216.34
2024-01-01T12:00:00.002Z [SECURLY_API_BLOCK] test.prx.useast2.v1api.securly.com   NXDOMAIN
2024-01-01T12:00:00.003Z [CACHE_HIT]         google.com                           -> 142.250.80.46
2024-01-01T12:00:00.004Z [UPSTREAM]          github.com                           -> 140.82.121.3 (cached)
2024-01-01T12:00:00.005Z [WPAD_BLOCK]        wpad                                 192.168.1.5:12346
```

Log type tokens: `STARTUP`, `QUERY`, `OVERRIDE`, `SECURLY_API_BLOCK`,
`SECURLY_PROXY_OVERRIDE`, `WPAD_BLOCK`, `CACHE_HIT`, `UPSTREAM`, `ERROR`.
