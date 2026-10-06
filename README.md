# IP Lookup

Alfred 5 workflow that shows the country and ISP of an IP address, checked against nine geolocation sources at once.

IP databases often disagree, and some are months out of date. This workflow asks them all in parallel and puts the consensus on top. Each distinct answer gets its own row, with the sources that gave it.

```
🇺🇸 United States · Google LLC     8.8.8.8 · AS15169 · all 9 sources agree
📍 Mountain View                   5 sources · ipapi.is, DB-IP, IPGeolocation, IP2Location, ipinfo
📍 Ashburn                         ip-api
📍 San Jose                        ipwho.is
📋 Google LLC                      Registry ARIN · GOGL · 8.8.8.0/24
```

## Usage

| You type | You get |
|---|---|
| `ip 8.8.8.8` | country, city and ISP for that address |
| `ip 2001:4860:4860::8888` | IPv6 works too |
| `ip example.com` | resolves the host, then looks up its address (VPN fake-IP answers in 198.18.0.0/15 are re-resolved over Google DNS-over-HTTPS) |
| `ip 1.2.3.4:443`, `ip https://1.2.3.4/path`, `ip [2606:4700::1111]:443` | the address is pulled out of ports, URLs and brackets |
| `ip ۸.۸.۸.۸` | Persian and Arabic digits work |
| `ip` | your own public IP; if the clipboard holds an IP, a row offers it (⇥ to use it) |

- ↩ copies the row as text, for example `8.8.8.8 — United States (US), Mountain View — Google LLC (AS15169)`.
- ⌘↩ opens the address on check-host.net. ⌥↩ opens it on ipinfo.io. ⇧ previews check-host in Quick Look.
- Select text anywhere and use the Universal Action **IP Lookup**.

## What the rows mean

- **Top row:** the country and ISP most sources agree on, with the vote count. A ⚠️ means the sources split on the country.
- **📍 rows:** one per distinct answer. Sources that agree share a row, and the row shows only what differs from the top line (usually the city). A row whose country disagrees is marked ⚠️ and names that country. A source that adds nothing new (same country and ISP, no city) is counted in the vote but gets no row of its own.
- **📋 row:** who the address block is *registered* to, from the regional registry (RIPE, ARIN, APNIC, LACNIC, AFRINIC) over RDAP. This is the registration, not the location, so it is not counted in the vote.
- **✗ rows:** a source that failed or timed out.

## Sources

| Source | What it gives |
|---|---|
| [check-host.net](https://check-host.net) | five databases in one request: DB-IP, IPGeolocation.io, IP2Location, MaxMind GeoIP and an IPInfo snapshot, each with its database date |
| [ip-api.com](https://ip-api.com) | country, city, ISP, ASN (the free tier is plain HTTP) |
| [ipapi.is](https://ipapi.is) | country, city, ASN |
| [ipwho.is](https://ipwho.is) | country, city, ISP, ASN |
| [ipinfo.io](https://ipinfo.io) | live lookup, can differ from the snapshot check-host shows |
| RDAP, via the [IANA bootstrap](https://data.iana.org/rdap/) | the registry record, queried directly at the right registry |

No API keys are needed. All sources are free tiers with rate limits, which is plenty for lookups by hand.

## Speed

All sources are queried at once in a background process, and rows stream into Alfred as each one answers. The fastest source usually lands in about a second and the rest within 2–5 seconds. Each refresh of the list takes under 100 ms.

Results are cached for 6 hours (5 minutes if any source failed), so a repeat lookup is instant. The IANA registry map is cached for 30 days.

## Install

Download `IP-Lookup.alfredworkflow` from [Releases](https://github.com/aliafshany/alfred-ip-lookup/releases) and double-click it.

Requirements: Alfred 5 with the Powerpack, and `/usr/bin/python3`. If macOS asks you to install the Command Line Tools the first time, accept, or run `xcode-select --install`. No other dependencies: the script uses only the Python standard library and `/usr/bin/curl`.

## Privacy

Every lookup sends the IP address you typed to the sources above. ip-api.com is queried over plain HTTP, because its free tier offers nothing else. Your own public IP is fetched from api.ipify.org (ipinfo.io as fallback) only when you run `ip` with no address. A hostname is sent to dns.google only when your system resolver returns a fake-IP (198.18.0.0/15) address. Nothing else leaves your Mac.

## Development

```
workflow/            the workflow as installed: info.plist, iplookup.py, icon.png
tests/               offline unit tests, with a saved check-host page as fixture
tools/make_icon.swift  renders icon.png from an SF Symbol
dist/                packaged .alfredworkflow
```

Run the tests with `/usr/bin/python3 -m unittest discover -s tests`. Package with `cd workflow && zip -X ../dist/IP-Lookup.alfredworkflow info.plist iplookup.py icon.png`.

## License

MIT
