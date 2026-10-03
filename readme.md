# lgeoip – IP Geolocation & Anonymization Detection Server

## Overview

**lgeoip** is an IP address analysis service that reveals geolocation while detecting VPNs,
proxies, Tor nodes and hosting providers. It combines several data sources, transparent
heuristics, and **optional AI refinement** (ONNX) on top of them.

Unlike basic geolocation services, lgeoip specialises in **identifying anonymization
techniques** by analysing:

- IP geolocation (country, region, city, coordinates)
- Autonomous System Number (ASN) and provider analysis
- Tor network membership (real-time bulk exit list, cached)
- Proxy/VPN detection (IP2Proxy integration, optional)
- Hostname analysis via reverse DNS (cached, time-bounded)
- Timezone discrepancy analysis (browser vs. IP, DST-aware)
- **AI-powered probability refinement** (optional, validated before use)

> **Version 2.1** – security, correctness and performance overhaul. See
> [Changelog](#changelog) and [Security model](#security-model).

## Repository Structure

| Component | Location | Description |
|-----------|----------|-------------|
| **Backend server** | `server.py` | FastAPI application (access control, rate limit, caching, admin console) |
| **Configuration** | `config.py` | All paths and settings via `LGEOIP_*` environment variables |
| **AI module** | `lgeoai.py` | ONNX inference, feature extraction, model validation, sample/feedback logging |
| **AI training** | `train_model.py` | Trains and exports the ONNX model (no target leakage) |
| **Tests** | `tests/test_lgeoip.py` | 43 unit/API tests (`unittest`) |
| **Dependencies** | `requirements.txt` | Runtime + training + test dependencies |
| **Frontend interface** | [GitHub Pages](https://tutuurg.github.io/lgeoip/) | Live web interface (unchanged, fully compatible with 2.1) |
| **AI model** | [lgeoai repository](https://github.com/tutuurg/lgeoai) | `lgeoai_model.onnx` |

## Features

### Core capabilities

- **Precise geolocation**: country, region, city, postal code, coordinates
- **Anonymization detection**: probability 0–100 % for VPN/proxy/Tor usage
- **ISP/ASN analysis**: provider identification and classification
- **Time zone analysis**: browser vs. IP comparison, DST-correct (`zoneinfo`)
- **Multi-source verification**: MaxMind, IP2Proxy (optional), Tor Project data
- **ASN intelligence**: curated list of hosting/VPN ASNs, editable from the admin console
- **AI refinement**: optional ONNX model, **validated at startup** and skipped when it adds nothing

### Detection methods

| Signal | Weight | Notes |
|--------|--------|-------|
| Tor exit node | +90 | against the Tor Project bulk exit list (cached, refreshed in background) |
| IP2Proxy: proxy/VPN | +85 | requires the IP2Proxy package and database |
| Known hosting/VPN ASN | +99 | from `known_asns.json` |
| Timezone mismatch (browser vs. IP) | +55 | only for self-lookup |
| ISP name looks like hosting/datacenter | +50 | keyword heuristics |
| Suspicious reverse-DNS hostname | +40 | `proxy`, `vpn`, `tor`, `relay`, `cloud`, `vps`, … |
| IP2Proxy: datacenter usage | +30 | requires IP2Proxy |
| IP2Proxy: threat flag | +20 | requires IP2Proxy |

The sum is **capped at 100 before** any further processing, so combined signals cannot
produce meaningless values.

## Installation & Setup

### Prerequisites

```bash
python -m pip install -r requirements.txt
```

Python 3.10+ is required (`zoneinfo`, `X | None` type syntax). Tested on 3.14 (Windows).
The test suite additionally needs `httpx` (already listed in `requirements.txt`).

### 1. Download the databases

| Database | Purpose | Default location | Download |
|----------|---------|------------------|----------|
| GeoLite2 City | city-level geolocation | `GeoLite2-City.mmdb` next to `server.py` | [MaxMind (free)](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) |
| GeoLite2 ASN | ASN/ISP information | `GeoLite2-ASN.mmdb` | [MaxMind (free)](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) |
| IP2Proxy PX12 | proxy/VPN detection (optional) | `IP2PROXY-LITE-PX12.BIN` | [IP2Location LITE](https://www.ip2location.com/database/ip2proxy) |

Databases and the model are **not** distributed with this repository: place them next to
`server.py` (the server looks there first, then in `D:\geoip` on Windows, and finally at
the path from `LGEOIP_*` variables).

Without the IP2Proxy database or package the server still runs, `ip2proxy_*` features stay
`0`, and `/check` reports the exact reason in `databases.ip2proxy_reason`.

### 2. AI model (optional)

```bash
git clone https://github.com/tutuurg/lgeoai.git
cp lgeoai/lgeoai_model.onnx .
```

`lgeoai.py` is included here and is API-compatible with the model from the AI repository.

### 3. Configuration (environment variables, no code editing)

Nothing has to be edited in the source: every path, limit and mode is configurable.

```bash
export LGEOIP_CITY_DB=/srv/geoip/GeoLite2-City.mmdb
export LGEOIP_ASN_DB=/srv/geoip/GeoLite2-ASN.mmdb
export LGEOIP_ALLOWED_ORIGINS=https://yourname.github.io
export LGEOIP_FRONTEND_URL=https://yourname.github.io/lgeoip/
```

```powershell
# Windows
$env:LGEOIP_ALLOWED_ORIGINS = "https://yourname.github.io"
```

### 4. Run

```bash
python server.py                 # normal start (settings from the environment)
python server.py --check-config  # print configuration and exit (diagnostics)
python server.py --console       # server + admin console in the same window
python server.py --console-only  # admin console only (separate window)
python server.py --host 0.0.0.0 --port 88
```

Default address is `http://127.0.0.1:88` (see [Security model](#security-model) if you need
LAN access or a tunnel).

## Configuration reference

All variables use the `LGEOIP_` prefix. Defaults are shown in parentheses.

| Variable | Default | Meaning |
|----------|---------|---------|
| `LGEOIP_CITY_DB` | next to script / `D:\geoip\GeoLite2-City.mmdb` | GeoLite2 City database |
| `LGEOIP_ASN_DB` | next to script / `D:\geoip\GeoLite2-ASN.mmdb` | GeoLite2 ASN database |
| `LGEOIP_PROXY_DB` | next to script / `D:\geoip\IP2PROXY-LITE-PX12.BIN` | IP2Proxy database |
| `LGEOIP_KNOWN_ASNS` | next to script / `D:\geoip\known_asns.json` | ASN list (created/edited by the console) |
| `LGEOIP_TOR_CACHE` | next to script / `D:\geoip\tor_exit_cache.json` | Tor exit-list cache |
| `LGEOIP_MODEL` | `lgeoai_model.onnx` next to script | ONNX model |
| `LGEOIP_TRAIN_LOG` | `ai_training_data.jsonl` next to script | feature samples for training |
| `LGEOIP_STATIC_DIR` | `static/` or `D:\geoip\files` | directory served under `/static` |
| `LGEOIP_STATIC_PREFIX` | `/static` | mount prefix for assets |
| `LGEOIP_STATIC_ALIAS_PREFIX` / `LGEOIP_STATIC_ALIAS_DIR` | `/static/files` → same dir | backward-compatible asset path |
| `LGEOIP_HOST` / `LGEOIP_PORT` | `127.0.0.1` / `88` | listen address |
| `LGEOIP_FRONTEND_URL` | `https://tutuurg.github.io/lgeoip/` | target of the `GET /` redirect |
| `LGEOIP_ACCESS_MODE` | `origin` | `origin` \| `token` \| `open` |
| `LGEOIP_ALLOWED_ORIGINS` | `https://tutuurg.github.io` | comma-separated Origin/Referer allowlist |
| `LGEOIP_API_TOKEN` | empty | shared token for `token` mode (`X-API-Token` header or `?token=`) |
| `LGEOIP_ALLOW_DIRECT_LOCAL` | `1` | allow direct local requests without Origin |
| `LGEOIP_ALLOWED_IPS` | empty | extra allowed clients (IP or CIDR, comma-separated) |
| `LGEOIP_TRUST_PROXY` | `0` | trust `X-Forwarded-For` / `X-Real-IP` |
| `LGEOIP_RATE_LIMIT_PER_MINUTE` | `200` | per-key limit (key = Origin, else IP) |
| `LGEOIP_RATE_LIMIT_BURST` | `60` | token-bucket size |
| `LGEOIP_RATE_LIMIT_GLOBAL_PER_MINUTE` | `1200` | process-wide limit |
| `LGEOIP_REVERSE_DNS` | `1` | enable reverse DNS |
| `LGEOIP_REVERSE_DNS_TIMEOUT` | `3.0` | per-lookup timeout, seconds |
| `LGEOIP_REVERSE_DNS_TTL` | `3600` | positive cache TTL (negative: 300 s) |
| `LGEOIP_REVERSE_DNS_WORKERS` | `4` | concurrent lookups |
| `LGEOIP_REVERSE_DNS_THIRD_PARTY` | `1` | run rDNS for third-party IPs |
| `LGEOIP_TOR_BACKGROUND` | `1` | background Tor list refresh |
| `LGEOIP_TOR_INTERVAL` | `3600` | refresh interval, seconds |
| `LGEOIP_TOR_SOURCES` | torproject, dan.me.uk | comma-separated sources, first working wins |
| `LGEOIP_TOR_MIN_SIZE` | `100` | reject suspiciously short lists |
| `LGEOIP_AI_ENABLED` | `1` | load the model |
| `LGEOIP_AI_VALIDATE` | `1` | check model usefulness at startup |
| `LGEOIP_AI_REDUNDANCY_MAE` | `0.02` | “model just repeats the heuristic” threshold |
| `LGEOIP_AI_HEURISTIC_WEIGHT` | `0.7` | heuristic share in the blend |
| `LGEOIP_LOG_SAMPLES` | `1` | write feature samples (never IPs) for training |
| `LGEOIP_LOG_SAMPLES_MAX_MB` | `32` | log rotation threshold |
| `LGEOIP_LOG_LEVEL` | `INFO` | logging level |
| `LGEOIP_ADMIN_CONSOLE` | `auto` | `auto` \| `on` \| `off` |

## API Endpoints

### `GET /json` – main IP analysis

| Parameter | Type | Description |
|-----------|------|-------------|
| `ip` | string | IP to analyse (optional; defaults to the client IP). Invalid values → `400` |
| `tz` | string | browser timezone, IANA name (`Europe/Moscow`) |
| `ai_mode` | boolean | request AI refinement (applied only if the model is useful) |

```bash
curl "http://127.0.0.1:88/json"
curl "http://127.0.0.1:88/json?ip=8.8.8.8&tz=America/New_York"
curl "http://127.0.0.1:88/json?ip=89.187.179.58&tz=Europe/Minsk&ai_mode=true"
```

**Response** (`GET /json?ip=89.187.179.58&tz=Europe/Minsk&ai_mode=true`):

```json
{
  "ip": "89.187.179.58",
  "country": "United States",
  "country_iso": "US",
  "city": "New York",
  "region": "New York",
  "postal_code": "10118",
  "latitude": 40.7126,
  "longitude": -74.0066,
  "timezone": "America/New_York",
  "isp": "Datacamp Limited",
  "asn": 60068,
  "network": "89.187.160.0/19",
  "source": "query_param",
  "browser_timezone": "Europe/Minsk",
  "timezone_match": false,
  "anonymization_probability": 100,
  "heuristic_probability": 100,
  "anonymization_reasons": [
    "Known hosting/VPN ASN: IPVanish",
    "Timezone mismatch: browser Europe/Minsk vs IP America/New_York (delta +8.0h, offset mismatch)"
  ],
  "ai_available": true,
  "ai_mode_requested": true,
  "ai_applied": false,
  "ai_status": "redundant",
  "ai_probability": 98.6
}
```

Field semantics:

* `anonymization_probability` – final score (0–100).
* `heuristic_probability` – score before the AI blend (also capped at 100).
* `ai_status` – `ready` (model is useful), `redundant` (model merely reproduces the
  heuristic and is therefore **not** applied), `invalid`, `unavailable`.
* `ai_applied` – `true` only when `ai_mode=true` and the model was actually blended in.
* `ai_probability` – raw model output in percent (exposed for transparency/diagnostics).
* `sample_id` – present when `LGEOIP_LOG_SAMPLES=1`; use it with `POST /feedback`.

### `GET /check` – status and diagnostics

```bash
curl "http://127.0.0.1:88/check"
```

`status` keeps the classic `online:HH:MM:SS` string for existing monitors; additional
fields report databases, Tor cache, reverse-DNS cache, AI state, ASN count and access mode.

### `GET /health` – compact health probe

```json
{"ok": true, "uptime_seconds": 42, "tor_ips": 9732, "ai_status": "redundant",
 "requests": {"total_requests": 12, "json_requests": 9}}
```

### `POST /feedback` – store a real label (improves the model)

```bash
curl -X POST "http://127.0.0.1:88/feedback" \
     -H "Content-Type: application/json" \
     -d '{"sample_id": "815d8b6b1c3944fcbce9b306c4f41151", "label": "vpn", "note": "user confirmed"}'
```

`label` accepts a number in `[0, 1]` or `clean` / `no` / `false` / `vpn` / `proxy` / `anon` /
`yes` / `true`. Labels are appended to `<training log>.feedback.jsonl` and used by
`train_model.py`.

### `GET /` – redirect

Redirects (`302`) to `LGEOIP_FRONTEND_URL`.

All responses carry `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`,
`Referrer-Policy` and `Cache-Control: no-store`.

## Admin Console

```bash
python server.py --console        # together with the server
python server.py --console-only   # separate window/process
python -c "import server; server.admin_console()"
```

| Command | Description |
|---------|-------------|
| `stats` | uptime, database/Tor/AI/request summary |
| `health` | machine-readable state (databases, caches, AI, access) |
| `requests` | request counters and rate-limit rejections |
| `ai` | AI status, samples collected, hints for retraining |
| `access` | access mode, allowed origins, limits |
| `asn_stats`, `list_asn`, `search_asn <term>` | ASN database views |
| `add_asn <num> <desc>`, `remove_asn <num>` | edit the ASN database (file-locked, merge-safe) |
| `reload_asn` | re-read `known_asns.json` |
| `update_tor`, `tor_status` | refresh / inspect the Tor exit list |
| `clear`, `help`, `exit` | UI helpers |

Writes to `known_asns.json` are guarded by a cross-process file lock and re-merge the file,
so a second console (or the running server) cannot silently overwrite your edits.

## AI model integration

The AI part is **optional and gated**: it is only used when it demonstrably adds
information beyond the heuristics.

`lgeoai.py` is mirrored from the [lgeoai repository](https://github.com/tutuurg/lgeoai) so
that this server runs from a plain `git clone`; if you change the feature contract, update
both repositories together (the model metadata and `FEATURE_KEYS` must match).

### How it works

1. The heuristics produce `heuristic_probability` (capped at 100).
2. 12 normalised features are extracted (`lgeoai.extract_features`).
3. If `ai_mode=true` **and** the model is validated as useful, the final score is
   `heuristic × LGEOIP_AI_HEURISTIC_WEIGHT + AI × 100 × (1 − weight)` (default 70/30).
4. `ai_status`, `ai_applied`, `ai_probability` are returned for transparency.

### Validation and the `redundant` state

`lgeoai.py` checks at startup whether the model merely reproduces the
`heuristic_probability` input:

* with a training log available it computes the MAE between the model output and that
  feature (`LGEOIP_AI_REDUNDANCY_MAE`, default `0.02`);
* without a log it uses synthetic probes (several feature patterns with the target
  feature forced to `0` and `1`).

If the model is redundant it is reported as `ai_status: "redundant"` and **never blended**,
so `ai_mode=true` cannot silently degrade results. The model is still loaded, and
`ai_probability` remains visible for diagnostics.

This is not theoretical: the previously published model scored MAE `0.0002` against the
heuristic on the project's own training log (the target was literally fed in as an input
feature), i.e. `ai_mode` changed nothing. `train_model.py` now refuses to reproduce that
mistake.

### Features used (exact order)

```
is_tor, has_suspicious_hostname, ip2proxy_proxy, ip2proxy_datacenter, hosting_isp,
known_vpn_asn, timezone_mismatch, tz_offset_hours, hostname_entropy, reasons_count,
hosting_and_tz_mismatch, heuristic_probability
```

All values are clamped to `[0, 1]`; `tz_offset_hours` is normalised by 12. The order and
normalisation are a **frozen contract** — changing them requires retraining.

### Training an honest model

```bash
python train_model.py --check          # inspect available data
python train_model.py                  # train on real labels from POST /feedback
python train_model.py --target heuristic --allow-distill --out lgeoai_model_distill.onnx
```

* `--target feedback` (default) requires ≥ 50 real labels and **excludes**
  `heuristic_probability` from the inputs (no target leakage).
* `--target heuristic --allow-distill` builds a distillation model: it cannot be more
  accurate than the heuristic itself, and the script says so, comparing the model MAE
  against the “just use the heuristic” baseline.
* Exported models carry metadata (`features`, `target`, `mae`, `r2`, `samples`,
  `trained_at`); the server reads the feature list from there and validates the input
  dimension, so a mismatched model is rejected instead of producing silent nonsense.
* `--jobs 1` forces single-threaded training for constrained environments.

### Sample collection & feedback loop

With `LGEOIP_LOG_SAMPLES=1` (default) every `/json` call appends one JSON line with the
**features and probabilities only — never the IP address or hostname**, and returns
`sample_id`. Frontends can post a user verdict to `POST /feedback`; labels are joined to
samples by `sample_id` during training. The active log is rotated at
`LGEOIP_LOG_SAMPLES_MAX_MB`.

## Security model

* **Origin allowlist.** `LGEOIP_ALLOWED_ORIGINS` is enforced for every request (CORS alone
  is not protection against non-browser clients). Requests without a matching
  `Origin`/`Referer` are rejected with `403`.
* **Token mode.** `LGEOIP_ACCESS_MODE=token` + `LGEOIP_API_TOKEN=…` requires
  `X-API-Token: …` (or `?token=…`) on every request — recommended when the service is
  exposed through a tunnel or reverse proxy.
* **Direct local access.** `LGEOIP_ALLOW_DIRECT_LOCAL=1` allows loopback clients without an
  `Origin` header, but only when the request carries no proxy headers
  (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`, …), so tunnelled clients cannot use it.
* **Rate limiting.** Token bucket per key (Origin, else client IP) plus a process-wide
  bucket; exceeded requests get `429` with a `Retry-After`-style message. Enable
  `LGEOIP_TRUST_PROXY=1` behind a trusted reverse proxy to limit per real client IP.
* **No data exposure via /static.** Only `LGEOIP_STATIC_DIR` is mounted, and the server
  refuses to mount a directory that contains the databases — previously `/static` served
  the whole deployment folder, including `.mmdb`/`.BIN` files and `known_asns.json`.
* **Bind address.** The default is `127.0.0.1`. Use `LGEOIP_HOST=0.0.0.0` deliberately and
  restrict access with a firewall and/or token mode.
* **Privacy.** Logs and statistics only contain masked IPs (`**.***.**.77`); training
  samples contain no IPs at all.
* **Robustness.** Blocking work (reverse DNS, Tor list download) never runs in the event
  loop; reverse DNS is cached and time-bounded; the Tor list is validated (IP-format check,
  minimum length) before it replaces the cache.

## Testing

```bash
python -m unittest discover -s tests -v
```

43 tests cover feature extraction and clamping, IP masking/normalisation, the rate limiter,
Tor list parsing/caching, reverse-DNS cache/timeout, ASN file locking, AI model validation
(including the redundancy gate), the detector (including “cap before blend”), access
control modes, and the HTTP API contract — including a regression test that databases are
**not** reachable through `/static`.

```bash
# quick manual checks
curl "http://127.0.0.1:88/health"
curl "http://127.0.0.1:88/json?ip=$(curl -s ifconfig.me)"
curl "http://127.0.0.1:88/json?ip=8.8.8.8&ai_mode=true"
curl "http://127.0.0.1:88/check"
```

## Changelog

### 2.1

* **Security:** real access control (origin allowlist / token / limits) instead of
  `return True`; `/static` no longer exposes the database directory; `127.0.0.1` by default.
* **Correctness:** probability is capped at 100 *before* the AI blend (previously sums up to
  284 were blended); DST-aware timezone comparison via `zoneinfo` (no `pytz`); IPv4-mapped
  IPv6 and invalid `ip` parameters handled explicitly; `known_asns.json` writes are
  file-locked and merge-safe.
* **Performance:** endpoints run in FastAPI's threadpool; reverse DNS is cached and
  time-bounded; the Tor list is refreshed by a background thread instead of inside requests.
* **AI:** target leakage removed in `train_model.py`; model metadata (`features`, metrics);
  startup validation with a `redundant` state; `POST /feedback` + sample IDs for honest
  retraining; `ai_probability`, `ai_applied`, `ai_status` exposed in the API.
* **Operations:** all settings via `LGEOIP_*` environment variables; `--check-config`;
  in-process admin console with new `ai`/`health`/`access` commands; `logging` instead of
  `print`; training-log rotation; `/health` endpoint.
* **Frontend compatibility:** the `GET /json` response keeps every field the web interface
  reads; new fields are additive.

## Limitations

1. **Database accuracy** – geolocation depends on MaxMind freshness (update monthly).
2. **VPN detection** – no system detects every VPN with 100 % accuracy.
3. **AI model** – not included; as discussed above, a model that only reproduces the
   heuristic is detected and ignored.
4. **IP2Proxy** – optional; without the package and database those signals stay `0`.
5. **Single process** – state (ASN list, Tor cache, statistics, rate limiter) lives in
   memory; running multiple workers is not supported.
6. **Legal compliance** – ensure compliance with data protection regulations.
7. **Commercial use** – MaxMind GeoLite2 is for non-commercial use only.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please run `python -m unittest discover -s tests` before submitting.

## License
```text
MIT License

Copyright (c) 2026 Cookie:3 (tutuurg) (https://github.com/tutuurg)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Support

For issues, feature requests, or questions:
1. Check [existing GitHub issues](https://github.com/tutuurg/lgeoip/issues)
2. Test with the live frontend interface
3. Send detailed bug reports with examples to zazagog.krt@gmail.com
