# lgeoip - IP Geolocation & Anonymization Detection Server

## Overview

**lgeoip** is a high-precision IP address analysis service that reveals true geolocation while detecting VPNs, proxies, Tor nodes, and hosting providers. The system combines multiple data sources, advanced heuristics, and **optional AI refinement** to provide detailed insights about any IP address.

Unlike basic geolocation services, lgeoip specializes in **identifying anonymization techniques** by analyzing:
- IP geolocation (country, region, city with coordinates)
- Autonomous System Number (ASN) and provider analysis
- Tor network membership (real-time bulk list)
- Proxy and VPN detection (IP2Proxy integration)
- Hostname analysis via reverse DNS
- Timezone discrepancy analysis (browser vs. IP)
- **AI-powered probability refinement** (optional)

## Repository Structure

| Component | Location | Description |
|-----------|----------|-------------|
| **Backend Server** | `server.py` | FastAPI application for IP analysis |
| **Frontend Interface** | [GitHub Pages](https://tutuurg.github.io/lgeoip/) | Live web interface |
| **AI Model** | [lgeoai repository](https://github.com/tutuurg/lgeoai) | ONNX model for probability refinement |

## Features

### Core Capabilities
- **Precise Geolocation**: Country, region, city, postal code, coordinates (4 decimal places)
- **Anonymization Detection**: Probability scoring (0-100%) for VPN/Proxy/Tor usage
- **ISP Analysis**: Provider identification and classification
- **Time Zone Analysis**: Browser vs. IP timezone comparison with mismatch detection
- **Multi-Source Verification**: Combines MaxMind, IP2Proxy, and Tor Project data
- **ASN Intelligence**: Auto-updating database of 130+ hosting/VPN providers
- **AI Refinement**: Optional ONNX model for enhanced detection accuracy

### Detection Methods
1. **Tor Exit Node Verification**: Real-time checking against Tor Project's bulk exit list
2. **Proxy Detection**: IP2Proxy database integration (supports PX12 format)
3. **ASN Analysis**: Custom database with auto-learning capabilities
4. **Hostname Analysis**: Reverse DNS lookup with suspicious keyword detection
5. **Timezone Discrepancy**: Browser vs. geolocation timezone comparison
6. **ISP Name Heuristics**: Detection of hosting/datacenter keywords
7. **AI Inference** (optional): ONNX model refinement (70% heuristic + 30% AI)

## Installation & Setup

### Prerequisites

```bash
pip install fastapi uvicorn geoip2 pytz requests
pip install IP2Proxy  # Optional: for enhanced proxy detection
```

### 1. Download Required Databases

| Database | Purpose | Download Link |
|----------|---------|---------------|
| GeoLite2 City | City-level geolocation | [MaxMind (free)](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) |
| GeoLite2 ASN | ASN/ISP information | [MaxMind (free)](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) |
| IP2Proxy PX12 | Proxy/VPN detection | [IP2Location (free LITE)](https://www.ip2location.com/database/ip2proxy) |

### 2. Download AI Model (Optional)

```bash
# Download from separate repository
git clone https://github.com/tutuurg/lgeoai.git
# Place lgeoai_model.onnx in the same directory as server.py
cp lgeoai/lgeoai_model.onnx .
```

### 3. Configure Database Paths

Edit `server.py` lines 20-24:

```python
CITY_DB_PATH = "GeoLite2-City.mmdb"      # Update with your path
ASN_DB_PATH = "GeoLite2-ASN.mmdb"        # Update with your path
PROXY_DB_PATH = "IP2PROXY-LITE-PX12.BIN" # Optional
KNOWN_ASNS_PATH = "known_asns.json"      # Auto-created
```

### 4. Configure Security Settings

Update CORS origins in `server.py` (line 92):

```python
allow_origins=["https://yourdomain.github.io"]  # Change to your frontend URL
```

Update redirect URL in `server.py` (line 354):

```python
return RedirectResponse(url="https://yourdomain.github.io/geoip-client/")
```

### 5. Run the Server

```bash
python server.py
```

Server starts at: `http://localhost:88`

## API Endpoints

### `GET /json` - Main IP Analysis

**Parameters:**
| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `ip` | string | IP address to analyze (optional, defaults to client IP) | `?ip=8.8.8.8` |
| `tz` | string | Browser timezone (IANA format) | `?tz=Europe/Moscow` |
| `ai_mode` | boolean | Enable AI refinement (requires model) | `?ai_mode=true` |

**Examples:**

```bash
# Analyze your own IP
curl "http://localhost:88/json"

# Analyze specific IP with timezone
curl "http://localhost:88/json?ip=8.8.8.8&tz=America/New_York"

# Enable AI refinement
curl "http://localhost:88/json?ip=89.187.179.58&tz=Europe/Minsk&ai_mode=true"
```

**Response Format:**

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
  "anonymization_reasons": [
    "Known hosting/VPN ASN: IPVanish",
    "Timezone offset mismatch: browser Europe/Minsk (+3:00), IP America/New_York (-5:00)"
  ],
  "ai_available": true,
  "ai_mode_requested": true
}
```

### `GET /check` - Health Check

```bash
curl "http://localhost:88/check"
```

Response: `{"status": "online:00:05:23"}` (uptime in HH:MM:SS)

### `GET /` - Redirect

Redirects to frontend interface (configured URL)

## Admin Console

Run in separate terminal:

```bash
python -c "import server; server.admin_console()"
```

### Available Commands

| Command | Description |
|---------|-------------|
| `stats` | Server uptime and database statistics |
| `asn_stats` | Detailed ASN database info |
| `requests` | API request metrics and traffic analysis |
| `list_asn` | Display known ASN database (first 20 entries) |
| `add_asn <num> <desc>` | Manually add ASN to database |
| `remove_asn <num>` | Remove ASN from database |
| `search_asn <term>` | Search ASN descriptions |
| `update_tor` | Refresh Tor exit node list |
| `reload_asn` | Reload ASN database from file |
| `clear` | Clear screen |
| `help` | Show all commands |

## AI Model Integration

The server supports optional AI refinement via an ONNX model stored in a **[separate repository](https://github.com/tutuurg/lgeoai)**.

### How AI Mode Works

1. **Heuristic probability** is calculated (0-100%) using 6 detection methods
2. **AI model** processes the same features independently
3. **Final probability** = `(heuristic × 0.7) + (AI × 100 × 0.3)`
4. Results include `"ai_available": true` and AI reason in `anonymization_reasons`

### AI Features Used

- Heuristic probability (normalized)
- Timezone match status
- Tor exit node flag
- Suspicious hostname flag
- IP2Proxy proxy flag
- IP2Proxy datacenter flag
- Hosting ISP flag
- Known VPN ASN flag
- Normalized timezone offset

### Requirements for AI Mode

1. Download `lgeoai_model.onnx` from [lgeoai repository](https://github.com/tutuurg/lgeoai)
2. Place in same directory as `server.py`
3. Ensure `lgeoai.py` exists (included in repository)
4. Pass `?ai_mode=true` in API requests

## Detection Examples

### Regular Connection (User at home)

```json
{
  "anonymization_probability": 0,
  "anonymization_reasons": ["No signs of anonymization detected"],
  "timezone_match": true
}
```

### VPN Detected

```json
{
  "anonymization_probability": 85,
  "anonymization_reasons": [
    "Known hosting/VPN ASN: M247 Europe",
    "ISP name indicates hosting/datacenter",
    "Timezone offset mismatch: browser +3:00, IP -5:00"
  ],
  "timezone_match": false
}
```

### Tor Exit Node

```json
{
  "anonymization_probability": 95,
  "anonymization_reasons": [
    "IP is known Tor exit node",
    "Known hosting/VPN ASN: Tor Project",
    "Suspicious hostname: tor-exit-node-01"
  ]
}
```

## Auto-Learning System

The server automatically adds ASNs to `known_asns.json` when:

1. Detection probability ≥ 80%
2. ASN not already in database
3. At least one additional indicator present:
   - Hosting keywords in ISP name
   - Suspicious hostname
   - Strong timezone mismatch

This allows the system to improve over time without manual intervention.

## Security Features

- **CORS Protection**: Only allows requests from configured domains
- **IP Masking**: Logs show masked IPs (e.g., `**.***.**.123`) for privacy
- **Request Validation**: Origin and Referer header verification
- **Security Headers**: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection
- **Request Statistics**: Built-in monitoring and rate limiting awareness

## Limitations

1. **Database Accuracy**: Geolocation depends on MaxMind freshness (update monthly)
2. **VPN Detection**: No system detects all VPNs with 100% accuracy
3. **AI Model**: Requires separate download (not included in this repo)
4. **Legal Compliance**: Ensure compliance with data protection regulations
5. **Commercial Use**: MaxMind GeoLite2 is for non-commercial use only

## Testing the Service

```bash
# Local test
curl "http://localhost:88/json"

# With VPN enabled (compare results)
curl "http://localhost:88/json?ip=$(curl -s ifconfig.me)"

# With AI mode
curl "http://localhost:88/json?ai_mode=true"

# Check server health
curl "http://localhost:88/check"
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

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
