# lgeoip - IP Geolocation & Anonymization Detection Server

## Overview

lgeoip is a high-precision IP address analysis service that reveals true geolocation while detecting VPNs, proxies, Tor nodes, and hosting providers with industry-leading accuracy. The system combines multiple data sources and advanced heuristics to provide detailed insights about any IP address.

Unlike basic geolocation services, lgeoip specializes in **identifying anonymization techniques** by analyzing:
- IP geolocation (country, region, city with coordinates)
- Autonomous System Number (ASN) and provider analysis
- Tor network membership
- Proxy and VPN detection
- Hostname analysis via reverse DNS
- Timezone discrepancy analysis

Theis repository consists of a **FastAPI backend server**  and a **frontend interface** available via GitHub Pages.

## Current Status

**Backend Server**: `server.py` - A Python FastAPI application for IP analysis

**Frontend Interface**: (https://tutuurg.github.io/lgeoip/) - The live web interface (HTML file located in this repository)

## Features

### Core Capabilities
- **Precise Geolocation**: Country, region, city, postal code, and coordinates (up to 4 decimal places)
- **Anonymization Detection**: Probability scoring for VPN/Proxy/Tor usage
- **ISP Analysis**: Provider identification and classification
- **Time Zone Analysis**: Browser vs. IP timezone comparison
- **Multi-Source Verification**: Combines MaxMind, IP2Proxy, and Tor Project data
- **ASN Intelligence**: Auto-updating database of hosting providers and data centers

### Detection Methods
1. **Tor Exit Node Verification**: Real-time checking against Tor Project's bulk exit list
2. **Proxy Detection**: Integration with IP2Proxy database
3. **ASN Analysis**: Custom database of 130+ known hosting/VPN ASNs
4. **Hostname Analysis**: Reverse DNS lookup with suspicious keyword detection
5. **Timezone Discrepancy**: Browser vs. geolocation timezone comparison
6. **ISP Name Heuristics**: Detection of hosting/datacenter keywords in provider names

## Architecture

### Backend Components
- **FastAPI Server**: RESTful API with CORS security
- **MaxMind Integration**: GeoLite2 City and ASN databases
- **IP2Proxy Integration**: Optional proxy detection
- **Tor Network Monitoring**: Hourly updates from Tor Project
- **Admin Console**: Built-in management interface
- **Auto-learning System**: Automatically adds suspicious ASNs to database

### API Endpoints
- `GET /json` - Main IP analysis endpoint
- `GET /check` - Server status monitoring
- `GET /` - Redirects to frontend interface

## Installation & Setup

### Prerequisites
```bash
pip install fastapi uvicorn geoip2 pytz requests
pip install IP2Proxy  # Optional: for enhanced proxy detection
```

### Configuration
1. **Download Required Databases**:
   - [GeoLite2 City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
   - [GeoLite2 ASN](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
   - [IP2Proxy](https://www.ip2location.com/database/ip2proxy) (Optional)

2. **Update Paths in `server.py`** (Lines 20-24):
```python
CITY_DB_PATH = "path/to/GeoLite2-City.mmdb"
ASN_DB_PATH = "path/to/GeoLite2-ASN.mmdb"
PROXY_DB_PATH = "path/to/IP2PROXY-LITE-PX12.BIN"  # Optional
KNOWN_ASNS_PATH = "path/to/known_asns.json"
```

3. **Configure Security Settings**:
   - Update CORS `allow_origins` (line 92)
   - Configure frontend redirect URL (line 354)
   - Update domain verification in `check_request_allowed()` function

### Running the Server
```bash
python server.py
```
Server starts at: `http://localhost:88`

### Admin Console
For server management, open a new terminal and run:
```bash
python -c "import server; server.advanced_admin_console()"
```

## API Usage

### Basic IP Lookup
```bash
curl "http://localhost:88/json?tz=Europe/Moscow"
```

### Specific IP Analysis
```bash
curl "http://localhost:88/json?ip=8.8.8.8&tz=America/New_York"
```

### Response Format
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
    "Timezone offset mismatch: browser Europe/Minsk (3:00:00), IP America/New_York (-1 day, 19:00:00)"
  ]
}
```

## Detection Examples

### Regular Connection
- **Anonymization Probability**: 0%
- **Timezone Match**: True
- **ISP**: Legitimate residential/mobile provider
- **ASN**: Not in known hosting/VPN database

### VPN/Proxy Detected
- **Anonymization Probability**: 85-100%
- **Timezone Match**: False (typically)
- **ISP**: Contains hosting/datacenter keywords
- **ASN**: Found in known hosting/VPN database
- **Proxy Detection**: IP2Proxy flags as proxy

### Tor Exit Node
- **Anonymization Probability**: 90%+
- **IP Found**: In Tor Project exit node list
- **Hostname**: Contains "tor", "exit", or "relay"

## Security Features

- **CORS Protection**: Only allows requests from configured domains
- **IP Masking**: Logs show masked IPs for privacy
- **Request Validation**: Origin and Referer header verification
- **Security Headers**: XSS protection, content type options, frame denial
- **Rate Limiting**: Built-in request statistics and monitoring

## Admin Console Commands

| Command | Description |
|---------|-------------|
| `stats` | Server runtime and database statistics |
| `requests` | API request metrics and traffic analysis |
| `list_asn` | Display known ASN database |
| `add_asn <num> <desc>` | Manually add ASN to database |
| `search_asn <term>` | Search ASN descriptions |
| `update_tor` | Refresh Tor exit node list |
| `reload_asn` | Reload ASN database from file |

## Database Management

The system maintains a JSON database of known VPN/hosting ASNs (`known_asns.json`) that:
- Auto-learns from high-probability detections
- Can be manually curated via admin console
- Persists between server restarts

## Integration with Frontend

The backend is designed to work with the frontend:
- **Live Site**: [https://tutuurg.github.io/lgeoip/](https://tutuurg.github.io/lgeoip/)
- **Communication**: Frontend makes AJAX calls to backend `/json` endpoint
- **Configuration**: Ensure CORS settings match your deployment URL

## Performance

- **Response Time**: Typically < 300ms for complete analysis
- **Database Lookups**: Local MaxMind databases (no external API calls)
- **Concurrency**: FastAPI async support for multiple simultaneous requests
- **Uptime Monitoring**: Built-in `/check` endpoint for health monitoring

## Limitations & Considerations

1. **Database Accuracy**: Geolocation accuracy depends on MaxMind database freshness
2. **VPN Detection**: No service can detect all VPNs with 100% accuracy
3. **Legal Compliance**: Ensure compliance with data protection regulations in your jurisdiction
4. **Resource Usage**: GeoIP databases require several GB of disk space
5. **Commercial Use**: MaxMind GeoLite2 is for non-commercial use; commercial applications require a license

## Testing

Test the service by:
1. Accessing the frontend interface
2. Testing with your regular connection
3. Testing with VPN enabled
4. Testing with Tor browser
5. Comparing timezone matches

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## License
```text
MIT License

Copyright (c) 2026 Zakhar Lasitski

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
1. Check the existing GitHub issues
2. Review the configuration documentation
3. Test with the live frontend interface
4. Send detailed bug reports with examples to zazagog.krt@gmail.com