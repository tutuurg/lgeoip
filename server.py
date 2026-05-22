#GitHub version
import geoip2.database
from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import uvicorn
import pytz
from datetime import datetime
import socket
import requests
import json
import threading
from lgeoai import LgeoAI

# Server start time
server_start_time = datetime.now()

# Database paths
CITY_DB_PATH = "GeoLite2-City.mmdb"
ASN_DB_PATH = "GeoLite2-ASN.mmdb"
PROXY_DB_PATH = "IP2PROXY-LITE-PX12.BIN"
KNOWN_ASNS_PATH = "known_asns.json"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Initialize readers
city_reader = geoip2.database.Reader(CITY_DB_PATH)
asn_reader = geoip2.database.Reader(ASN_DB_PATH)

# IP2Proxy initialization
proxy_reader = None
if os.path.exists(PROXY_DB_PATH):
    try:
        import IP2Proxy
        proxy_reader = IP2Proxy.IP2Proxy()
        proxy_reader.open(PROXY_DB_PATH)
        print("[INFO] IP2Proxy database loaded")
    except Exception:
        print("[WARN] IP2Proxy database not loaded")

# Known ASN database
known_vpn_asns = {}

def load_known_asns():
    global known_vpn_asns
    if os.path.exists(KNOWN_ASNS_PATH):
        try:
            with open(KNOWN_ASNS_PATH, "r", encoding="utf-8") as f:
                known_vpn_asns = {int(k): v for k, v in json.load(f).items()}
            print(f"[INFO] Loaded {len(known_vpn_asns)} known ASNs")
        except Exception:
            print("[ERROR] Failed to load known_asns.json")
    else:
        print("[WARN] known_asns.json not found")

load_known_asns()

# Initialize AI model
lgeoai = LgeoAI(model_path="lgeoai_model.onnx")

def save_known_asns():
    try:
        with open(KNOWN_ASNS_PATH, "w", encoding="utf-8") as f:
            json.dump({str(k): v for k, v in known_vpn_asns.items()}, f, indent=4, ensure_ascii=False)
        print(f"[INFO] Saved {len(known_vpn_asns)} ASNs to database")
    except Exception:
        print("[ERROR] Failed to save known_asns.json")

# Tor exit nodes
tor_exit_ips = set()
tor_list_last_update = 0
TOR_BULK_URL = "https://www.dan.me.uk/torlist/"

# Request statistics
request_stats = {
    "total_requests": 0,
    "json_requests": 0,
    "root_requests": 0,
    "check_requests": 0,
    "unique_ips": set(),
    "start_time": datetime.now()
}

app = FastAPI(title="GeoIP Server with Anonymization Detection", version="2.0")

# CORS configuration - restrict to specific origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.github.io"],  # Update with your domain
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

def mask_ip(ip: str) -> str:
    """Mask IP address, showing only the last octet"""
    if "." in ip:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"**.***.**.{parts[3]}"
    elif ":" in ip:
        return "****:***:***:****"
    return "****"

def update_tor_exit_list():
    global tor_exit_ips, tor_list_last_update
    now = datetime.now().timestamp()
    if now - tor_list_last_update > 3600:
        try:
            response = requests.get(TOR_BULK_URL, timeout=10)
            if response.status_code == 200:
                tor_exit_ips = set(line.strip() for line in response.text.splitlines() if line.strip())
                tor_list_last_update = now
                print(f"[TOR] List updated: {len(tor_exit_ips)} IPs")
        except Exception:
            pass

def calculate_anonymization_probability(ip_data: dict, browser_timezone: str | None, ai_mode: bool = False) -> dict:
    probability = 0
    reasons = []

    ip = ip_data["ip"]
    ip_timezone = ip_data.get("timezone")
    isp = ip_data.get("isp", "").lower() if ip_data.get("isp") else ""
    asn = ip_data.get("asn")

    timezone_match = False
    mismatch_reason = None
    
    # Flags for AI
    is_tor = False
    suspicious_hostname = False
    ip2proxy_proxy = False
    ip2proxy_dc = False
    hosting_isp = False
    known_vpn_asn_flag = False
    tz_offset = 0

    update_tor_exit_list()

    # 1. Tor exit node
    if ip in tor_exit_ips:
        probability += 90
        reasons.append("IP is known Tor exit node")
        is_tor = True

    # 2. Reverse DNS check
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower()
        suspicious_keywords = ["proxy", "vpn", "tor", "exit", "relay", "datacenter", "cloud", "server", "node", "tunnel"]
        if any(keyword in hostname for keyword in suspicious_keywords):
            probability += 40
            reasons.append(f"Suspicious hostname: {hostname}")
            suspicious_hostname = True
    except Exception:
        pass

    # 3. IP2Proxy
    if proxy_reader:
        try:
            record = proxy_reader.get_all(ip)
            if record.get("is_proxy") == 1:
                probability += 85
                ip2proxy_proxy = True
                proxy_type = record.get("proxy_type")
                if proxy_type and proxy_type.strip() not in ["-", ""]:
                    reasons.append(f"Detected as {proxy_type} proxy (IP2Proxy)")
                else:
                    reasons.append("Detected as proxy (IP2Proxy)")

            usage_type = record.get("usage_type")
            if usage_type and "dch" in usage_type.lower():
                probability += 30
                ip2proxy_dc = True
                reasons.append("Datacenter/hosting IP (IP2Proxy)")

            threat = record.get("threat")
            if threat and threat.strip() not in ["-", ""]:
                probability += 20
                reasons.append(f"Threat detected: {threat}")

            provider = record.get("provider")
            if provider and provider.strip() not in ["-", ""]:
                reasons.append(f"Proxy provider: {provider}")
        except Exception:
            pass

    # 4. ISP/ASN heuristics
    hosting_keywords = ["hosting", "datacenter", "cloud", "server", "vps", "dedicated", "colocation"]
    if any(keyword in isp for keyword in hosting_keywords):
        probability += 50
        hosting_isp = True
        reasons.append("ISP name indicates hosting/datacenter")

    if asn in known_vpn_asns:
        probability += 99
        known_vpn_asn_flag = True
        reasons.append(f"Known hosting/VPN ASN: {known_vpn_asns[asn]}")

    # 5. Timezone check
    if browser_timezone and ip_timezone:
        try:
            browser_tz = pytz.timezone(browser_timezone)
            ip_tz = pytz.timezone(ip_timezone)

            now = datetime.now()
            browser_offset = browser_tz.utcoffset(now)
            ip_offset = ip_tz.utcoffset(now)

            if browser_offset == ip_offset:
                timezone_match = True
            else:
                probability += 55
                if browser_offset and ip_offset:
                    tz_offset = (browser_offset.total_seconds() - ip_offset.total_seconds()) / 3600
                mismatch_reason = f"Timezone offset mismatch: browser {browser_timezone} ({browser_offset}), IP {ip_timezone} ({ip_offset})"
        except pytz.UnknownTimeZoneError:
            if browser_timezone == ip_timezone:
                timezone_match = True
            else:
                probability += 55
                mismatch_reason = f"Timezone string mismatch (unknown zone): browser={browser_timezone}, IP={ip_timezone}"
        except Exception:
            if browser_timezone == ip_timezone:
                timezone_match = True
            else:
                probability += 55
                mismatch_reason = f"Timezone comparison error: fallback to string mismatch"
    else:
        mismatch_reason = "Browser timezone not provided"

    if mismatch_reason:
        reasons.append(mismatch_reason)

    # Auto-learning for ASN detection
    if probability >= 80 and asn and asn not in known_vpn_asns:
        auto_reason = "Auto-detected "
        details = []
        
        if any(keyword in isp for keyword in hosting_keywords):
            details.append("hosting in ISP name")
        if suspicious_hostname:
            details.append("suspicious hostname")
        if mismatch_reason and ("mismatch" in mismatch_reason):
            details.append("strong timezone mismatch")
            
        if details:
            auto_description = auto_reason + ", ".join(details)
            known_vpn_asns[asn] = auto_description
            save_known_asns()

    probability = min(probability, 100)

    if probability == 0:
        reasons = ["No signs of anonymization detected"]

    # AI refinement (inference only, no data collection)
    try:
        if ai_mode and lgeoai.model_available:
            # Extract features for AI inference
            features = [
                0,  # placeholder - implement your feature extraction
                probability / 100,  # normalized heuristic probability
                1 if timezone_match else 0,
                1 if is_tor else 0,
                1 if suspicious_hostname else 0,
                1 if ip2proxy_proxy else 0,
                1 if ip2proxy_dc else 0,
                1 if hosting_isp else 0,
                1 if known_vpn_asn_flag else 0,
                min(max(tz_offset / 12, -1), 1),  # normalized timezone offset
            ]
            
            ai_prob = lgeoai.predict(features)
            if ai_prob is not None:
                # Weight: 70% heuristic, 30% AI
                final_prob = probability * 0.7 + ai_prob * 100 * 0.3
                probability = round(final_prob)
                reasons.append(f"AI refinement: {round(ai_prob * 100)}%")
    except Exception as e:
        print(f"[AI] Error: {e}")

    return {
        "probability": round(probability),
        "reasons": reasons,
        "timezone_match": timezone_match
    }

def lookup_ip(ip: str) -> dict:
    data = {
        "ip": ip,
        "country": None,
        "country_iso": None,
        "city": None,
        "region": None,
        "postal_code": None,
        "latitude": None,
        "longitude": None,
        "timezone": None,
        "isp": None,
        "asn": None,
        "network": None
    }

    try:
        r = city_reader.city(ip)
        data.update({
            "country": r.country.name,
            "country_iso": r.country.iso_code,
            "city": r.city.name,
            "region": r.subdivisions.most_specific.name if r.subdivisions else None,
            "postal_code": r.postal.code,
            "latitude": r.location.latitude,
            "longitude": r.location.longitude,
            "timezone": r.location.time_zone
        })
    except Exception:
        pass

    try:
        r = asn_reader.asn(ip)
        data.update({
            "isp": r.autonomous_system_organization,
            "asn": r.autonomous_system_number,
            "network": str(r.network)
        })
    except Exception:
        pass

    return data

def update_request_stats(endpoint: str, client_ip: str):
    """Update request statistics"""
    request_stats["total_requests"] += 1
    request_stats["unique_ips"].add(client_ip)
    
    if endpoint == "/json":
        request_stats["json_requests"] += 1
    elif endpoint == "/":
        request_stats["root_requests"] += 1
    elif endpoint == "/check":
        request_stats["check_requests"] += 1

@app.get("/json")
async def json_lookup(
    request: Request,
    ip: str | None = Query(default=None, description="IP address to lookup"),
    browser_timezone: str | None = Query(default=None, alias="tz", description="Browser timezone"),
    ai_mode: bool = Query(default=False, alias="ai_mode", description="Enable AI refinement")
):
    client_ip = request.client.host
    target_ip = ip if ip else client_ip
    
    masked_client_ip = mask_ip(client_ip)
    masked_target_ip = mask_ip(target_ip)
    print(f"[JSON] Request from {masked_client_ip}, target IP: {masked_target_ip}, ai_mode={ai_mode}")
    update_request_stats("/json", client_ip)

    try:
        result = lookup_ip(target_ip)
        result["source"] = "query_param" if ip else "client_ip"

        anon_data = calculate_anonymization_probability(result, browser_timezone, ai_mode)
        result.update({
            "browser_timezone": browser_timezone,
            "timezone_match": anon_data["timezone_match"],
            "anonymization_probability": anon_data["probability"],
            "anonymization_reasons": anon_data["reasons"],
            "ai_available": lgeoai.model_available,
            "ai_mode_requested": ai_mode
        })

        return JSONResponse(result)
    except Exception as e:
        print(f"[ERROR] {e}")
        return JSONResponse({"error": "Server error"}, status_code=500)

@app.get("/check")
async def check_status(request: Request):
    uptime = datetime.now() - server_start_time
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    print(f"[CHECK] Status checked, uptime: {uptime_str}")
    update_request_stats("/check", "0.0.0.0")
    
    return {"status": f"online:{uptime_str}"}

@app.get("/")
async def root(request: Request):
    """
    Redirect to the main GeoIP client page
    """
    client_ip = request.client.host
    masked_ip = mask_ip(client_ip)
    print(f"[ROOT] Request from {masked_ip} - redirecting to client page")
    update_request_stats("/", client_ip)
    
    # Update this URL to your actual client page
    return RedirectResponse(url="https://yourdomain.github.io/geoip-client/", status_code=302)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    return response

def admin_console():
    """Simple admin console for server management"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║          GEOIP ADMIN CONSOLE v2.0                        ║
║          Server: http://localhost:88                     ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)
    
    while True:
        try:
            command = input("\n> ").strip().lower()
            
            if command == "":
                continue
                
            elif command in ["help", "?"]:
                print("\nAvailable commands:")
                print("  help, ?       - show this help")
                print("  stats         - server statistics")
                print("  asn_stats     - ASN database statistics")
                print("  requests      - request statistics")
                print("  add_asn <num> <desc> - add ASN to database")
                print("  remove_asn <num> - remove ASN from database")
                print("  list_asn      - list all ASNs")
                print("  search_asn <word> - search ASN by description")
                print("  reload_asn    - reload ASN database")
                print("  update_tor    - update Tor exit node list")
                print("  clear         - clear screen")
                print("  exit, quit    - exit console")
                
            elif command == "stats":
                uptime = datetime.now() - server_start_time
                days = uptime.days
                hours, remainder = divmod(int(uptime.seconds), 3600)
                minutes, seconds = divmod(remainder, 60)
                
                print(f"\n╔════════════════ SERVER STATISTICS ════════════════╗")
                print(f"║ Uptime: {days}d {hours:02d}:{minutes:02d}:{seconds:02d}")
                print(f"║ ASNs in database: {len(known_vpn_asns)}")
                print(f"║ Tor IPs: {len(tor_exit_ips)}")
                print(f"║ IP2Proxy: {'Loaded' if proxy_reader else 'Not loaded'}")
                print(f"╚══════════════════════════════════════════════════════╝")
                
            elif command == "asn_stats":
                if known_vpn_asns:
                    print(f"\nTotal ASNs in database: {len(known_vpn_asns)}")
                    print("Last 10 added:")
                    for asn, desc in list(known_vpn_asns.items())[-10:]:
                        print(f"  ASN {asn}: {desc[:60]}...")
                else:
                    print("ASN database is empty")
                    
            elif command == "requests":
                uptime = datetime.now() - request_stats["start_time"]
                hours, remainder = divmod(int(uptime.total_seconds()), 3600)
                minutes, seconds = divmod(remainder, 60)
                
                print(f"\n╔════════════════ REQUEST STATISTICS ════════════════╗")
                print(f"║ Period: {hours:02d}:{minutes:02d}:{seconds:02d}")
                print(f"║ Total requests: {request_stats['total_requests']}")
                print(f"║  JSON requests: {request_stats['json_requests']}")
                print(f"║  ROOT requests: {request_stats['root_requests']}")
                print(f"║ CHECK requests: {request_stats['check_requests']}")
                print(f"║ Unique IPs: {len(request_stats['unique_ips'])}")
                print(f"║ Avg load: {request_stats['total_requests'] / max(1, uptime.total_seconds() / 60):.2f} req/min")
                print(f"╚══════════════════════════════════════════════════════╝")
                
            elif command.startswith("add_asn "):
                parts = command.split(maxsplit=2)
                if len(parts) < 2:
                    print("Usage: add_asn <ASN_number> [description]")
                    continue
                try:
                    asn = int(parts[1])
                    desc = parts[2] if len(parts) > 2 else "Manually added"
                    known_vpn_asns[asn] = desc
                    save_known_asns()
                    print(f"✓ ASN {asn} added: {desc}")
                except ValueError:
                    print("Error: ASN must be a number")
                    
            elif command.startswith("remove_asn "):
                parts = command.split()
                if len(parts) != 2:
                    print("Usage: remove_asn <ASN_number>")
                    continue
                try:
                    asn = int(parts[1])
                    if asn in known_vpn_asns:
                        del known_vpn_asns[asn]
                        save_known_asns()
                        print(f"✓ ASN {asn} removed from database")
                    else:
                        print(f"ASN {asn} not found in database")
                except ValueError:
                    print("Error: ASN must be a number")
                    
            elif command == "list_asn":
                if known_vpn_asns:
                    print(f"\nTotal ASNs: {len(known_vpn_asns)}")
                    for asn, desc in sorted(known_vpn_asns.items())[:20]:
                        print(f"  {asn}: {desc}")
                    if len(known_vpn_asns) > 20:
                        print(f"  ... and {len(known_vpn_asns) - 20} more entries")
                else:
                    print("ASN database is empty")
                    
            elif command.startswith("search_asn "):
                search_term = command.split(maxsplit=1)[1].lower()
                results = []
                for asn, desc in known_vpn_asns.items():
                    if search_term in desc.lower():
                        results.append((asn, desc))
                
                if results:
                    print(f"\nFound {len(results)} matches:")
                    for asn, desc in results[:10]:
                        print(f"  {asn}: {desc}")
                    if len(results) > 10:
                        print(f"  ... and {len(results) - 10} more entries")
                else:
                    print("No matches found")
                    
            elif command == "reload_asn":
                load_known_asns()
                print("✓ ASN database reloaded")
                
            elif command == "update_tor":
                old_count = len(tor_exit_ips)
                update_tor_exit_list()
                print(f"✓ Tor list updated: {old_count} → {len(tor_exit_ips)} IPs")
                
            elif command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                print(banner)
                
            elif command in ["exit", "quit"]:
                print("Saving data...")
                save_known_asns()
                print("Exiting admin console")
                print("Server continues running")
                break
                
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            print("\n\nExiting admin console")
            print("Server continues running")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          LGEOIP SERVER v2.0                              ║")
    print("║          Server: http://localhost:88                     ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"Database directory: {BASE_DIR}")
    print(f"MaxMind City: {CITY_DB_PATH}")
    print(f"MaxMind ASN: {ASN_DB_PATH}")
    print(f"IP2Proxy PX12: {PROXY_DB_PATH}")
    print(f"Known ASNs: {KNOWN_ASNS_PATH}")
    print("="*60)
    print("To run admin console in a new window:")
    print("1. Open new terminal/command prompt")
    print(f"2. cd {os.path.dirname(os.path.abspath(__file__))}")
    print("3. Run: python -c \"import server; server.admin_console()\"")
    print("="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=88, log_level="error")
