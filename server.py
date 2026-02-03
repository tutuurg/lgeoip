# server.py - FastAPI GeoIP сервер с детекцией анонимизации
# Версия для публикации на GitHub

import geoip2.database
from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import uvicorn
import pytz
from datetime import datetime
import socket
import requests
import json
import time
import threading
import subprocess
import sys

# Время запуска сервера
server_start_time = datetime.now()

# Конфигурация путей (заполните своими путями)
# ПРИМЕЧАНИЕ: Перед запуском укажите правильные пути к файлам баз данных
CITY_DB_PATH = "path/to/GeoLite2-City.mmdb"  # Укажите путь к GeoLite2 City
ASN_DB_PATH = "path/to/GeoLite2-ASN.mmdb"    # Укажите путь к GeoLite2 ASN
PROXY_DB_PATH = "path/to/IP2PROXY-LITE-PX12.BIN"  # Укажите путь к IP2Proxy (опционально)
KNOWN_ASNS_PATH = "path/to/known_asns.json"  # Укажите путь к файлу известных ASN

# Определение базовой директории
BASE_DIR = os.path.dirname(CITY_DB_PATH) if os.path.exists(CITY_DB_PATH) else os.getcwd()

# Инициализация читалок баз данных
city_reader = None
asn_reader = None

# Загрузка GeoIP2 баз данных
try:
    city_reader = geoip2.database.Reader(CITY_DB_PATH)
    print(f"[INFO] GeoLite2-City база загружена: {CITY_DB_PATH}")
except Exception as e:
    print(f"[ERROR] Не удалось загрузить GeoLite2-City: {e}")

try:
    asn_reader = geoip2.database.Reader(ASN_DB_PATH)
    print(f"[INFO] GeoLite2-ASN база загружена: {ASN_DB_PATH}")
except Exception as e:
    print(f"[ERROR] Не удалось загрузить GeoLite2-ASN: {e}")

# Проверка и инициализация IP2Proxy (опционально)
proxy_reader = None
if os.path.exists(PROXY_DB_PATH):
    try:
        import IP2Proxy
        proxy_reader = IP2Proxy.IP2Proxy()
        proxy_reader.open(PROXY_DB_PATH)
        print(f"[INFO] IP2Proxy база загружена: {PROXY_DB_PATH}")
    except ImportError:
        print("[WARN] Библиотека IP2Proxy не установлена. Установите: pip install IP2Proxy")
    except Exception as e:
        print(f"[ERROR] Ошибка загрузки IP2Proxy: {e}")
else:
    print(f"[INFO] IP2Proxy база не найдена: {PROXY_DB_PATH}")

# Глобальная база известных ASN (хосты, VPN, прокси)
known_vpn_asns = {}

def load_known_asns():
    """Загружает базу известных ASN из JSON файла"""
    global known_vpn_asns
    if os.path.exists(KNOWN_ASNS_PATH):
        try:
            with open(KNOWN_ASNS_PATH, "r", encoding="utf-8") as f:
                known_vpn_asns = {int(k): v for k, v in json.load(f).items()}
            print(f"[INFO] Загружено {len(known_vpn_asns)} известных ASN из {KNOWN_ASNS_PATH}")
        except Exception as e:
            print(f"[ERROR] Ошибка загрузки known_asns.json: {e}")
    else:
        print(f"[WARN] Файл known_asns.json не найден: {KNOWN_ASNS_PATH}")
        print("[INFO] Создан пустой словарь известных ASN")

load_known_asns()

def save_known_asns():
    """Сохраняет базу известных ASN в JSON файл"""
    try:
        with open(KNOWN_ASNS_PATH, "w", encoding="utf-8") as f:
            json.dump({str(k): v for k, v in known_vpn_asns.items()}, f, indent=4, ensure_ascii=False)
        print(f"[INFO] Сохранено {len(known_vpn_asns)} ASN в базу")
    except Exception as e:
        print(f"[ERROR] Ошибка сохранения known_asns.json: {e}")

# Глобальные переменные для списка Tor выходных узлов
tor_exit_ips = set()
tor_list_last_update = 0
TOR_BULK_URL = "https://check.torproject.org/torbulkexitlist"

# Статистика запросов сервера
request_stats = {
    "total_requests": 0,
    "json_requests": 0,
    "root_requests": 0,
    "check_requests": 0,
    "unique_ips": set(),
    "start_time": datetime.now()
}

# Инициализация FastAPI приложения
app = FastAPI(title="Local GeoIP Server + Anonymization Detection", version="2.0")

# Настройки CORS - разрешаем только указанный домен
# ИЗМЕНИТЕ: укажите ваш домен вместо example.com
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],  # ИЗМЕНИТЕ: ваш домен
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

# Подключение статических файлов
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")

# Инициализация шаблонов Jinja2
templates = Jinja2Templates(directory=BASE_DIR)

def mask_ip(ip: str) -> str:
    """Маскирует IP адрес для логирования (оставляет только последний октет)"""
    if "." in ip:  # IPv4
        parts = ip.split(".")
        if len(parts) == 4:
            return f"***.***.**.{parts[3]}"
    elif ":" in ip:  # IPv6
        return "****:***:***:****"
    return "****"

def update_tor_exit_list():
    """Обновляет список Tor выходных узлов с torproject.org"""
    global tor_exit_ips, tor_list_last_update
    now = datetime.now().timestamp()
    # Обновляем список каждые 3600 секунд (1 час)
    if now - tor_list_last_update > 3600:
        try:
            response = requests.get(TOR_BULK_URL, timeout=10)
            if response.status_code == 200:
                tor_exit_ips = set(line.strip() for line in response.text.splitlines() if line.strip())
                tor_list_last_update = now
                print(f"[TOR] Список обновлен: {len(tor_exit_ips)} IP")
        except Exception as e:
            print(f"[TOR] Ошибка обновления списка: {e}")

def calculate_anonymization_probability(ip_data: dict, browser_timezone: str | None) -> dict:
    """
    Вычисляет вероятность использования анонимизации (VPN/Proxy/Tor)
    на основе анализа различных параметров IP адреса
    """
    probability = 0
    reasons = []

    ip = ip_data["ip"]
    ip_timezone = ip_data.get("timezone")
    isp = ip_data.get("isp", "").lower() if ip_data.get("isp") else ""
    asn = ip_data.get("asn")

    timezone_match = False
    mismatch_reason = None

    # Обновляем список Tor узлов при необходимости
    update_tor_exit_list()

    # 1. Проверка на Tor выходной узел
    if ip in tor_exit_ips:
        probability += 90
        reasons.append("IP is known Tor exit node")

    # 2. Проверка обратного DNS (hostname)
    suspicious_hostname = False
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower()
        suspicious_keywords = ["proxy", "vpn", "tor", "exit", "relay", 
                               "datacenter", "cloud", "server", "node", "tunnel"]
        if any(keyword in hostname for keyword in suspicious_keywords):
            probability += 40
            reasons.append(f"Suspicious hostname: {hostname}")
            suspicious_hostname = True
    except Exception:
        pass  # Ошибка обратного DNS - не критично

    # 3. Проверка через IP2Proxy (если доступно)
    if proxy_reader:
        try:
            record = proxy_reader.get_all(ip)
            if record.get("is_proxy") == 1:
                probability += 85
                proxy_type = record.get("proxy_type")
                if proxy_type and proxy_type.strip() not in ["-", ""]:
                    reasons.append(f"Detected as {proxy_type} proxy (IP2Proxy)")
                else:
                    reasons.append("Detected as proxy (IP2Proxy)")

            # Проверка типа использования
            usage_type = record.get("usage_type")
            if usage_type and "dch" in usage_type.lower():  # Datacenter/Hosting
                probability += 30
                reasons.append("Datacenter/hosting IP (IP2Proxy)")

            # Проверка угроз
            threat = record.get("threat")
            if threat and threat.strip() not in ["-", ""]:
                probability += 20
                reasons.append(f"Threat detected: {threat}")

            # Информация о провайдере
            provider = record.get("provider")
            if provider and provider.strip() not in ["-", ""]:
                reasons.append(f"Proxy provider: {provider}")
        except Exception as e:
            print(f"[IP2Proxy] Ошибка проверки IP {ip}: {e}")

    # 4. Эвристический анализ по ISP/ASN
    hosting_keywords = ["hosting", "datacenter", "cloud", "server", 
                       "vps", "dedicated", "colocation"]
    if any(keyword in isp for keyword in hosting_keywords):
        probability += 50
        reasons.append("ISP name indicates hosting/datacenter")

    # Проверка по известным ASN
    if asn in known_vpn_asns:
        probability += 99
        reasons.append(f"Known hosting/VPN ASN: {known_vpn_asns[asn]}")

    # 5. Проверка соответствия часового пояса
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
                mismatch_reason = f"Timezone offset mismatch: browser {browser_timezone} ({browser_offset}), IP {ip_timezone} ({ip_offset})"
        except pytz.UnknownTimeZoneError:
            # Если часовой пояс неизвестен, сравниваем строки
            if browser_timezone == ip_timezone:
                timezone_match = True
            else:
                probability += 55
                mismatch_reason = f"Timezone string mismatch (unknown zone): browser={browser_timezone}, IP={ip_timezone}"
        except Exception as e:
            # Резервный вариант сравнения
            if browser_timezone == ip_timezone:
                timezone_match = True
            else:
                probability += 55
                mismatch_reason = f"Timezone comparison error: {e}"
    else:
        mismatch_reason = "Browser timezone not provided" if not browser_timezone else "IP timezone not available"

    if mismatch_reason:
        reasons.append(mismatch_reason)

    # Автоматическое обучение: добавление новых ASN в базу
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

    # Ограничение вероятности 100%
    probability = min(probability, 100)

    # Если вероятность 0%, добавляем информационное сообщение
    if probability == 0:
        reasons = ["No signs of anonymization detected"]

    return {
        "probability": round(probability),
        "reasons": reasons,
        "timezone_match": timezone_match
    }

def lookup_ip(ip: str) -> dict:
    """
    Выполняет геолокацию IP адреса с использованием баз MaxMind
    Возвращает словарь с информацией о местоположении
    """
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

    # Геолокация через GeoLite2-City
    if city_reader:
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
        except Exception as e:
            print(f"[GeoIP City] Ошибка для IP {ip}: {e}")

    # Получение информации об ASN через GeoLite2-ASN
    if asn_reader:
        try:
            r = asn_reader.asn(ip)
            data.update({
                "isp": r.autonomous_system_organization,
                "asn": r.autonomous_system_number,
                "network": str(r.network)
            })
        except Exception as e:
            print(f"[GeoIP ASN] Ошибка для IP {ip}: {e}")

    return data

def update_request_stats(endpoint: str, client_ip: str):
    """Обновляет статистику запросов сервера"""
    request_stats["total_requests"] += 1
    request_stats["unique_ips"].add(client_ip)
    
    # Учет по типам запросов
    if endpoint == "/json":
        request_stats["json_requests"] += 1
    elif endpoint == "/":
        request_stats["root_requests"] += 1
    elif endpoint == "/check":
        request_stats["check_requests"] += 1

async def check_request_allowed(request: Request) -> bool:
    """
    Проверяет, разрешён ли запрос к API
    Разрешаем только запросы с указанного домена или прямой доступ к корню
    """
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    path = request.url.path
    
    # Разрешаем доступ к корневому пути (для редиректа на фронтенд)
    if path == "/":
        return True
        
    # ИЗМЕНИТЕ: укажите ваш домен
    allowed_origin = "https://example.com"
    
    # Проверка по Origin заголовку
    if origin == allowed_origin:
        return True
    
    # Дополнительная проверка по Referer
    if referer and referer.startswith(allowed_origin):
        return True
        
    return False

# ==================== API ENDPOINTS ====================

@app.get("/json")
async def json_lookup(
    request: Request,
    ip: str | None = Query(default=None, description="IP address to lookup"),
    browser_timezone: str | None = Query(default=None, alias="tz", description="Browser timezone (e.g. Europe/Moscow)")
):
    """
    Основной endpoint для геолокации IP адреса
    Параметры:
    - ip: целевой IP адрес (опционально, по умолчанию используется IP клиента)
    - tz: часовой пояс браузера (для детекции анонимизации)
    """
    # Проверка доступа
    if not await check_request_allowed(request):
        print(f"[BLOCKED] Запрос к /json заблокирован. Origin: {request.headers.get('origin', 'None')}, Referer: {request.headers.get('referer', 'None')}")
        return JSONResponse({"error": "Access denied"}, status_code=403)
    
    client_ip = request.client.host
    target_ip = ip if ip else client_ip
    
    # Маскировка IP для логирования
    masked_client_ip = mask_ip(client_ip)
    masked_target_ip = mask_ip(target_ip)
    print(f"[JSON] Запрос от {masked_client_ip}, целевой IP: {masked_target_ip}")
    update_request_stats("/json", client_ip)

    try:
        # Геолокация IP
        result = lookup_ip(target_ip)
        result["source"] = "query_param" if ip else "client_ip"

        # Анализ анонимизации
        anon_data = calculate_anonymization_probability(result, browser_timezone)
        
        # Добавление результатов анализа
        result.update({
            "browser_timezone": browser_timezone,
            "timezone_match": anon_data["timezone_match"],
            "anonymization_probability": anon_data["probability"],
            "anonymization_reasons": anon_data["reasons"]
        })

        return JSONResponse(result)
    except Exception as e:
        print(f"[ERROR] Ошибка обработки запроса: {e}")
        return JSONResponse({"error": "Server error"}, status_code=500)

@app.get("/check")
async def check_status(request: Request):
    """
    Endpoint для проверки статуса сервера
    Возвращает время работы сервера
    """
    # Проверка доступа
    if not await check_request_allowed(request):
        print(f"[BLOCKED] Запрос к /check заблокирован. Origin: {request.headers.get('origin', 'None')}, Referer: {request.headers.get('referer', 'None')}")
        return JSONResponse({"error": "Access denied"}, status_code=403)
    
    # Расчет времени работы
    uptime = datetime.now() - server_start_time
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    print(f"[CHECK] Статус проверен, uptime: {uptime_str}")
    update_request_stats("/check", "0.0.0.0")
    
    return {"status": f"online:{uptime_str}"}

@app.get("/")
async def root(request: Request):
    """
    Корневой endpoint - редирект на фронтенд приложение
    """
    client_ip = request.client.host
    masked_ip = mask_ip(client_ip)
    print(f"[ROOT] Запрос от {masked_ip} - редирект на фронтенд")
    update_request_stats("/", client_ip)
    
    # ИЗМЕНИТЕ: укажите URL вашего фронтенд приложения
    frontend_url = "https://example.com/lgeoip/"
    return RedirectResponse(url=frontend_url, status_code=302)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Middleware для добавления заголовков безопасности
    и проверки авторизации запросов
    """
    # Проверка разрешен ли запрос
    if not await check_request_allowed(request):
        print(f"[SECURITY] Заблокирован запрос к {request.url.path} от {request.client.host}")
        return JSONResponse({"error": "Access denied"}, status_code=403)
    
    # Продолжаем обработку запроса
    response = await call_next(request)
    
    # Добавление заголовков безопасности
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    return response

# ==================== ADMIN CONSOLE ====================

def advanced_admin_console():
    """
    Расширенная консоль администратора для управления сервером
    Запускается в отдельном терминале
    """
    banner = """
╔══════════════════════════════════════════════════════════╗
║          GEOIP ADMIN CONSOLE v2.0                        ║
║          Сервер: http://localhost:88                     ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)
    
    while True:
        try:
            command = input("\n> ").strip().lower()
            
            if command == "":
                continue
                
            elif command == "help" or command == "?":
                print("\nДоступные команды:")
                print("  help, ?           - показать эту справку")
                print("  stats             - статистика сервера")
                print("  asn_stats         - статистика по ASN")
                print("  requests          - статистика запросов")
                print("  add_asn <num> <desc> - добавить ASN в базу")
                print("  remove_asn <num>  - удалить ASN из базы")
                print("  list_asn          - список всех ASN")
                print("  search_asn <word> - поиск ASN по описанию")
                print("  reload_asn        - перезагрузить базу ASN")
                print("  update_tor        - обновить список Tor")
                print("  clear             - очистить экран")
                print("  restart           - перезапустить сервер")
                print("  exit, quit        - выход из консоли")
                
            elif command == "stats":
                uptime = datetime.now() - server_start_time
                days = uptime.days
                hours, remainder = divmod(int(uptime.seconds), 3600)
                minutes, seconds = divmod(remainder, 60)
                
                print(f"\n╔════════════════ СТАТИСТИКА СЕРВЕРА ════════════════╗")
                print(f"║ Время работы: {days}д {hours:02d}:{minutes:02d}:{seconds:02d}")
                print(f"║ ASN в базе: {len(known_vpn_asns)}")
                print(f"║ Tor IPs: {len(tor_exit_ips)}")
                print(f"║ IP2Proxy: {'Загружен' if proxy_reader else 'Не загружен'}")
                print(f"╚══════════════════════════════════════════════════════╝")
                
            elif command == "asn_stats":
                if known_vpn_asns:
                    print(f"\nВсего ASN в базе: {len(known_vpn_asns)}")
                    print("Последние 10 добавленных:")
                    for asn, desc in list(known_vpn_asns.items())[-10:]:
                        print(f"  ASN {asn}: {desc[:60]}...")
                else:
                    print("База ASN пуста")
                    
            elif command == "requests":
                uptime = datetime.now() - request_stats["start_time"]
                hours, remainder = divmod(int(uptime.total_seconds()), 3600)
                minutes, seconds = divmod(remainder, 60)
                
                print(f"\n╔════════════════ СТАТИСТИКА ЗАПРОСОВ ═══════════════╗")
                print(f"║ Период: {hours:02d}:{minutes:02d}:{seconds:02d}")
                print(f"║ Всего запросов: {request_stats['total_requests']}")
                print(f"║  JSON запросов: {request_stats['json_requests']}")
                print(f"║  ROOT запросов: {request_stats['root_requests']}")
                print(f"║ CHECK запросов: {request_stats['check_requests']}")
                print(f"║ Уникальных IP: {len(request_stats['unique_ips'])}")
                print(f"║ Средняя нагрузка: {request_stats['total_requests'] / max(1, uptime.total_seconds() / 60):.2f} запр/мин")
                print(f"╚══════════════════════════════════════════════════════╝")
                
            elif command.startswith("add_asn "):
                parts = command.split(maxsplit=2)
                if len(parts) < 2:
                    print("Использование: add_asn <номер_ASN> [описание]")
                    continue
                try:
                    asn = int(parts[1])
                    desc = parts[2] if len(parts) > 2 else "Добавлено вручную"
                    known_vpn_asns[asn] = desc
                    save_known_asns()
                    print(f"✓ ASN {asn} добавлен: {desc}")
                except ValueError:
                    print("Ошибка: ASN должен быть числом")
                    
            elif command.startswith("remove_asn "):
                parts = command.split()
                if len(parts) != 2:
                    print("Использование: remove_asn <номер_ASN>")
                    continue
                try:
                    asn = int(parts[1])
                    if asn in known_vpn_asns:
                        del known_vpn_asns[asn]
                        save_known_asns()
                        print(f"✓ ASN {asn} удален из базы")
                    else:
                        print(f"ASN {asn} не найден в базе")
                except ValueError:
                    print("Ошибка: ASN должен быть числом")
                    
            elif command == "list_asn":
                if known_vpn_asns:
                    print(f"\nВсего ASN: {len(known_vpn_asns)}")
                    for asn, desc in sorted(known_vpn_asns.items())[:20]:
                        print(f"  {asn}: {desc}")
                    if len(known_vpn_asns) > 20:
                        print(f"  ... и еще {len(known_vpn_asns) - 20} записей")
                else:
                    print("База ASN пуста")
                    
            elif command.startswith("search_asn "):
                search_term = command.split(maxsplit=1)[1].lower()
                results = []
                for asn, desc in known_vpn_asns.items():
                    if search_term in desc.lower():
                        results.append((asn, desc))
                
                if results:
                    print(f"\nНайдено {len(results)} совпадений:")
                    for asn, desc in results[:10]:
                        print(f"  {asn}: {desc}")
                    if len(results) > 10:
                        print(f"  ... и еще {len(results) - 10} записей")
                else:
                    print("Совпадений не найдено")
                    
            elif command == "reload_asn":
                load_known_asns()
                print("✓ База ASN перезагружена")
                
            elif command == "update_tor":
                old_count = len(tor_exit_ips)
                update_tor_exit_list()
                print(f"✓ Список Tor обновлен: {old_count} → {len(tor_exit_ips)} IP")
                
            elif command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                print(banner)
                
            elif command == "restart":
                print("Перезапуск сервера...")
                save_known_asns()
                print("Сохранение данных...")
                print("Для перезапуска сервера запустите его заново")
                print("Консоль продолжит работу")
                
            elif command in ["exit", "quit"]:
                print("Сохранение данных...")
                save_known_asns()
                print("Выход из консоли администратора")
                print("Сервер продолжает работу")
                break
                
            else:
                print(f"Неизвестная команда: {command}")
                print("Введите 'help' для списка команд")
                
        except KeyboardInterrupt:
            print("\n\nВыход из консоли администратора")
            print("Сервер продолжает работу")
            break
        except Exception as e:
            print(f"Ошибка: {e}")

# ==================== MAIN ====================

if __name__ == "__main__":
    # Информация при запуске сервера
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          GEOIP SERVER v2.0                               ║")
    print("║          Сервер: http://localhost:88                     ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"Директория баз: {BASE_DIR}")
    print(f"MaxMind City: {CITY_DB_PATH}")
    print(f"MaxMind ASN: {ASN_DB_PATH}")
    print(f"IP2Proxy PX12: {PROXY_DB_PATH}")
    print(f"Known ASNs: {KNOWN_ASNS_PATH}")
    print("\n[ВАЖНО] Настройте конфигурацию перед запуском:")
    print("1. Укажите правильные пути к файлам баз данных")
    print("2. Настройте CORS в строке 92 (allow_origins)")
    print("3. Настройте frontend URL в строке 354")
    print("4. Настройте проверку домена в функции check_request_allowed()")
    print("="*60)
    print("\n[ЗАПУСК] Сервер запускается на порту 88")
    print("Для управления используйте консоль администратора:")
    print("1. Откройте новое окно терминала")
    print("2. Перейдите в папку с сервером")
    print("3. Запустите: python -c \"import server; server.advanced_admin_console()\"")
    print("="*60 + "\n")
    
    # Запуск FastAPI сервера
    uvicorn.run(app, host="0.0.0.0", port=88, log_level="info")