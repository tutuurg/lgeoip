"""
config.py — единая конфигурация lgeoip.

Все пути и настройки читаются из переменных окружения (префикс LGEOIP_),
дефолты подобраны под текущую машину, поэтому сервер продолжает работать
без правки кода на другой машине: достаточно выставить ENV.

Примеры:
    set LGEOIP_CITY_DB=C:\\data\\GeoLite2-City.mmdb
    set LGEOIP_HOST=127.0.0.1
    set LGEOIP_ACCESS_MODE=token
    set LGEOIP_API_TOKEN=длинный-случайный-токен
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _env_str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return default if value is None or value.strip() == "" else value.strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "да"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw.strip().replace(",", "."))
    except ValueError:
        return default


def _env_path(name: str, default: Path) -> Path:
    return Path(_env_str(name, str(default))).expanduser()


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _first_existing(*candidates: Path) -> Path:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _db_default(name: str, *fallbacks: str) -> Path:
    """
    Сначала ищем файл рядом со скриптом, затем в известных местах.

    Так один и тот же config.py работает и в приватном развёртывании
    (базы в D:\\geoip), и в публичном репозитории (базы рядом с server.py).
    """
    return _first_existing(BASE_DIR / name, *(Path(item) for item in fallbacks))


# --------------------------------------------------------------------------
# пути к базам и файлам состояния
# --------------------------------------------------------------------------
CITY_DB_PATH = _env_path("LGEOIP_CITY_DB", _db_default("GeoLite2-City.mmdb", r"D:\geoip\GeoLite2-City.mmdb"))
ASN_DB_PATH = _env_path("LGEOIP_ASN_DB", _db_default("GeoLite2-ASN.mmdb", r"D:\geoip\GeoLite2-ASN.mmdb"))
PROXY_DB_PATH = _env_path("LGEOIP_PROXY_DB", _db_default("IP2PROXY-LITE-PX12.BIN", r"D:\geoip\IP2PROXY-LITE-PX12.BIN"))
KNOWN_ASNS_PATH = _env_path("LGEOIP_KNOWN_ASNS", _db_default("known_asns.json", r"D:\geoip\known_asns.json"))
TOR_CACHE_PATH = _env_path("LGEOIP_TOR_CACHE", _db_default("tor_exit_cache.json", r"D:\geoip\tor_exit_cache.json"))

MODEL_PATH = _env_path("LGEOIP_MODEL", BASE_DIR / "lgeoai_model.onnx")
TRAIN_LOG_PATH = _env_path("LGEOIP_TRAIN_LOG", BASE_DIR / "ai_training_data.jsonl")

# Статика: только каталог с ассетами, НИКОГДА каталог с базами.
# Раньше монтировался D:\geoip целиком, из-за чего mmdb/BIN/known_asns.json
# раздавались по /static/<имя файла>.
STATIC_DIR = _env_path(
    "LGEOIP_STATIC_DIR",
    _first_existing(BASE_DIR / "static", Path(r"D:\geoip\files")),
)
STATIC_URL_PREFIX = _env_str("LGEOIP_STATIC_PREFIX", "/static")
# Совместимость со старой раскладкой, когда D:\geoip монтировался целиком:
# /static/files/<logo> продолжает работать, но базы по-прежнему недоступны.
STATIC_ALIAS_PREFIX = _env_str("LGEOIP_STATIC_ALIAS_PREFIX", "/static/files")
STATIC_ALIAS_DIR = _env_path("LGEOIP_STATIC_ALIAS_DIR", Path(r"D:\geoip\files"))

# --------------------------------------------------------------------------
# сеть
# --------------------------------------------------------------------------
HOST = _env_str("LGEOIP_HOST", "127.0.0.1")  # было 0.0.0.0 — см. README
PORT = _env_int("LGEOIP_PORT", 88)
TRUST_PROXY = _env_bool("LGEOIP_TRUST_PROXY", False)
# куда редиректит GET /
FRONTEND_URL = _env_str("LGEOIP_FRONTEND_URL", "https://tutuurg.github.io/lgeoip/")

# --------------------------------------------------------------------------
# доступ
# --------------------------------------------------------------------------
# origin  — пускаем браузерные запросы с разрешённых Origin + прямой локальный доступ
# token   — обязателен LGEOIP_API_TOKEN (для публичного туннеля)
# open    — как было: пускаем всех (не рекомендуется, пишет WARNING в лог)
ACCESS_MODE = _env_str("LGEOIP_ACCESS_MODE", "origin").lower()
ALLOWED_ORIGINS = _env_list("LGEOIP_ALLOWED_ORIGINS", ["https://tutuurg.github.io"])
API_TOKEN = _env_str("LGEOIP_API_TOKEN", "")
ALLOW_DIRECT_LOCAL = _env_bool("LGEOIP_ALLOW_DIRECT_LOCAL", True)
ALLOWED_IPS = _env_list("LGEOIP_ALLOWED_IPS", [])

# rate limit: token bucket на ключ + общий лимит на процесс.
# По умолчанию лимит на ключ считается по Origin (иначе по IP): за туннелем все
# запросы приходят с 127.0.0.1, поэтому чтобы лимитировать по реальному
# пользователю, включите LGEOIP_TRUST_PROXY=1 (только если туннель доверенный).
RATE_LIMIT_PER_MINUTE = _env_int("LGEOIP_RATE_LIMIT_PER_MINUTE", 200)
RATE_LIMIT_BURST = _env_int("LGEOIP_RATE_LIMIT_BURST", 60)
RATE_LIMIT_GLOBAL_PER_MINUTE = _env_int("LGEOIP_RATE_LIMIT_GLOBAL_PER_MINUTE", 1200)
RATE_LIMIT_MAX_KEYS = _env_int("LGEOIP_RATE_LIMIT_MAX_KEYS", 5000)

# --------------------------------------------------------------------------
# поведение детектора
# --------------------------------------------------------------------------
REVERSE_DNS_ENABLED = _env_bool("LGEOIP_REVERSE_DNS", True)
REVERSE_DNS_TIMEOUT = _env_float("LGEOIP_REVERSE_DNS_TIMEOUT", 3.0)
REVERSE_DNS_TTL = _env_float("LGEOIP_REVERSE_DNS_TTL", 3600.0)
REVERSE_DNS_MAX_WORKERS = _env_int("LGEOIP_REVERSE_DNS_WORKERS", 4)
# false — не делать reverse DNS для чужих IP (быстрее и приватнее, но теряется признак)
REVERSE_DNS_THIRD_PARTY = _env_bool("LGEOIP_REVERSE_DNS_THIRD_PARTY", True)

TOR_UPDATE_INTERVAL = _env_int("LGEOIP_TOR_INTERVAL", 3600)
TOR_BACKGROUND = _env_bool("LGEOIP_TOR_BACKGROUND", True)
TOR_SOURCES = _env_list(
    "LGEOIP_TOR_SOURCES",
    [
        "https://check.torproject.org/torbulkexitlist",
        "https://www.dan.me.uk/torlist/",
    ],
)
TOR_MIN_LIST_SIZE = _env_int("LGEOIP_TOR_MIN_SIZE", 100)
HTTP_USER_AGENT = _env_str("LGEOIP_USER_AGENT", "lgeoip/2.1 (+https://tutuurg.github.io/lgeoip/)")

# --------------------------------------------------------------------------
# AI
# --------------------------------------------------------------------------
AI_ENABLED = _env_bool("LGEOIP_AI_ENABLED", True)
AI_VALIDATE = _env_bool("LGEOIP_AI_VALIDATE", True)
# если модель на валидационной выборке почти повторяет heuristic_probability,
# она не несёт информации и в блендинг не идёт (см. README, раздел про AI)
AI_REDUNDANCY_MAE = _env_float("LGEOIP_AI_REDUNDANCY_MAE", 0.02)
AI_HEURISTIC_WEIGHT = _env_float("LGEOIP_AI_HEURISTIC_WEIGHT", 0.7)
LOG_SAMPLES = _env_bool("LGEOIP_LOG_SAMPLES", True)
LOG_SAMPLES_MAX_MB = _env_int("LGEOIP_LOG_SAMPLES_MAX_MB", 32)

# --------------------------------------------------------------------------
# эксплуатация
# --------------------------------------------------------------------------
LOG_LEVEL = _env_str("LGEOIP_LOG_LEVEL", "INFO").upper()
ADMIN_CONSOLE = _env_str("LGEOIP_ADMIN_CONSOLE", "auto").lower()  # auto|off|on


def masked_token() -> str:
    if not API_TOKEN:
        return "<not set>"
    return API_TOKEN[:4] + "…" + API_TOKEN[-2:] if len(API_TOKEN) > 8 else "***"


def warnings() -> list[str]:
    """Configuration problems worth reporting at startup (English: also printed publicly)."""
    problems: list[str] = []
    if ACCESS_MODE not in {"origin", "token", "open"}:
        problems.append(f"LGEOIP_ACCESS_MODE={ACCESS_MODE!r} is unknown, 'origin' will be used")
    if ACCESS_MODE == "token" and not API_TOKEN:
        problems.append("ACCESS_MODE=token but LGEOIP_API_TOKEN is empty - every request will get 403")
    if ACCESS_MODE == "open":
        problems.append("ACCESS_MODE=open - the API is open to everyone (insecure)")
    if HOST not in {"127.0.0.1", "localhost", "::1"}:
        problems.append(f"listening on {HOST} - the API is reachable from the network; restrict it with a firewall")
    if not CITY_DB_PATH.exists():
        problems.append(f"city database not found: {CITY_DB_PATH} - geodata will be empty")
    if not ASN_DB_PATH.exists():
        problems.append(f"ASN database not found: {ASN_DB_PATH} - ISP/ASN will be empty")
    if not PROXY_DB_PATH.exists():
        problems.append(
            f"IP2Proxy database not found: {PROXY_DB_PATH} - IP2Proxy detection is disabled "
            "(ip2proxy_* features stay 0)"
        )
    # защита от повторения старой ошибки: статика не должна указывать на каталог с базами
    static_guard = {CITY_DB_PATH.parent, ASN_DB_PATH.parent, PROXY_DB_PATH.parent}
    if STATIC_DIR in static_guard and STATIC_DIR.exists():
        problems.append(f"STATIC_DIR={STATIC_DIR} equals a database directory - /static is not mounted")
    return problems


def summary_lines() -> list[str]:
    def mark(path: Path) -> str:
        return "present" if path.exists() else "MISSING"

    return [
        f"BASE_DIR            : {BASE_DIR}",
        f"City DB             : {CITY_DB_PATH} ({mark(CITY_DB_PATH)})",
        f"ASN DB              : {ASN_DB_PATH} ({mark(ASN_DB_PATH)})",
        f"IP2Proxy DB         : {PROXY_DB_PATH} ({mark(PROXY_DB_PATH)})",
        f"Known ASN           : {KNOWN_ASNS_PATH} ({mark(KNOWN_ASNS_PATH)})",
        f"Tor cache           : {TOR_CACHE_PATH}",
        f"AI model            : {MODEL_PATH} ({mark(MODEL_PATH)})",
        f"Training log        : {TRAIN_LOG_PATH}",
        f"Static dir          : {STATIC_DIR} ({mark(STATIC_DIR)})",
        f"Listen              : {HOST}:{PORT}",
        f"Frontend URL        : {FRONTEND_URL}",
        f"Access mode         : {ACCESS_MODE}, origins={ALLOWED_ORIGINS or 'any'}, "
        f"token={masked_token()}, direct-local={ALLOW_DIRECT_LOCAL}, trust-proxy={TRUST_PROXY}",
        f"Rate limit          : {RATE_LIMIT_PER_MINUTE}/min per key (burst {RATE_LIMIT_BURST}), "
        f"global {RATE_LIMIT_GLOBAL_PER_MINUTE}/min",
        f"Reverse DNS         : {'on' if REVERSE_DNS_ENABLED else 'off'}, "
        f"timeout {REVERSE_DNS_TIMEOUT}s, ttl {REVERSE_DNS_TTL}s, "
        f"3rd-party={'yes' if REVERSE_DNS_THIRD_PARTY else 'no'}",
        f"Tor                 : interval {TOR_UPDATE_INTERVAL}s, "
        f"background={'yes' if TOR_BACKGROUND else 'no'}, sources={len(TOR_SOURCES)}",
        f"AI                  : enabled={AI_ENABLED}, validate={AI_VALIDATE}, "
        f"redundancy_mae<{AI_REDUNDANCY_MAE}, heuristic_weight={AI_HEURISTIC_WEIGHT}",
        f"Sample logging      : {'on' if LOG_SAMPLES else 'off'}",
        f"Admin console       : {ADMIN_CONSOLE}",
    ]
