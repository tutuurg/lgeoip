"""
server.py — lgeoip: GeoIP + детект анонимизации (FastAPI).

Что исправлено относительно первой версии:

1.  /static больше не раздаёт каталог с базами (раньше по /static/<файл> можно
    было скачать GeoLite2-*.mmdb, IP2PROXY-*.BIN и known_asns.json).
2.  access control вместо `return True # временно`: allowlist Origin/Referer,
    опциональный токен, ограничение прямого доступа, rate limit.
3.  Блокирующие вызовы (reverse DNS, скачивание списка Tor) вынесены из
    event loop: эндпоинты объявлены обычными `def` (FastAPI уводит их в
    threadpool), DNS кешируется и ограничен по времени, список Tor обновляется
    фоновым потоком.
4.  probability зажимается до 100 ДО AI-блендинга (раньше суммы до 284 давали
    бессмысленный результат), AI-ветка работает только если модель проверена
    как полезная, в ответе видны ai_probability/ai_status/heuristic_probability.
5.  Пути и все настройки — в config.py через ENV, без хардкода D:\\...
6.  Админ-консоль — поток в том же процессе (а не второй процесс через
    exec() своего же исходника), запись known_asns.json под блокировкой файла.
7.  Убраны мёртвые импорты/шаблоны, логирование через logging, добавлен
    /health и POST /feedback для сбора реальных меток.

Запуск:
    py -3 server.py                 # чтение настроек из ENV
    py -3 server.py --console       # сервер + админ-консоль в этом же окне
    py -3 server.py --console-only  # только консоль (для отдельного окна)
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import logging
import os
import socket
import sys
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Body, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

import config
from lgeoai import LgeoAI, extract_features

logger = logging.getLogger("lgeoip")


SERVER_START_TIME = datetime.now()
MAX_TRACKED_IPS = 10_000
SUSPICIOUS_HOSTNAME_KEYWORDS = (
    "proxy", "vpn", "tor", "exit", "relay", "datacenter", "cloud", "server", "node", "tunnel",
)
HOSTING_ISP_KEYWORDS = ("hosting", "datacenter", "cloud", "server", "vps", "dedicated", "colocation")

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore[assignment]

try:
    import geoip2.database
except Exception:  # pragma: no cover
    geoip2 = None  # type: ignore[assignment]


# ==========================================================================
# утилиты
# ==========================================================================
def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))
        root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def mask_ip(ip: str | None) -> str:
    """Маскирует IP, оставляя последний октет / последние два хекстета."""
    if not ip:
        return "****"
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "****"
    if isinstance(address, ipaddress.IPv4Address):
        parts = str(address).split(".")
        return f"**.***.**.{parts[3]}"
    # IPv6: оставляем последнюю группу
    return f"****:****:****:{str(address).split(':')[-1]}"


def normalize_ip(raw: str | None) -> str | None:
    """Приводит IPv4-mapped IPv6 (::ffff:1.2.3.4) к IPv4, проверяет корректность."""
    if not raw:
        return None
    candidate = raw.strip()
    if not candidate:
        return None
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def is_loopback(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def is_ip_in(token: str, networks: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return False
    for item in networks:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Межпроцессная блокировка файла (чтобы консоль и сервер не затирали друг друга)."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+")
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt

            for _ in range(50):
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    acquired = True
                    break
                except OSError:
                    time.sleep(0.05)
            if not acquired:
                logger.warning("не удалось получить блокировку %s — пишу без неё", lock_path.name)
        else:  # pragma: no cover
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            acquired = True
        yield
    finally:
        try:
            if acquired and os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            elif acquired:  # pragma: no cover
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()


# ==========================================================================
# rate limit
# ==========================================================================
class RateLimiter:
    """Token bucket на ключ + общий лимит на процесс."""

    def __init__(self, per_minute: int, burst: int, global_per_minute: int, max_keys: int = 5000) -> None:
        self.rate = max(per_minute, 0) / 60.0
        self.capacity = float(max(burst, 1))  # burst — сколько запросов можно «в залпе»
        self.global_rate = max(global_per_minute, 0) / 60.0
        self.global_capacity = float(max(global_per_minute, 1))
        self.max_keys = max(100, max_keys)
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, list[float]] = OrderedDict()
        self._global = [self.global_capacity, time.monotonic()]
        self.rejected = 0

    def _consume(self, bucket: list[float], rate: float, capacity: float, now: float) -> bool:
        tokens, last = bucket
        tokens = min(capacity, tokens + max(0.0, now - last) * rate)
        if tokens < 1.0:
            bucket[0], bucket[1] = tokens, now
            return False
        bucket[0], bucket[1] = tokens - 1.0, now
        return True

    def allow(self, key: str) -> tuple[bool, float]:
        """(разрешено, сколько секунд подождать). Лимит <= 0 отключает соответствующую проверку."""
        if self.rate <= 0 and self.global_rate <= 0:
            return True, 0.0
        now = time.monotonic()
        with self._lock:
            if self.global_rate > 0 and not self._consume(self._global, self.global_rate, self.global_capacity, now):
                self.rejected += 1
                return False, round(1.0 / self.global_rate, 1)

            if self.rate > 0:
                bucket = self._buckets.get(key)
                if bucket is None:
                    bucket = [self.capacity, now]
                    self._buckets[key] = bucket
                    while len(self._buckets) > self.max_keys:
                        self._buckets.popitem(last=False)
                else:
                    self._buckets.move_to_end(key)
                if not self._consume(bucket, self.rate, self.capacity, now):
                    self.rejected += 1
                    return False, round(1.0 / self.rate, 1)
            return True, 0.0


# ==========================================================================
# базы
# ==========================================================================
class GeoDatabases:
    """Ленивая и безопасная обёртка над MaxMind/IP2Proxy."""

    def __init__(self, city_path: Path, asn_path: Path, proxy_path: Path) -> None:
        self.city_path = city_path
        self.asn_path = asn_path
        self.proxy_path = proxy_path
        self.city_reader = None
        self.asn_reader = None
        self.proxy_reader = None
        self.proxy_reason = ""
        self._lock = threading.Lock()  # mmap-чтение быстрое, блокировка нужна для смены ридеров
        self._open_city()
        self._open_asn()
        self._open_proxy()

    def _open_city(self) -> None:
        if geoip2 is None:
            logger.error("geoip2 не установлен — геоданные недоступны (pip install geoip2)")
            return
        if not self.city_path.exists():
            logger.error("нет базы городов: %s", self.city_path)
            return
        try:
            self.city_reader = geoip2.database.Reader(str(self.city_path))
            logger.info("база городов загружена: %s", self.city_path)
        except Exception as exc:
            logger.error("не удалось открыть базу городов %s: %s", self.city_path, exc)

    def _open_asn(self) -> None:
        if geoip2 is None or not self.asn_path.exists():
            logger.error("нет базы ASN: %s", self.asn_path)
            return
        try:
            self.asn_reader = geoip2.database.Reader(str(self.asn_path))
            logger.info("база ASN загружена: %s", self.asn_path)
        except Exception as exc:
            logger.error("не удалось открыть базу ASN %s: %s", self.asn_path, exc)

    def _open_proxy(self) -> None:
        if not self.proxy_path.exists():
            self.proxy_reason = f"file not found: {self.proxy_path}"
            logger.warning("IP2Proxy отключён: %s (признаки ip2proxy_* всегда 0)", self.proxy_reason)
            return
        try:
            import IP2Proxy  # type: ignore
        except Exception as exc:
            self.proxy_reason = f"IP2Proxy module is not installed ({exc.__class__.__name__})"
            logger.warning("IP2Proxy отключён: %s. Установите: pip install IP2Proxy", self.proxy_reason)
            return
        try:
            reader = IP2Proxy.IP2Proxy()
            reader.open(str(self.proxy_path))
            self.proxy_reader = reader
            logger.info("база IP2Proxy загружена: %s", self.proxy_path)
        except Exception as exc:
            self.proxy_reason = f"cannot open database: {exc}"
            logger.warning("IP2Proxy отключён: %s", self.proxy_reason)

    def status(self) -> dict[str, Any]:
        return {
            "city": self.city_reader is not None,
            "asn": self.asn_reader is not None,
            "ip2proxy": self.proxy_reader is not None,
            "ip2proxy_reason": self.proxy_reason,
        }

    def lookup(self, ip: str) -> dict[str, Any]:
        data: dict[str, Any] = {
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
            "network": None,
        }
        with self._lock:
            if self.city_reader is not None:
                try:
                    record = self.city_reader.city(ip)
                    data.update(
                        {
                            "country": record.country.name,
                            "country_iso": record.country.iso_code,
                            "city": record.city.name,
                            "region": record.subdivisions.most_specific.name if record.subdivisions else None,
                            "postal_code": record.postal.code,
                            "latitude": record.location.latitude,
                            "longitude": record.location.longitude,
                            "timezone": record.location.time_zone,
                        }
                    )
                except Exception as exc:
                    logger.debug("city lookup %s: %s", mask_ip(ip), exc)
            if self.asn_reader is not None:
                try:
                    record = self.asn_reader.asn(ip)
                    data.update(
                        {
                            "isp": record.autonomous_system_organization,
                            "asn": record.autonomous_system_number,
                            "network": str(record.network),
                        }
                    )
                except Exception as exc:
                    logger.debug("asn lookup %s: %s", mask_ip(ip), exc)
        return data

    def proxy_info(self, ip: str) -> dict[str, Any]:
        if self.proxy_reader is None:
            return {}
        with self._lock:
            try:
                return dict(self.proxy_reader.get_all(ip) or {})
            except Exception as exc:
                logger.debug("ip2proxy lookup %s: %s", mask_ip(ip), exc)
                return {}

    def close(self) -> None:
        with self._lock:
            for reader in (self.city_reader, self.asn_reader):
                try:
                    if reader is not None:
                        reader.close()
                except Exception:
                    pass
            if self.proxy_reader is not None:
                try:
                    self.proxy_reader.close()
                except Exception:
                    pass


# ==========================================================================
# список Tor exit nodes
# ==========================================================================
class TorExitList:
    """Список Tor exit nodes с кешем и фоновым обновлением (без блокировки запросов)."""

    def __init__(self, cache_path: Path, sources: list[str], interval: int, min_size: int) -> None:
        self.cache_path = cache_path
        self.sources = list(sources)
        self.interval = max(60, interval)
        self.min_size = min_size
        self._lock = threading.RLock()
        self._ips: set[str] = set()
        self._updated_at = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.load_cache()

    # ---------------------------------------------------------------- кеш
    def load_cache(self) -> bool:
        if not self.cache_path.exists():
            return False
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
            ips = {normalize_ip(item) for item in payload.get("ips", [])}
            ips.discard(None)
            with self._lock:
                self._ips = {ip for ip in ips if ip}
                self._updated_at = float(payload.get("timestamp", 0) or 0)
            logger.info("Tor: загружено %d IP из кеша", len(self._ips))
            return True
        except Exception as exc:
            logger.warning("Tor: кеш не прочитан (%s)", exc)
            return False

    def save_cache(self) -> None:
        try:
            with self._lock:
                payload = {"ips": sorted(self._ips), "timestamp": self._updated_at}
            with file_lock(self.cache_path):
                self.cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            logger.info("Tor: кеш сохранён (%d IP)", len(payload["ips"]))
        except OSError as exc:
            logger.warning("Tor: не удалось сохранить кеш: %s", exc)

    # ------------------------------------------------------------ обновление
    def refresh(self, timeout: float = 15.0) -> bool:
        """Скачивает список. Вызывать только из фонового потока или консоли."""
        if requests is None:
            logger.warning("Tor: модуль requests недоступен")
            return False
        headers = {"User-Agent": config.HTTP_USER_AGENT}
        for url in self.sources:
            try:
                response = requests.get(url, timeout=timeout, headers=headers)
                if response.status_code != 200:
                    logger.warning("Tor: %s -> HTTP %s", url, response.status_code)
                    continue
                parsed = self._parse(response.text)
                if len(parsed) < self.min_size:
                    logger.warning("Tor: %s -> подозрительно короткий список (%d), отбрасываю", url, len(parsed))
                    continue
                with self._lock:
                    self._ips = parsed
                    self._updated_at = time.time()
                self.save_cache()
                logger.info("Tor: список обновлён из %s — %d IP", url, len(parsed))
                return True
            except Exception as exc:
                logger.warning("Tor: %s -> %s", url, exc)
        return False

    @staticmethod
    def _parse(text: str) -> set[str]:
        """Валидирует строки: мусорные/HTML-ответы больше не попадают в список."""
        result: set[str] = set()
        for line in text.splitlines():
            candidate = line.split("#", 1)[0].strip()  # отбрасываем хвостовые комментарии
            if not candidate:
                continue
            normalized = normalize_ip(candidate)
            if normalized:
                result.add(normalized)
        return result

    def ensure_fresh(self) -> bool:
        """Дёшево: если кеш устарел — просит фоновый поток, сам ничего не качает."""
        with self._lock:
            stale = (time.time() - self._updated_at) > self.interval
        if not stale:
            return False
        if not config.TOR_BACKGROUND:
            # фоновое обновление выключено: сеть дёргать из обработки запроса нельзя
            return False
        if self._thread is None or not self._thread.is_alive():
            self.start_background()
        return True

    def start_background(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="tor-refresh", daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        # первый проход — сразу, дальше по интервалу; ошибки не роняют поток
        while not self._stop.is_set():
            try:
                self.refresh()
            except Exception as exc:  # pragma: no cover
                logger.warning("Tor: ошибка фонового обновления: %s", exc)
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()

    def contains(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ips

    def status(self) -> dict[str, Any]:
        with self._lock:
            size = len(self._ips)
            updated = self._updated_at
        age = None if not updated else round((time.time() - updated) / 3600.0, 2)
        return {"size": size, "last_update": updated, "age_hours": age, "interval_seconds": self.interval}

    def replace(self, ips: set[str]) -> None:
        """Для тестов/консоли: подменить список без сети."""
        with self._lock:
            self._ips = set(ips)
            self._updated_at = time.time()


# ==========================================================================
# reverse DNS с кешем и таймаутом
# ==========================================================================
class ReverseDNS:
    """Обратный DNS: TTL-кеш, ограничение по времени, без блокировки воркеров."""

    def __init__(self, ttl: float, timeout: float, workers: int, enabled: bool = True) -> None:
        self.ttl = max(1.0, ttl)
        self.timeout = max(0.1, timeout)
        self.enabled = enabled
        self.max_workers = max(1, workers)
        self._pool = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="rdns")
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, str | None]] = {}
        self._inflight = 0

    def lookup(self, ip: str) -> str | None:
        if not self.enabled:
            return None
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(ip)
            if cached and cached[0] > now:
                return cached[1]
            if self._inflight >= self.max_workers:  # пул занят — не копим задания
                return cached[1] if cached else None
            self._inflight += 1
        try:
            future = self._pool.submit(self._resolve, ip)
            try:
                hostname = future.result(timeout=self.timeout)
            except FutureTimeout:
                future.cancel()
                logger.debug("reverse DNS timeout для %s", mask_ip(ip))
                return None
            except Exception as exc:
                logger.debug("reverse DNS %s: %s", mask_ip(ip), exc)
                return None
        finally:
            with self._lock:
                self._inflight -= 1
        with self._lock:
            ttl = self.ttl if hostname else min(self.ttl, 300.0)  # негативный ответ короче
            self._cache[ip] = (time.monotonic() + ttl, hostname)
            if len(self._cache) > 20000:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
        return hostname

    @staticmethod
    def _resolve(ip: str) -> str | None:
        return socket.gethostbyaddr(ip)[0].lower()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {"enabled": self.enabled, "cached": len(self._cache), "in_flight": self._inflight}


# ==========================================================================
# база известных ASN
# ==========================================================================
class KnownAsns:
    """Словарь известных VPN/хостинг ASN с безопасной записью на диск.

    Правки не затирают чужие изменения: перед записью файл перечитывается,
    объединяется с тем, что в памяти, а явно удалённые ASN не возвращаются.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self.data: dict[int, str] = {}
        self._removed: set[int] = set()
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            logger.warning("known_asns.json не найден: %s", self.path)
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            with self._lock:
                self.data = {int(key): str(value) for key, value in raw.items()}
                self._removed.clear()
            logger.info("загружено %d известных ASN", len(self.data))
        except Exception as exc:
            logger.error("ошибка загрузки %s: %s", self.path, exc)

    def save(self) -> bool:
        with self._lock:
            memory = dict(self.data)
            removed = set(self._removed)
        try:
            with file_lock(self.path):
                merged = dict(memory)
                if self.path.exists():
                    try:
                        raw = json.loads(self.path.read_text(encoding="utf-8"))
                        for key, value in raw.items():
                            asn = int(key)
                            if asn in removed or asn in merged:
                                continue
                            merged[asn] = str(value)  # чужие добавления сохраняем
                    except Exception as exc:
                        logger.warning("не удалось перечитать %s перед записью: %s", self.path.name, exc)
                self.path.write_text(
                    json.dumps({str(key): value for key, value in merged.items()}, indent=4, ensure_ascii=False),
                    encoding="utf-8",
                )
            with self._lock:
                self.data = merged
                self._removed.clear()
            logger.info("сохранено %d ASN в %s", len(merged), self.path)
            return True
        except OSError as exc:
            logger.error("не удалось сохранить %s: %s", self.path, exc)
            return False

    def get(self, asn: Any) -> str | None:
        try:
            key = int(asn)
        except (TypeError, ValueError):
            return None
        with self._lock:
            return self.data.get(key)

    def add(self, asn: int, description: str) -> None:
        with self._lock:
            self.data[asn] = description
            self._removed.discard(asn)

    def remove(self, asn: int) -> bool:
        with self._lock:
            self._removed.add(asn)
            return self.data.pop(asn, None) is not None

    def __len__(self) -> int:
        with self._lock:
            return len(self.data)

    def items(self) -> list[tuple[int, str]]:
        with self._lock:
            return list(self.data.items())


# ==========================================================================
# детектор анонимизации
# ==========================================================================
class AnonymizationDetector:
    """Эвристики + (опционально) AI-уточнение."""

    def __init__(self, databases: GeoDatabases, tor: TorExitList, dns: ReverseDNS, known_asns: KnownAsns, ai: LgeoAI) -> None:
        self.databases = databases
        self.tor = tor
        self.dns = dns
        self.known_asns = known_asns
        self.ai = ai

    # -------------------------------------------------------------- tz
    @staticmethod
    def compare_timezones(browser_timezone: str | None, ip_timezone: str | None) -> tuple[bool, float, str]:
        """
        Сравнивает часовые пояса по фактическому (с учётом DST) смещению.

        Раньше использовался pytz.utcoffset(naive now) — это стандартное
        смещение, из-за чего в период перехода на летнее время сравнение могло
        врать (например, при южном полушарии).
        """
        if not browser_timezone or not ip_timezone:
            return False, 0.0, "timezone not provided"
        try:
            browser_zone = ZoneInfo(browser_timezone)
            ip_zone = ZoneInfo(ip_timezone)
        except (ZoneInfoNotFoundError, ValueError):
            if browser_timezone == ip_timezone:
                return True, 0.0, "unknown zone, string match"
            return False, 0.0, f"unknown zone, string mismatch: browser={browser_timezone}, ip={ip_timezone}"
        except Exception as exc:
            if browser_timezone == ip_timezone:
                return True, 0.0, "timezone compare error, string match"
            return False, 0.0, f"timezone compare error ({exc.__class__.__name__})"

        moment = datetime.now(timezone.utc)
        browser_offset = moment.astimezone(browser_zone).utcoffset()
        ip_offset = moment.astimezone(ip_zone).utcoffset()
        if browser_offset == ip_offset:
            return True, 0.0, "match"
        if browser_offset is None or ip_offset is None:
            return False, 0.0, "offset unavailable"
        return False, (browser_offset - ip_offset).total_seconds() / 3600.0, "offset mismatch"

    # ----------------------------------------------------------- main
    def analyze(
        self,
        ip_data: dict[str, Any],
        browser_timezone: str | None,
        is_self_lookup: bool = True,
        ai_mode: bool = False,
    ) -> dict[str, Any]:
        probability = 0
        reasons: list[str] = []

        ip = ip_data["ip"]
        ip_timezone = ip_data.get("timezone")
        isp = (ip_data.get("isp") or "").lower()
        asn = ip_data.get("asn")

        is_tor = False
        suspicious_hostname = False
        ip2proxy_proxy = False
        ip2proxy_dc = False
        hosting_isp = False
        known_vpn_asn_flag = False
        tz_offset = 0.0
        timezone_match = False

        # 1. Tor exit node
        self.tor.ensure_fresh()
        if self.tor.contains(ip):
            probability += 90
            reasons.append("IP is known Tor exit node")
            is_tor = True

        # 2. reverse DNS (кешируется; для чужих IP можно отключить через ENV)
        if config.REVERSE_DNS_ENABLED and (is_self_lookup or config.REVERSE_DNS_THIRD_PARTY):
            hostname = self.dns.lookup(ip)
            if hostname:
                if any(keyword in hostname for keyword in SUSPICIOUS_HOSTNAME_KEYWORDS):
                    probability += 40
                    reasons.append(f"Suspicious hostname: {hostname}")
                    suspicious_hostname = True
        elif not is_self_lookup:
            logger.debug("reverse DNS пропущен для стороннего IP %s", mask_ip(ip))

        # 3. IP2Proxy
        proxy_record = self.databases.proxy_info(ip)
        if proxy_record:
            record = {str(key).lower(): value for key, value in proxy_record.items()}
            if record.get("is_proxy") == 1:
                probability += 85
                ip2proxy_proxy = True
                proxy_type = (record.get("proxy_type") or "").strip()
                reasons.append(f"Detected as {proxy_type} proxy (IP2Proxy)" if proxy_type not in {"", "-"} else "Detected as proxy (IP2Proxy)")
            usage_type = str(record.get("usage_type") or "")
            if "dch" in usage_type.lower():
                probability += 30
                ip2proxy_dc = True
                reasons.append("Datacenter/hosting IP (IP2Proxy)")
            threat = str(record.get("threat") or "").strip()
            if threat and threat != "-":
                probability += 20
                reasons.append(f"Threat detected: {threat}")
            provider = str(record.get("provider") or "").strip()
            if provider and provider != "-":
                reasons.append(f"Proxy provider: {provider}")

        # 4. эвристики ISP/ASN
        if any(keyword in isp for keyword in HOSTING_ISP_KEYWORDS):
            probability += 50
            hosting_isp = True
            reasons.append("ISP name indicates hosting/datacenter")

        known_description = self.known_asns.get(asn)
        if known_description is not None:
            probability += 99
            known_vpn_asn_flag = True
            reasons.append(f"Known hosting/VPN ASN: {known_description}")

        # 5. часовой пояс — только для self-lookup
        if is_self_lookup and browser_timezone and ip_timezone:
            timezone_match, tz_offset, note = self.compare_timezones(browser_timezone, ip_timezone)
            if not timezone_match:
                probability += 55
                reasons.append(
                    f"Timezone mismatch: browser {browser_timezone} vs IP {ip_timezone} "
                    f"(delta {tz_offset:+.1f}h, {note})"
                )
        elif is_self_lookup:
            reasons.append("Browser timezone not provided")
        else:
            timezone_match = True  # для сторонних IP проверка не применяется

        heuristic_probability = probability
        # ВАЖНО: зажимаем до AI-блендинга, иначе 0.7*284 + 0.3*AI > 100
        probability = min(probability, 100)

        features = extract_features(
            heuristic_prob=heuristic_probability,
            reasons=reasons,
            timezone_match=timezone_match,
            is_tor=is_tor,
            suspicious_hostname=suspicious_hostname,
            ip2proxy_proxy=ip2proxy_proxy,
            ip2proxy_dc=ip2proxy_dc,
            hosting_isp=hosting_isp,
            known_vpn_asn=known_vpn_asn_flag,
            tz_offset=tz_offset,
            hostname_entropy=0.0,  # признак заморожен: в обучающих данных всегда 0
        )

        ai_probability: float | None = None
        ai_applied = False
        if config.AI_ENABLED and self.ai.model_available:
            ai_probability = self.ai.predict(features)
            if ai_mode and ai_probability is not None and self.ai.ai_useful:
                weight = min(max(config.AI_HEURISTIC_WEIGHT, 0.0), 1.0)
                blended = probability * weight + ai_probability * 100.0 * (1.0 - weight)
                probability = round(min(max(blended, 0.0), 100.0))
                ai_applied = True
                direction = "raised" if blended > heuristic_probability else "lowered"
                reasons.append(f"AI refinement: {round(ai_probability * 100)}% ({direction} the score)")
            elif ai_mode and ai_probability is not None and not self.ai.ai_useful:
                reasons.append(f"AI model not applied (status: {self.ai.ai_status})")

        if probability == 0:
            reasons = ["No signs of anonymization detected"]

        return {
            "probability": min(probability, 100),
            "heuristic_probability": min(heuristic_probability, 100),
            "reasons": reasons,
            "timezone_match": timezone_match,
            "features": features,
            "ai_probability": ai_probability,
            "ai_applied": ai_applied,
            "ai_status": self.ai.ai_status,
        }


# ==========================================================================
# доступ
# ==========================================================================
class AccessController:
    """
    Проверка доступа + rate limit.

    Режимы (LGEOIP_ACCESS_MODE):
      origin — разрешены браузерные запросы с Origin/Referer из allowlist и
               (опционально) прямой локальный доступ без прокси-заголовков;
      token  — обязателен LGEOIP_API_TOKEN (X-API-Token или ?token=);
      open   — как в старой версии, пускаем всех (пишет WARNING).
    """

    def __init__(self, limiter: RateLimiter) -> None:
        self.limiter = limiter
        self.mode = config.ACCESS_MODE if config.ACCESS_MODE in {"origin", "token", "open"} else "origin"
        self.allowed_origins = {origin.rstrip("/").lower() for origin in config.ALLOWED_ORIGINS}
        self.checked = 0
        self.denied = 0

    # ------------------------------------------------------------ helpers
    @staticmethod
    def client_ip(request: Request) -> str | None:
        if config.TRUST_PROXY:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return normalize_ip(forwarded.split(",")[0])
            real_ip = request.headers.get("x-real-ip")
            if real_ip:
                return normalize_ip(real_ip)
        return normalize_ip(request.client.host if request.client else None)

    def _origin_ok(self, request: Request) -> bool:
        for header in ("origin", "referer"):
            value = request.headers.get(header)
            if not value:
                continue
            if not self.allowed_origins:
                return True
            normalized = value.rstrip("/").lower()
            for allowed in self.allowed_origins:
                if normalized == allowed or normalized.startswith(allowed + "/"):
                    return True
        return False

    @staticmethod
    def _has_proxy_headers(request: Request) -> bool:
        return any(
            request.headers.get(name)
            for name in ("x-forwarded-for", "x-real-ip", "x-forwarded-host", "forwarded", "cf-connecting-ip")
        )

    @staticmethod
    def _token_from(request: Request) -> str:
        header = request.headers.get("x-api-token") or request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            header = header[7:]
        return (header or request.query_params.get("token") or "").strip()

    def rate_key(self, request: Request, client_ip: str | None) -> str:
        origin = (request.headers.get("origin") or request.headers.get("referer") or "").lower()
        if origin:
            return f"origin:{origin}"
        return f"ip:{client_ip or 'unknown'}"

    # --------------------------------------------------------------- check
    def check(self, request: Request) -> tuple[bool, int, str]:
        self.checked += 1
        client_ip = self.client_ip(request)
        path = request.url.path

        if self.mode == "open":
            allowed = True
        elif self.mode == "token":
            if not config.API_TOKEN:
                return self._deny(503, "server token not configured")
            allowed = self._token_from(request) == config.API_TOKEN
        else:  # origin
            if config.API_TOKEN and self._token_from(request) == config.API_TOKEN:
                allowed = True
            elif self._origin_ok(request):
                allowed = True
            elif is_ip_in(client_ip or "", config.ALLOWED_IPS):
                allowed = True
            elif config.ALLOW_DIRECT_LOCAL and is_loopback(client_ip) and not self._has_proxy_headers(request):
                allowed = True
            else:
                allowed = False

        if not allowed:
            logger.warning(
                "доступ запрещён: %s от %s (origin=%s, referer=%s)",
                path,
                mask_ip(client_ip),
                request.headers.get("origin", "-"),
                request.headers.get("referer", "-"),
            )
            return self._deny(403, "Access denied")

        ok, wait = self.limiter.allow(self.rate_key(request, client_ip))
        if not ok:
            logger.warning("rate limit: %s от %s (retry-after %.1fs)", path, mask_ip(client_ip), wait)
            self.denied += 1
            return False, 429, f"rate limit exceeded, retry in {wait:.0f}s"
        return True, 200, "ok"

    def _deny(self, status: int, reason: str) -> tuple[bool, int, str]:
        self.denied += 1
        return False, status, reason


# ==========================================================================
# статистика
# ==========================================================================
class RequestStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_requests = 0
        self.json_requests = 0
        self.root_requests = 0
        self.check_requests = 0
        self.feedback_requests = 0
        self.unique_clients: OrderedDict[str, None] = OrderedDict()

    def track(self, endpoint: str, client_ip: str | None) -> None:
        with self._lock:
            self.total_requests += 1
            if endpoint == "/json":
                self.json_requests += 1
            elif endpoint == "/":
                self.root_requests += 1
            elif endpoint == "/check":
                self.check_requests += 1
            elif endpoint == "/feedback":
                self.feedback_requests += 1
            if client_ip:
                masked = mask_ip(client_ip)  # в статистике тоже без сырых IP
                self.unique_clients[masked] = None
                self.unique_clients.move_to_end(masked)
                while len(self.unique_clients) > MAX_TRACKED_IPS:
                    self.unique_clients.popitem(last=False)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_requests": self.total_requests,
                "json_requests": self.json_requests,
                "root_requests": self.root_requests,
                "check_requests": self.check_requests,
                "feedback_requests": self.feedback_requests,
                "unique_clients": len(self.unique_clients),
            }


# ==========================================================================
# приложение
# ==========================================================================
def create_app() -> FastAPI:
    setup_logging(config.LOG_LEVEL)

    databases = GeoDatabases(config.CITY_DB_PATH, config.ASN_DB_PATH, config.PROXY_DB_PATH)
    tor = TorExitList(config.TOR_CACHE_PATH, config.TOR_SOURCES, config.TOR_UPDATE_INTERVAL, config.TOR_MIN_LIST_SIZE)
    dns = ReverseDNS(config.REVERSE_DNS_TTL, config.REVERSE_DNS_TIMEOUT, config.REVERSE_DNS_MAX_WORKERS, config.REVERSE_DNS_ENABLED)
    known_asns = KnownAsns(config.KNOWN_ASNS_PATH)
    ai = LgeoAI(
        model_path=config.MODEL_PATH if config.AI_ENABLED else None,
        log_path=config.TRAIN_LOG_PATH,
        validate=config.AI_VALIDATE,
        redundancy_mae=config.AI_REDUNDANCY_MAE,
        max_log_mb=config.LOG_SAMPLES_MAX_MB,
    )
    detector = AnonymizationDetector(databases, tor, dns, known_asns, ai)
    limiter = RateLimiter(config.RATE_LIMIT_PER_MINUTE, config.RATE_LIMIT_BURST, config.RATE_LIMIT_GLOBAL_PER_MINUTE, config.RATE_LIMIT_MAX_KEYS)
    access = AccessController(limiter)
    stats = RequestStats()

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        for line in config.summary_lines():
            logger.info("config | %s", line)
        for problem in config.warnings():
            logger.warning("config | %s", problem)
        if config.TOR_BACKGROUND:
            tor.start_background()
        logger.info("сервер готов: http://%s:%d", config.HOST, config.PORT)
        try:
            yield
        finally:
            tor.stop()
            databases.close()
            logger.info("сервер остановлен")

    app = FastAPI(title="Local GeoIP Server + Anonymization Detection", version="2.1", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.ALLOWED_ORIGINS or ["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
        max_age=600,
    )

    # Статика — только каталог ассетов. Каталог с базами монтировать нельзя.
    static_dir = config.STATIC_DIR
    bases_dirs = {config.CITY_DB_PATH.parent, config.ASN_DB_PATH.parent, config.PROXY_DB_PATH.parent}
    resolved_bases = {path.resolve() for path in bases_dirs if path.exists()}
    safe_static = (
        static_dir.exists() and static_dir.is_dir() and static_dir.resolve() not in resolved_bases
    )
    if safe_static:
        # сначала более длинный префикс: /static/files/... как в старой раскладке
        alias_dir = config.STATIC_ALIAS_DIR
        if alias_dir and alias_dir.exists() and alias_dir.resolve() not in resolved_bases:
            app.mount(config.STATIC_ALIAS_PREFIX, StaticFiles(directory=str(alias_dir)), name="static-files")
            logger.info("статика: %s -> %s", config.STATIC_ALIAS_PREFIX, alias_dir)
        app.mount(config.STATIC_URL_PREFIX, StaticFiles(directory=str(static_dir)), name="static")
        logger.info("статика: %s -> %s (только ассеты, базы не раздаются)", config.STATIC_URL_PREFIX, static_dir)
    else:
        logger.warning("статика не смонтирована (каталог %s отсутствует или совпадает с каталогом баз)", static_dir)

    @app.middleware("http")
    async def security_and_access(request: Request, call_next):
        started = time.perf_counter()
        allowed, status, reason = access.check(request)
        if not allowed:
            response = JSONResponse({"error": reason}, status_code=status)
        else:
            response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info("%s %s -> %s (%.0f ms)", request.method, request.url.path, response.status_code, elapsed_ms)
        return response

    # ------------------------------------------------------------- эндпоинты
    @app.get("/json")
    def json_lookup(
        request: Request,
        ip: str | None = Query(default=None, description="IP address to lookup"),
        browser_timezone: str | None = Query(default=None, alias="tz", description="Browser timezone"),
        ai_mode: bool = Query(default=False, alias="ai_mode", description="Enable AI refinement"),
    ) -> JSONResponse:
        client_ip = access.client_ip(request)
        target_ip = normalize_ip(ip) if ip else client_ip
        stats.track("/json", client_ip)

        if target_ip is None:
            return JSONResponse({"error": "invalid ip parameter"}, status_code=400)

        is_self_lookup = bool(ip is None) or target_ip == client_ip

        try:
            result = databases.lookup(target_ip)
            result["source"] = "query_param" if ip else "client_ip"
            analysis = detector.analyze(result, browser_timezone, is_self_lookup=is_self_lookup, ai_mode=ai_mode)

            result.update(
                {
                    "browser_timezone": browser_timezone,
                    "timezone_match": analysis["timezone_match"],
                    "anonymization_probability": analysis["probability"],
                    "heuristic_probability": analysis["heuristic_probability"],
                    "anonymization_reasons": analysis["reasons"],
                    "ai_available": ai.model_available,
                    "ai_mode_requested": ai_mode,
                    "ai_applied": analysis["ai_applied"],
                    "ai_status": analysis["ai_status"],
                    "ai_probability": None if analysis["ai_probability"] is None else round(analysis["ai_probability"] * 100, 1),
                }
            )

            if config.LOG_SAMPLES:
                sample_id = ai.log_sample(
                    features_dict=analysis["features"],
                    heuristic_prob=analysis["heuristic_probability"],
                    final_prob=analysis["probability"],
                    ai_prob=analysis["ai_probability"],
                    extra={"is_self_lookup": is_self_lookup, "ai_mode": bool(ai_mode)},
                )
                if sample_id:
                    result["sample_id"] = sample_id

            logger.info(
                "json: %s -> %s, self=%s, ai=%s, probability=%s",
                mask_ip(client_ip),
                mask_ip(target_ip),
                is_self_lookup,
                ai_mode,
                analysis["probability"],
            )
            return JSONResponse(result)
        except Exception as exc:
            logger.exception("json: ошибка обработки %s: %s", mask_ip(target_ip), exc)
            return JSONResponse({"error": "Server error"}, status_code=500)

    @app.get("/check")
    def check_status(request: Request) -> dict[str, Any]:
        stats.track("/check", access.client_ip(request))
        uptime = datetime.now() - SERVER_START_TIME
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return {
            # формат строки сохранён для совместимости с мониторингом
            "status": f"online:{hours:02d}:{minutes:02d}:{seconds:02d}",
            "uptime_seconds": int(uptime.total_seconds()),
            "databases": databases.status(),
            "tor": tor.status(),
            "reverse_dns": dns.stats(),
            "ai": ai.get_stats(),
            "known_asns": len(known_asns),
            "access_mode": access.mode,
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        """Короткий статус для мониторинга (без тяжёлых полей)."""
        return {
            "ok": databases.status()["city"] and databases.status()["asn"],
            "uptime_seconds": int((datetime.now() - SERVER_START_TIME).total_seconds()),
            "tor_ips": tor.status()["size"],
            "ai_status": ai.ai_status,
            "requests": stats.snapshot(),
        }

    @app.post("/feedback")
    def feedback(payload: dict[str, Any] = Body(...)) -> JSONResponse:
        """Реальная метка пользователя для дообучения модели."""
        stats.track("/feedback", None)
        sample_id = str(payload.get("sample_id") or "").strip()
        if not sample_id:
            return JSONResponse({"error": "sample_id is required"}, status_code=400)
        label = payload.get("label", payload.get("probability"))
        note = payload.get("note")
        if isinstance(label, str):
            normalized = label.strip().lower()
            mapping = {
                "clean": 0.0, "no": 0.0, "false": 0.0, "нет": 0.0, "0": 0.0,
                "vpn": 1.0, "proxy": 1.0, "anon": 1.0, "anonymous": 1.0,
                "yes": 1.0, "true": 1.0, "да": 1.0, "1": 1.0,
            }
            if normalized in mapping:
                label = mapping[normalized]
        if isinstance(label, str):
            try:
                label = float(label.replace(",", "."))
            except ValueError:
                return JSONResponse({"error": "label must be a number in [0, 1] or clean/vpn"}, status_code=400)
        if not isinstance(label, (int, float)):
            return JSONResponse({"error": "label is required"}, status_code=400)
        label = max(0.0, min(1.0, float(label)))
        if not ai.log_feedback(sample_id, label, note if isinstance(note, str) else None):
            return JSONResponse({"error": "cannot store feedback"}, status_code=500)
        return JSONResponse({"ok": True, "sample_id": sample_id, "label": label})

    @app.get("/")
    def root(request: Request) -> RedirectResponse:
        stats.track("/", access.client_ip(request))
        return RedirectResponse(url=config.FRONTEND_URL, status_code=302)

    app.state.databases = databases
    app.state.tor = tor
    app.state.dns = dns
    app.state.known_asns = known_asns
    app.state.ai = ai
    app.state.detector = detector
    app.state.access = access
    app.state.stats = stats
    return app


app = create_app()


# ==========================================================================
# админ-консоль (в этом же процессе, отдельным потоком)
# ==========================================================================
def admin_console(app_ref: FastAPI = app, banner: bool = True) -> None:
    state = app_ref.state
    databases = state.databases
    tor = state.tor
    known_asns = state.known_asns
    ai = state.ai
    access = state.access
    stats = state.stats

    if banner:
        print("=" * 58)
        print("GEOIP ADMIN CONSOLE v2.1")
        print(f"Сервер: http://{config.HOST}:{config.PORT}   (в процессе сервера)")
        print("Команды: help | stats | health | ai | access | exit")
        print("=" * 58)

    while True:
        try:
            command = input("\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nВыход из консоли администратора. Сервер продолжает работу.")
            return

        low = command.lower()
        try:
            if low in {"", "help", "?"}:
                print(
                    "\nДоступные команды:\n"
                    "  help, ?              - справка\n"
                    "  stats                - сводная статистика\n"
                    "  health               - состояние баз/кешей/AI\n"
                    "  requests             - статистика запросов\n"
                    "  asn_stats            - статистика по ASN\n"
                    "  add_asn <num> <desc> - добавить ASN\n"
                    "  remove_asn <num>     - удалить ASN\n"
                    "  list_asn             - список ASN\n"
                    "  search_asn <word>    - поиск ASN по описанию\n"
                    "  reload_asn           - перечитать known_asns.json\n"
                    "  update_tor           - обновить список Tor (сеть)\n"
                    "  tor_status           - статус списка Tor\n"
                    "  ai                   - статус AI и собранных данных\n"
                    "  access               - режим доступа и rate limit\n"
                    "  clear                - очистить экран\n"
                    "  exit, quit           - выйти из консоли\n"
                )
            elif low == "stats":
                uptime = datetime.now() - SERVER_START_TIME
                days = uptime.days
                hours, remainder = divmod(int(uptime.seconds), 3600)
                minutes, seconds = divmod(remainder, 60)
                print(f"\nВремя работы: {days}д {hours:02d}:{minutes:02d}:{seconds:02d}")
                print(f"ASN в базе: {len(known_asns)}")
                print(f"Tor IPs: {tor.status()['size']}")
                print(f"IP2Proxy: {'загружен' if databases.status()['ip2proxy'] else 'не загружен'}")
                print(f"AI модель: {ai.ai_status}" + (f" (MAE {ai.redundancy_mae:.4f})" if ai.redundancy_mae is not None else ""))
                print(f"Запросов: {stats.snapshot()}")
            elif low == "health":
                print(json.dumps(
                    {
                        "databases": databases.status(),
                        "tor": tor.status(),
                        "reverse_dns": state.dns.stats(),
                        "ai": ai.get_stats(),
                        "access": access_stats(access),
                    },
                    ensure_ascii=False,
                    indent=2,
                ))
            elif low == "requests":
                uptime = datetime.now() - SERVER_START_TIME
                snapshot = stats.snapshot()
                minutes = max(1.0, uptime.total_seconds() / 60)
                print(f"\nПериод: {int(uptime.total_seconds())} с")
                for key, value in snapshot.items():
                    print(f"  {key}: {value}")
                print(f"  запросов/мин: {snapshot['total_requests'] / minutes:.2f}")
                print(f"  rate limit rejections: {access.limiter.rejected}, отказов доступа: {access.denied}")
            elif low == "asn_stats":
                items = known_asns.items()
                print(f"\nВсего ASN: {len(items)}")
                for asn, desc in items[-10:]:
                    print(f"  ASN {asn}: {str(desc)[:60]}")
            elif low.startswith("add_asn "):
                parts = command.split(maxsplit=2)
                if len(parts) < 2:
                    print("Использование: add_asn <номер_ASN> [описание]")
                    continue
                try:
                    asn = int(parts[1])
                except ValueError:
                    print("Ошибка: ASN должен быть числом")
                    continue
                known_asns.add(asn, parts[2] if len(parts) > 2 else "Добавлено вручную")
                print(f"✓ ASN {asn} добавлен" if known_asns.save() else "ASN добавлен в память, но не сохранён на диск")
            elif low.startswith("remove_asn "):
                parts = command.split()
                if len(parts) != 2:
                    print("Использование: remove_asn <номер_ASN>")
                    continue
                try:
                    asn = int(parts[1])
                except ValueError:
                    print("Ошибка: ASN должен быть числом")
                    continue
                print(f"✓ ASN {asn} удалён" if known_asns.remove(asn) else f"ASN {asn} не найден")
                known_asns.save()
            elif low == "list_asn":
                items = sorted(known_asns.items())
                print(f"\nВсего ASN: {len(items)}")
                for asn, desc in items[:20]:
                    print(f"  {asn}: {desc}")
                if len(items) > 20:
                    print(f"  ... и ещё {len(items) - 20}")
            elif low.startswith("search_asn "):
                term = command.split(maxsplit=1)[1].lower()
                found = [(asn, desc) for asn, desc in known_asns.items() if term in str(desc).lower()]
                print(f"Найдено {len(found)}")
                for asn, desc in found[:10]:
                    print(f"  {asn}: {desc}")
            elif low == "reload_asn":
                known_asns.load()
                print(f"✓ База ASN перечитана: {len(known_asns)} записей")
            elif low == "update_tor":
                before = tor.status()["size"]
                print("Обновляю список Tor...")
                ok = tor.refresh()
                after = tor.status()["size"]
                print(f"{'✓' if ok else '✗'} Tor: {before} → {after} IP")
            elif low == "tor_status":
                status = tor.status()
                print(f"\nTor exit nodes: {status['size']}")
                print(f"Последнее обновление: {datetime.fromtimestamp(status['last_update']) if status['last_update'] else 'никогда'}")
                print(f"Интервал: {status['interval_seconds']} с")
                print(f"Кеш: {tor.cache_path}")
            elif low == "ai":
                info = ai.get_stats()
                print(json.dumps(info, ensure_ascii=False, indent=2))
                if info["ai_status"] == "redundant":
                    print("\nМодель воспроизводит эвристику и не применяется. Нужны реальные метки:")
                    print("  POST /feedback {sample_id, label}  ->  py -3 train_model.py")
            elif low == "access":
                print(json.dumps(access_stats(access), ensure_ascii=False, indent=2))
            elif low == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                print("GEOIP ADMIN CONSOLE v2.1 — help для списка команд")
            elif low in {"exit", "quit"}:
                known_asns.save()
                tor.save_cache()
                print("Данные сохранены. Выход из консоли, сервер продолжает работу.")
                return
            else:
                print(f"Неизвестная команда: {command}. Введите help.")
        except Exception as exc:  # консоль не должна падать
            print(f"Ошибка: {exc}")


def access_stats(access: AccessController) -> dict[str, Any]:
    return {
        "mode": access.mode,
        "allowed_origins": sorted(access.allowed_origins),
        "token_configured": bool(config.API_TOKEN),
        "allow_direct_local": config.ALLOW_DIRECT_LOCAL,
        "checked": access.checked,
        "denied": access.denied,
        "rate_limit_per_minute": config.RATE_LIMIT_PER_MINUTE,
        "rate_limit_rejected": access.limiter.rejected,
    }


def launch_console_window() -> None:
    """Запускает консоль в отдельном окне (отдельный процесс, только консоль)."""
    if os.name != "nt":
        print(f"Запустите в отдельном терминале: py -3 {Path(__file__).name} --console-only")
        return
    script = Path(__file__).resolve()
    os.system(f'start "lgeoip console" cmd /k "cd /d "{script.parent}" && py -3 "{script.name}" --console-only"')


# ==========================================================================
# точка входа
# ==========================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="lgeoip server")
    parser.add_argument("--host", default=config.HOST, help="адрес прослушивания (по умолчанию из LGEOIP_HOST)")
    parser.add_argument("--port", type=int, default=config.PORT, help="порт (по умолчанию из LGEOIP_PORT)")
    parser.add_argument("--console", action="store_true", help="запустить админ-консоль в этом же окне")
    parser.add_argument("--console-only", action="store_true", help="только админ-консоль, без сервера")
    parser.add_argument("--check-config", action="store_true", help="показать конфигурацию и выйти")
    parser.add_argument("--log-level", default=config.LOG_LEVEL, help="уровень логирования")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.log_level)

    if args.check_config:
        for line in config.summary_lines():
            print(line)
        for problem in config.warnings():
            print(f"WARNING: {problem}")
        return 0

    if args.console_only:
        admin_console(app, banner=True)
        return 0

    print("=" * 58)
    print("GEOIP SERVER v2.1")
    print(f"Сервер: http://{args.host}:{args.port}")
    print("=" * 58)
    for line in config.summary_lines():
        print(f"  {line}")
    for problem in config.warnings():
        print(f"  WARNING: {problem}")
    print("=" * 58)

    console_thread = None
    wants_console = args.console or (config.ADMIN_CONSOLE == "on") or (
        config.ADMIN_CONSOLE == "auto" and sys.stdin is not None and sys.stdin.isatty()
    )
    if wants_console:
        console_thread = threading.Thread(target=admin_console, args=(app,), name="admin-console", daemon=True)
        console_thread.start()

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level.lower())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
