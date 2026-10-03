"""
lgeoai.py — AI-модуль уточнения вероятности анонимизации (ONNX Runtime).

Что изменилось по сравнению с первой версией:

* порядок признаков берётся из метаданных ONNX (`features`), если они записаны
  при обучении; иначе используется FEATURE_KEYS. Размерность входа модели
  проверяется явно, поэтому несовпадение фич больше не даёт «молчаливый мусор»;
* predict() принимает и словарь, и список чисел (совместимо со старыми вызовами);
* добавлена валидация полезности модели: если на обучающем логе модель почти
  повторяет heuristic_probability, она помечается как redundant и в блендинг
  не идёт — иначе AI «уточняет» эвристику самой эвристикой;
* log_sample() возвращает sample_id, появился log_feedback() — реальные метки
  пишутся отдельным append-only файлом и используются в train_model.py;
* убраны bare except, добавлена блокировка записи в лог и ротация файла.

ВАЖНО: семантика признаков заморожена (нормировки, порядок) — она должна
совпадать с данными, на которых обучалась модель. Менять нормировки можно
только вместе с переобучением.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

logger = logging.getLogger("lgeoai")

try:  # onnxruntime нужен только для инференса
    import onnxruntime as ort
except Exception as exc:  # pragma: no cover - окружение без onnxruntime
    ort = None
    _ORT_IMPORT_ERROR: Exception | None = exc
else:
    _ORT_IMPORT_ERROR = None


# Порядок признаков == порядок в train_model.py. Не менять без переобучения!
FEATURE_KEYS: list[str] = [
    "is_tor",
    "has_suspicious_hostname",
    "ip2proxy_proxy",
    "ip2proxy_datacenter",
    "hosting_isp",
    "known_vpn_asn",
    "timezone_mismatch",
    "tz_offset_hours",
    "hostname_entropy",
    "reasons_count",
    "hosting_and_tz_mismatch",
    "heuristic_probability",
]

# Признак-«ответ»: если он есть среди входов, модель может просто копировать
# эвристику (утечка целевой переменной). train_model.py умеет обучать без него.
LEAKY_FEATURE = "heuristic_probability"

# Нормировка tz_offset_hours зафиксирована на /12 — так считались обучающие
# данные. Реальный максимум разницы часовых поясов 26, но менять нельзя: будет
# расхождение train/serve.
TZ_OFFSET_NORMALIZER = 12.0

# Порог для синтетической проверки (когда лога нет): он мягче, потому что пробы
# нереалистичны, и полезную модель лучше не отключать по ошибке.
SYNTHETIC_REDUNDANCY_MAE = 0.15


def safe_float(value: Any, default: float = 0.0) -> float:
    """float() без исключений: мусор/NaN дают default."""
    try:
        number = value.item() if hasattr(value, "item") else float(value)
    except (TypeError, ValueError):
        return default
    if number != number:  # NaN
        return default
    return float(number)


def clamp01(value: Any) -> float:
    """Приводит значение к float в [0, 1]; мусор превращается в 0.0."""
    return max(0.0, min(1.0, safe_float(value)))


def features_to_vector(values: Mapping[str, Any] | Sequence[Any], keys: Sequence[str] = FEATURE_KEYS) -> np.ndarray:
    """Словарь признаков (или готовый список) -> матрица формы (1, N)."""
    if isinstance(values, Mapping):
        vector = [clamp01(values.get(key, 0.0)) for key in keys]
    else:
        vector = [clamp01(value) for value in values]
    return np.asarray([vector], dtype=np.float32)


class LgeoAI:
    """Обёртка над ONNX-моделью + сбор данных для будущего обучения."""

    def __init__(
        self,
        model_path: str | Path | None = None,
        log_path: str | Path = "ai_training_data.jsonl",
        validate: bool = True,
        redundancy_mae: float = 0.02,
        feedback_path: str | Path | None = None,
        max_log_mb: int = 32,
    ) -> None:
        self.session = None
        self.log_path = Path(log_path)
        self.feedback_path = (
            Path(feedback_path) if feedback_path else self.log_path.with_suffix(self.log_path.suffix + ".feedback.jsonl")
        )
        self.model_path = Path(model_path) if model_path else None
        self.model_available = False
        self.ai_useful = False
        self.ai_status = "unavailable"  # unavailable|invalid|ready|redundant
        self.redundancy_mae: float | None = None
        self.redundancy_source: str | None = None
        self.feature_keys: list[str] = list(FEATURE_KEYS)
        self.request_count = 0
        self.max_log_bytes = max(1, int(max_log_mb)) * 1024 * 1024
        self._log_lock = threading.Lock()
        self._validate = validate
        self._redundancy_threshold = float(redundancy_mae)

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_model()

    # ------------------------------------------------------------------ модель
    def _load_model(self) -> None:
        if self.model_path is None:
            logger.info("AI: модель не задана — режим сбора данных")
            return
        if not self.model_path.exists():
            logger.warning("AI: модель не найдена (%s) — режим сбора данных", self.model_path)
            return
        if ort is None:
            self.ai_status = "invalid"
            logger.warning("AI: onnxruntime недоступен (%s) — режим сбора данных", _ORT_IMPORT_ERROR)
            return

        try:
            providers = [p for p in ("DmlExecutionProvider", "CPUExecutionProvider") if p in ort.get_available_providers()]
            self.session = ort.InferenceSession(str(self.model_path), providers=providers or ["CPUExecutionProvider"])
        except Exception as exc:
            self.ai_status = "invalid"
            logger.warning("AI: не удалось загрузить модель %s: %s", self.model_path, exc)
            return

        model_input = self.session.get_inputs()[0]
        declared = self._declared_features()
        input_dim = self._input_dim(model_input.shape)

        if declared:
            self.feature_keys = declared
        if input_dim is not None and input_dim != len(self.feature_keys):
            self.ai_status = "invalid"
            self.session = None
            logger.error(
                "AI: размерность входа модели %s не совпадает с признаками (%s != %s) — модель отключена",
                input_dim,
                input_dim,
                len(self.feature_keys),
            )
            return

        self.model_available = True
        self.ai_status = "ready"
        self.ai_useful = True
        logger.info(
            "AI: модель загружена (%s), провайдер %s, вход %s, выход %s, признаков %d",
            self.model_path.name,
            self.session.get_providers()[0] if self.session.get_providers() else "?",
            model_input.shape,
            self.session.get_outputs()[0].shape,
            len(self.feature_keys),
        )

        if self._validate:
            self._validate_model()

    def _declared_features(self) -> list[str]:
        """Читает список признаков из метаданных ONNX, если он там есть."""
        if self.session is None:
            return []
        try:
            meta = self.session.get_modelmeta().custom_metadata_map or {}
        except Exception:
            return []
        raw = meta.get("features")
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            logger.warning("AI: метаданные 'features' в модели не читаются, использую FEATURE_KEYS")
            return []
        if isinstance(parsed, list) and parsed and all(isinstance(item, str) for item in parsed):
            return parsed
        return []

    @staticmethod
    def _input_dim(shape: Sequence[Any]) -> int | None:
        if not shape:
            return None
        last = shape[-1]
        if isinstance(last, int):
            return last
        return None

    def _validate_model(self) -> None:
        """
        Проверяет, несёт ли модель информацию помимо эвристики.

        Основной способ — сравнить выход модели с признаком-ответом
        heuristic_probability на логе сбора данных. Если лога нет, делается
        синтетическая проверка: выход модели должен зависеть не только от
        признака-ответа. MAE ниже порога => модель воспроизводит эвристику,
        помечаем её redundant и не применяем в блендинге.
        """
        if LEAKY_FEATURE not in self.feature_keys:
            # Целевой признак не подаётся на вход — модель не может просто копировать эвристику.
            return

        leak_index = self.feature_keys.index(LEAKY_FEATURE)
        matrix = self._load_validation_matrix()
        if matrix is not None:
            try:
                predicted = self._run(matrix)
            except Exception as exc:
                logger.warning("AI: ошибка валидации модели: %s", exc)
                return
            mae = float(np.abs(predicted.ravel() - matrix[:, leak_index]).mean())
            self._decide_redundancy(mae, f"на {len(matrix)} записях лога {self.log_path.name}")
            return

        self._synthetic_redundancy_check(leak_index)

    def _load_validation_matrix(self) -> np.ndarray | None:
        if not self.log_path.exists():
            return None
        samples: list[list[float]] = []
        try:
            with self.log_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    features = record.get("features")
                    if isinstance(features, Mapping):
                        samples.append([clamp01(features.get(key, 0.0)) for key in self.feature_keys])
                    if len(samples) >= 20000:
                        break
        except OSError as exc:
            logger.warning("AI: не удалось прочитать лог для валидации: %s", exc)
            return None
        if len(samples) < 50:
            logger.info("AI: в логе мало данных (%d записей) — перехожу к синтетической проверке", len(samples))
            return None
        return np.asarray(samples, dtype=np.float32)

    def _synthetic_redundancy_check(self, leak_index: int) -> None:
        """
        Проверка без лога: подставляем разные наборы прочих признаков и смотрим,
        повторяет ли выход модели признак-ответ heuristic_probability.

        Берём лучший для модели результат по нескольким наборам проб (min):
        пометить полезную модель как redundant хуже, чем пропустить сомнительную.
        """
        rng = np.random.default_rng(12345)
        probes: dict[str, np.ndarray] = {
            "random01": rng.integers(0, 2, size=(64, len(self.feature_keys))).astype(np.float32),
            "sparse": (rng.random((64, len(self.feature_keys))) < 0.15).astype(np.float32),
            "onehot": np.eye(len(self.feature_keys), dtype=np.float32),
            "zeros": np.zeros((64, len(self.feature_keys)), dtype=np.float32),
        }
        residuals: dict[str, float] = {}
        for label, base in probes.items():
            low = base.copy()
            low[:, leak_index] = 0.0
            high = base.copy()
            high[:, leak_index] = 1.0
            try:
                predicted_low = self._run(low).ravel()
                predicted_high = self._run(high).ravel()
            except Exception as exc:
                logger.warning("AI: синтетическая проверка (%s) не удалась: %s", label, exc)
                return
            residuals[label] = float((np.abs(predicted_low).mean() + np.abs(predicted_high - 1.0).mean()) / 2.0)

        best = min(residuals.values())
        logger.debug("AI: синтетическая проверка, отклонения от тождества: %s", {k: round(v, 4) for k, v in residuals.items()})
        self._decide_redundancy(
            best,
            f"synthetic probe (output is determined by the target feature, {residuals})",
            threshold=SYNTHETIC_REDUNDANCY_MAE,
        )

    def _decide_redundancy(self, mae: float, source: str, threshold: float | None = None) -> None:
        limit = self._redundancy_threshold if threshold is None else threshold
        self.redundancy_mae = mae
        self.redundancy_source = "synthetic" if threshold is not None else "log"
        if mae < limit:
            self.ai_status = "redundant"
            self.ai_useful = False
            logger.warning(
                "AI: модель повторяет эвристику (MAE %.4f < %.4f, %s) — в блендинг не применяется. "
                "Нужны реальные метки: POST /feedback + train_model.py",
                mae,
                limit,
                source,
            )
        else:
            logger.info("AI: модель отличается от эвристики (MAE %.4f, %s) — применяется", mae, source)

    def _run(self, matrix: np.ndarray) -> np.ndarray:
        assert self.session is not None
        input_name = self.session.get_inputs()[0].name
        return np.asarray(self.session.run(None, {input_name: matrix})[0])

    # --------------------------------------------------------------- инференс
    def predict(self, features: Mapping[str, Any] | Sequence[Any]) -> float | None:
        """
        Вероятность анонимизации от модели в [0, 1] или None, если модель недоступна.

        Принимает словарь признаков (как extract_features) или готовый список чисел.
        """
        if self.session is None:
            return None
        try:
            matrix = features_to_vector(features, self.feature_keys)
        except Exception as exc:
            logger.warning("AI: не удалось собрать вектор признаков: %s", exc)
            return None
        if matrix.shape[1] != len(self.feature_keys):
            logger.warning("AI: ожидалось %d признаков, получено %d", len(self.feature_keys), matrix.shape[1])
            return None
        try:
            output = self._run(matrix)
        except Exception as exc:
            logger.error("AI: ошибка инференса: %s", exc)
            return None
        return clamp01(np.ravel(output)[0] if output.size else 0.5)

    # ------------------------------------------------------------- сбор данных
    def log_sample(
        self,
        features_dict: Mapping[str, Any],
        heuristic_prob: float,
        final_prob: float | None = None,
        user_feedback: Any = None,
        ai_prob: float | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> str | None:
        """
        Пишет пример для будущего обучения. IP/хостнейм не сохраняются.

        Возвращает sample_id (нужен для POST /feedback) или None при ошибке.
        """
        sample_id = uuid.uuid4().hex
        sample: dict[str, Any] = {
            "sample_id": sample_id,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "features": {key: clamp01(features_dict.get(key, 0.0)) for key in self.feature_keys},
            "heuristic_probability": round(float(heuristic_prob) / 100.0, 6),
            "final_probability": round(float(final_prob if final_prob is not None else heuristic_prob) / 100.0, 6),
            "ai_probability": None if ai_prob is None else round(float(ai_prob), 6),
            "user_feedback": user_feedback,
            "model": self.model_path.name if self.model_path else None,
        }
        if extra:
            sample.update(extra)

        try:
            with self._log_lock:
                self._rotate_if_needed()
                with self.log_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(sample, ensure_ascii=False) + "\n")
            self.request_count += 1
            if self.request_count % 100 == 0:
                logger.info("AI: собрано %d примеров", self.request_count)
            return sample_id
        except OSError as exc:
            logger.warning("AI: не удалось записать пример: %s", exc)
            return None

    def log_feedback(self, sample_id: str, label: float, note: str | None = None, source: str = "api") -> bool:
        """Сохраняет реальную метку пользователя рядом с примером (append-only)."""
        if not sample_id:
            return False
        record = {
            "sample_id": sample_id,
            "label": round(clamp01(label), 6),
            "note": (note or "")[:500],
            "source": source,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }
        try:
            with self._log_lock:
                self.feedback_path.parent.mkdir(parents=True, exist_ok=True)
                with self.feedback_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            return True
        except OSError as exc:
            logger.warning("AI: не удалось записать метку: %s", exc)
            return False

    def _rotate_if_needed(self) -> None:
        try:
            if self.log_path.exists() and self.log_path.stat().st_size > self.max_log_bytes:
                rotated = self.log_path.with_suffix(self.log_path.suffix + ".1")
                rotated.unlink(missing_ok=True)
                self.log_path.replace(rotated)
                logger.info("AI: лог обучения повёрнут в %s", rotated.name)
        except OSError as exc:
            logger.warning("AI: не удалось повернуть лог: %s", exc)

    # ------------------------------------------------------------------ статус
    def get_stats(self) -> dict[str, Any]:
        log_count = 0
        feedback_count = 0
        try:
            if self.log_path.exists():
                with self.log_path.open("r", encoding="utf-8") as handle:
                    log_count = sum(1 for line in handle if line.strip())
        except OSError:
            pass
        try:
            if self.feedback_path.exists():
                with self.feedback_path.open("r", encoding="utf-8") as handle:
                    feedback_count = sum(1 for line in handle if line.strip())
        except OSError:
            pass
        return {
            "model_available": self.model_available,
            "ai_useful": self.ai_useful,
            "ai_status": self.ai_status,
            "redundancy_mae": self.redundancy_mae,
            "validation_source": self.redundancy_source,
            "features": list(self.feature_keys),
            "requests_processed": self.request_count,
            "logged_samples": log_count,
            "feedback_samples": feedback_count,
            "log_file": str(self.log_path),
            "feedback_file": str(self.feedback_path),
            "model_file": str(self.model_path) if self.model_path else None,
        }


def extract_features(
    heuristic_prob: float,
    reasons: Sequence[Any],
    timezone_match: bool,
    is_tor: bool = False,
    suspicious_hostname: bool = False,
    ip2proxy_proxy: bool = False,
    ip2proxy_dc: bool = False,
    hosting_isp: bool = False,
    known_vpn_asn: bool = False,
    tz_offset: float = 0,
    hostname_entropy: float = 0,
    **legacy_ignored: Any,
) -> dict[str, float]:
    """
    Нормализованные признаки для AI-модели, все в [0, 1].

    Порядок/нормировки заморожены: они должны совпадать с обучающими данными.
    Лишние аргументы (ip_data, browser_timezone из старой версии) игнорируются,
    чтобы старые вызовы не падали.
    """
    if legacy_ignored:
        logger.debug("extract_features: проигнорированы лишние аргументы %s", sorted(legacy_ignored))

    return {
        "is_tor": 1.0 if is_tor else 0.0,
        "has_suspicious_hostname": 1.0 if suspicious_hostname else 0.0,
        "ip2proxy_proxy": 1.0 if ip2proxy_proxy else 0.0,
        "ip2proxy_datacenter": 1.0 if ip2proxy_dc else 0.0,
        "hosting_isp": 1.0 if hosting_isp else 0.0,
        "known_vpn_asn": 1.0 if known_vpn_asn else 0.0,
        "timezone_mismatch": 0.0 if timezone_match else 1.0,
        "tz_offset_hours": min(abs(safe_float(tz_offset)) / TZ_OFFSET_NORMALIZER, 1.0),
        "hostname_entropy": clamp01(hostname_entropy),
        "reasons_count": min(len(reasons) / 5.0, 1.0),
        "hosting_and_tz_mismatch": 1.0 if (hosting_isp and not timezone_match) else 0.0,
        "heuristic_probability": clamp01(safe_float(heuristic_prob) / 100.0),
    }
