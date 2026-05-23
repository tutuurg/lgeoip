"""
lgeoai.py — модуль для AI-уточнения анонимизации
Использует ONNX Runtime с NPU (DirectML)
"""

import onnxruntime as ort
import numpy as np
import json
from pathlib import Path
from datetime import datetime
import os

class LgeoAI:
    def __init__(self, model_path=None, log_path="ai_training_data.jsonl"):
        """
        Инициализация AI-модуля
        
        Args:
            model_path: путь к .onnx модели (если None — только сбор данных)
            log_path: путь для сохранения данных обучения
        """
        self.session = None
        self.log_path = Path(log_path)
        self.model_available = False
        self.request_count = 0
        
        # Создаём папку для логов если нужно
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Загружаем модель если есть
        if model_path and Path(model_path).exists():
            try:
                # Пробуем NPU через DirectML, если нет — CPU
                providers = ['DmlExecutionProvider', 'CPUExecutionProvider']
                self.session = ort.InferenceSession(model_path, providers=providers)
                self.model_available = True
                print(f"[AI] ✅ Модель загружена")
                print(f"[AI]    Провайдер: {self.session.get_providers()[0]}")
                print(f"[AI]    Вход: {self.session.get_inputs()[0].shape}")
                print(f"[AI]    Выход: {self.session.get_outputs()[0].shape}")
            except Exception as e:
                print(f"[AI] ⚠️ Ошибка загрузки модели: {e}")
                print(f"[AI]    Работа в режиме сбора данных")
        else:
            if model_path:
                print(f"[AI] ⚠️ Модель не найдена: {model_path}")
            print("[AI] ℹ️ Работа в режиме сбора данных")
    
    def predict(self, features_dict):
        """
        Получить вероятность анонимизации от AI
        
        Args:
            features_dict: словарь с признаками (см. extract_features)
        
        Returns:
            float: вероятность 0.0-1.0 или None если модель недоступна
        """
        if not self.model_available:
            return None
        
        # Преобразуем в вектор
        vector = self._dict_to_vector(features_dict)
        if vector is None:
            return None
        
        # Инференс на NPU
        try:
            inputs = {self.session.get_inputs()[0].name: vector}
            outputs = self.session.run(None, inputs)
            
            # Получаем результат в зависимости от формы выхода
            output = outputs[0]
            
            # Если выход - массив, извлекаем скаляр
            if isinstance(output, np.ndarray):
                if output.size == 1:
                    prob = float(output.item())
                elif output.ndim == 2 and output.shape[1] == 1:
                    prob = float(output[0][0])
                elif output.ndim == 1:
                    prob = float(output[0])
                else:
                    prob = float(output[0][0]) if output.size > 0 else 0.5
            else:
                prob = float(output)
            
            return max(0.0, min(1.0, prob))
        except Exception as e:
            print(f"[AI] ❌ Ошибка инференса: {e}")
            return None
    
    def _dict_to_vector(self, features_dict):
        """
        Преобразует словарь признаков в numpy массив
        Порядок признаков должен совпадать с обучением модели
        """
        keys = [
            'is_tor',
            'has_suspicious_hostname', 
            'ip2proxy_proxy',
            'ip2proxy_datacenter',
            'hosting_isp',
            'known_vpn_asn',
            'timezone_mismatch',
            'tz_offset_hours',
            'hostname_entropy',
            'reasons_count',
            'hosting_and_tz_mismatch',
            'heuristic_probability'
        ]
        
        vector = []
        for key in keys:
            val = features_dict.get(key, 0.0)
            try:
                # Если это numpy-скаляр, конвертируем в float
                if hasattr(val, 'item'):
                    val = val.item()
                else:
                    val = float(val)
                val = max(0.0, min(1.0, val))
            except:
                val = 0.0
            vector.append(val)
        
        # Возвращаем 2D массив (1 строка, N колонок)
        return np.array([vector], dtype=np.float32)
    
    def log_sample(self, features_dict, heuristic_prob, final_prob=None, user_feedback=None):
        """
        Сохраняет данные для будущего обучения модели
        """
        sample = {
            "timestamp": datetime.now().isoformat(),
            "features": features_dict,
            "heuristic_probability": heuristic_prob / 100.0,
            "final_probability": (final_prob or heuristic_prob) / 100.0,
            "user_feedback": user_feedback
        }
        
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            self.request_count += 1
            if self.request_count % 100 == 0:
                print(f"[AI] 📊 Собрано {self.request_count} примеров")
        except Exception as e:
            print(f"[AI] ⚠️ Ошибка сохранения лога: {e}")
    
    def get_stats(self):
        """Возвращает статистику работы AI модуля"""
        log_count = 0
        if self.log_path.exists():
            with open(self.log_path, "r", encoding="utf-8") as f:
                log_count = sum(1 for _ in f)
        
        return {
            "model_available": self.model_available,
            "requests_processed": self.request_count,
            "logged_samples": log_count,
            "log_file": str(self.log_path)
        }


def extract_features(ip_data, browser_timezone, heuristic_prob, reasons, timezone_match, 
                     is_tor=False, suspicious_hostname=False, ip2proxy_proxy=False,
                     ip2proxy_dc=False, hosting_isp=False, known_vpn_asn=False,
                     tz_offset=0, hostname_entropy=0):
    """
    Извлекает нормализованные признаки для AI модели
    Все признаки нормализованы к диапазону [0, 1]
    """
    reasons_count = min(len(reasons) / 5.0, 1.0)
    hosting_and_tz_mismatch = 1.0 if (hosting_isp and not timezone_match) else 0.0
    heuristic_norm = heuristic_prob / 100.0
    
    return {
        'is_tor': 1.0 if is_tor else 0.0,
        'has_suspicious_hostname': 1.0 if suspicious_hostname else 0.0,
        'ip2proxy_proxy': 1.0 if ip2proxy_proxy else 0.0,
        'ip2proxy_datacenter': 1.0 if ip2proxy_dc else 0.0,
        'hosting_isp': 1.0 if hosting_isp else 0.0,
        'known_vpn_asn': 1.0 if known_vpn_asn else 0.0,
        'timezone_mismatch': 0.0 if timezone_match else 1.0,
        'tz_offset_hours': min(abs(tz_offset) / 12.0, 1.0),
        'hostname_entropy': min(hostname_entropy, 1.0),
        'reasons_count': reasons_count,
        'hosting_and_tz_mismatch': hosting_and_tz_mismatch,
        'heuristic_probability': heuristic_norm
    }