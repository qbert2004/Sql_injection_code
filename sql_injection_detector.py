"""
SQL Injection Prevention Agent - Core Detection Module
Многоуровневая система детектирования SQL-инъекций
"""

import re
import json
import logging
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from urllib.parse import unquote_plus

# ============================================================================
# КОНФИГУРАЦИЯ И ЛОГИРОВАНИЕ
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SQLInjectionAgent")


@dataclass
class DetectionResult:
    """Результат детектирования"""
    is_malicious: bool
    confidence: float
    detection_method: str
    matched_patterns: List[str]
    sanitized_value: Optional[str]
    risk_score: float
    timestamp: str
    source: str = "unknown"

    def to_siem_format(self) -> Dict:
        """Формат для SIEM-систем (CEF, JSON)"""
        return {
            "timestamp": self.timestamp,
            "event_type": "sql_injection_detection",
            "severity": "critical" if self.is_malicious else "info",
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "detection_method": self.detection_method,
            "matched_patterns": self.matched_patterns,
            "action": "blocked" if self.is_malicious else "allowed"
        }


# ============================================================================
# СЛОЙ ПОЛИТИКИ: СИГНАТУРЫ И ПАТТЕРНЫ
# ============================================================================

class SignaturePolicy:
    """Сигнатурный детектор на основе регулярных выражений"""

    # Критические SQL-паттерны
    CRITICAL_PATTERNS = {
        'union_select': r'union\s+(all\s+)?select',
        'sql_comment': r'(--|#|/\*|\*/)',
        'always_true': r'(\d+\s*=\s*\d+|[\'"]?\w+[\'"]?\s*=\s*[\'"]?\w+[\'"]?)',
        'drop_table': r'drop\s+(table|database|schema)',
        'exec_command': r'(exec|execute|xp_cmdshell)\s*\(',
        'information_schema': r'information_schema\.',
        'sleep_delay': r'(sleep|waitfor|benchmark|pg_sleep)\s*\(',
        'stacked_queries': r';\s*(select|insert|update|delete|drop)',
        'hex_encoding': r'0x[0-9a-f]+',
        'char_function': r'char\s*\(\s*\d+',
        'into_outfile': r'into\s+(outfile|dumpfile)',
        'load_file': r'load_file\s*\(',
        'sql_keywords': r'\b(select|insert|update|delete|drop|create|alter|truncate)\b',
        'quote_escape': r'(\\\'|\\"|%27|%22)',
        'or_injection': r'\bor\b\s+[\'"]*\d+[\'"]*\s*=\s*[\'"]*\d+[\'"]*',
        'blind_sqli': r'(substring|substr|mid|ascii|ord)\s*\(',
        'database_enum': r'(database|schema|table_name|column_name)\s*\(',
    }

    # Whitelist: безопасные паттерны
    WHITELIST_PATTERNS = [
        r'^[a-zA-Z0-9_\-\.@]+$',  # Простые идентификаторы
        r'^\d{1,10}$',  # Числа
    ]

    # Blacklist: запрещенные символы
    BLACKLIST_CHARS = [';', '--', '/*', '*/', 'xp_', 'sp_', '@@']

    def __init__(self):
        self.patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.CRITICAL_PATTERNS.items()
        }
        self.whitelist = [re.compile(p, re.IGNORECASE) for p in self.WHITELIST_PATTERNS]

    def detect(self, value: str) -> Tuple[bool, List[str], float]:
        """
        Детектирование по сигнатурам
        Returns: (is_malicious, matched_patterns, confidence)
        """
        decoded_value = self._decode_value(value)
        matched = []

        # Проверка whitelist (строгая)
        for pattern in self.whitelist:
            if pattern.match(decoded_value):
                return False, [], 0.0

        # Проверка blacklist символов
        for char in self.BLACKLIST_CHARS:
            if char in decoded_value.lower():
                matched.append(f"blacklist_char:{char}")

        # Проверка критических паттернов
        for name, pattern in self.patterns.items():
            if pattern.search(decoded_value):
                matched.append(name)

        if matched:
            confidence = min(1.0, len(matched) * 0.2 + 0.3)
            return True, matched, confidence

        return False, [], 0.0

    def _decode_value(self, value: str) -> str:
        """Декодирование URL и специальных символов"""
        decoded = unquote_plus(value)
        decoded = decoded.replace('%20', ' ')
        return decoded


# ============================================================================
# ML-ДЕТЕКТОР: TF-IDF + ЛОГИСТИЧЕСКАЯ РЕГРЕССИЯ
# ============================================================================

class MLDetector:
    """Machine Learning детектор на основе TF-IDF + LogReg"""

    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            analyzer='char',
            ngram_range=(2, 5),
            max_features=1000,
            lowercase=True
        )
        self.model = LogisticRegression(
            C=1.0,
            max_iter=1000,
            random_state=42
        )
        self.is_trained = False

    def train(self, training_data: List[str], labels: List[int]):
        """
        Обучение модели
        training_data: список строк (SQL-запросы/параметры)
        labels: 1 - вредоносный, 0 - безопасный
        """
        X = self.vectorizer.fit_transform(training_data)
        self.model.fit(X, labels)
        self.is_trained = True
        logger.info(f"ML-модель обучена на {len(training_data)} примерах")

    def predict(self, value: str) -> Tuple[bool, float]:
        """
        Предсказание
        Returns: (is_malicious, probability)
        """
        if not self.is_trained:
            return False, 0.0

        X = self.vectorizer.transform([value])
        proba = self.model.predict_proba(X)[0]

        # proba[1] - вероятность класса "вредоносный"
        is_malicious = proba[1] > 0.5
        confidence = proba[1]

        return is_malicious, confidence

    def save_model(self, filepath: str):
        """Сохранение модели"""
        with open(filepath, 'wb') as f:
            pickle.dump({'vectorizer': self.vectorizer, 'model': self.model}, f)
        logger.info(f"Модель сохранена: {filepath}")

    def load_model(self, filepath: str):
        """Загрузка модели"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            self.vectorizer = data['vectorizer']
            self.model = data['model']
            self.is_trained = True
        logger.info(f"Модель загружена: {filepath}")


# ============================================================================
# ЭВРИСТИЧЕСКИЙ АНАЛИЗАТОР
# ============================================================================

class HeuristicAnalyzer:
    """Эвристический анализ запросов"""

    RISK_INDICATORS = {
        'length': 100,  # Подозрительная длина
        'special_chars_ratio': 0.3,  # Процент спецсимволов
        'sql_keywords_count': 3,  # Количество SQL-ключевых слов
        'encoded_chars': 5,  # Количество закодированных символов
    }

    def analyze(self, value: str) -> Tuple[float, Dict[str, Any]]:
        """
        Эвристический анализ
        Returns: (risk_score, metrics)
        """
        metrics = {}
        risk_score = 0.0

        # Длина строки
        length = len(value)
        metrics['length'] = length
        if length > self.RISK_INDICATORS['length']:
            risk_score += 0.2

        # Процент специальных символов
        special_chars = sum(1 for c in value if not c.isalnum() and c not in ' \t\n')
        special_ratio = special_chars / max(length, 1)
        metrics['special_chars_ratio'] = special_ratio
        if special_ratio > self.RISK_INDICATORS['special_chars_ratio']:
            risk_score += 0.3

        # SQL-ключевые слова
        sql_keywords = ['select', 'insert', 'update', 'delete', 'union', 'drop', 'exec']
        keyword_count = sum(1 for kw in sql_keywords if kw in value.lower())
        metrics['sql_keywords_count'] = keyword_count
        if keyword_count >= self.RISK_INDICATORS['sql_keywords_count']:
            risk_score += 0.4

        # Закодированные символы
        encoded_count = value.count('%') + value.count('\\x')
        metrics['encoded_chars'] = encoded_count
        if encoded_count > self.RISK_INDICATORS['encoded_chars']:
            risk_score += 0.1

        # Энтропия (разнообразие символов)
        entropy = self._calculate_entropy(value)
        metrics['entropy'] = entropy
        if entropy > 4.5:
            risk_score += 0.2

        return min(risk_score, 1.0), metrics

    def _calculate_entropy(self, s: str) -> float:
        """Расчет энтропии строки"""
        if not s:
            return 0.0

        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1

        entropy = 0.0
        length = len(s)
        for count in freq.values():
            p = count / length
            entropy -= p * np.log2(p)

        return entropy


# ============================================================================
# ГЛАВНЫЙ ДЕТЕКТОР: ОБЪЕДИНЕНИЕ ВСЕХ МЕТОДОВ
# ============================================================================

class SQLInjectionAgent:
    """Главный агент детектирования SQL-инъекций"""

    def __init__(self, ml_model_path: Optional[str] = None):
        self.signature_policy = SignaturePolicy()
        self.ml_detector = MLDetector()
        self.heuristic_analyzer = HeuristicAnalyzer()

        # Загрузка ML-модели, если есть
        if ml_model_path:
            try:
                self.ml_detector.load_model(ml_model_path)
            except FileNotFoundError:
                logger.warning(f"ML-модель не найдена: {ml_model_path}")

        # Пороги детектирования
        self.DETECTION_THRESHOLD = 0.5
        self.RISK_THRESHOLD = 0.6

    def analyze(self, value: str) -> DetectionResult:
        """
        Комплексный анализ значения
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # 1. Сигнатурный анализ
        sig_malicious, sig_patterns, sig_confidence = self.signature_policy.detect(value)

        # 2. ML-анализ
        ml_malicious, ml_confidence = self.ml_detector.predict(value)

        # 3. Эвристический анализ
        heur_risk, heur_metrics = self.heuristic_analyzer.analyze(value)

        # Объединение результатов (взвешенное голосование)
        weights = {
            'signature': 0.5,
            'ml': 0.3,
            'heuristic': 0.2
        }

        combined_confidence = (
            sig_confidence * weights['signature'] +
            ml_confidence * weights['ml'] +
            heur_risk * weights['heuristic']
        )

        is_malicious = (
            sig_malicious or
            (combined_confidence > self.DETECTION_THRESHOLD)
        )

        # Определение метода детектирования
        if sig_malicious:
            detection_method = "signature"
        elif ml_malicious and ml_confidence > 0.7:
            detection_method = "ml_model"
        elif heur_risk > self.RISK_THRESHOLD:
            detection_method = "heuristic"
        else:
            detection_method = "combined"

        # Риск-скор
        risk_score = max(sig_confidence, ml_confidence, heur_risk)

        # Санитизация (если нужна)
        sanitized = self._sanitize_value(value) if not is_malicious else None

        result = DetectionResult(
            is_malicious=is_malicious,
            confidence=combined_confidence,
            detection_method=detection_method,
            matched_patterns=sig_patterns,
            sanitized_value=sanitized,
            risk_score=risk_score,
            timestamp=timestamp
        )

        # Логирование
        self._log_detection(value, result)

        return result

    def _sanitize_value(self, value: str) -> str:
        """Базовая санитизация значения"""
        # Удаление опасных символов
        sanitized = value.replace("'", "''")  # Экранирование одинарных кавычек
        sanitized = re.sub(r'[;\-\-]', '', sanitized)  # Удаление ; и --
        sanitized = re.sub(r'/\*.*?\*/', '', sanitized)  # Удаление комментариев
        return sanitized

    def _log_detection(self, value: str, result: DetectionResult):
        """Логирование результата детектирования"""
        log_data = {
            "value_preview": value[:50] + "..." if len(value) > 50 else value,
            "result": asdict(result)
        }

        if result.is_malicious:
            logger.warning(f"MALICIOUS REQUEST DETECTED: {json.dumps(log_data, indent=2)}")
        else:
            logger.info(f"Request analyzed: malicious={result.is_malicious}, confidence={result.confidence:.2f}")


# ============================================================================
# ОБУЧЕНИЕ МОДЕЛИ: ПРИМЕР ДАТАСЕТА
# ============================================================================

def train_initial_model(save_path: str = "sql_injection_model.pkl"):
    """Обучение начальной ML-модели"""

    # Примеры вредоносных запросов
    malicious_samples = [
        "' OR '1'='1",
        "admin' --",
        "1' UNION SELECT NULL, username, password FROM users--",
        "'; DROP TABLE users; --",
        "1' AND 1=0 UNION SELECT NULL, table_name FROM information_schema.tables--",
        "1' AND SLEEP(5)--",
        "1' OR '1'='1' /*",
        "admin' OR 1=1#",
        "' OR 'a'='a",
        "1' UNION ALL SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version--",
        "1'; EXEC sp_MSForEachTable 'DROP TABLE ?'--",
        "' OR EXISTS(SELECT * FROM users)--",
        "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
        "'; WAITFOR DELAY '00:00:05'--",
    ]

    # Примеры безопасных запросов
    safe_samples = [
        "john.doe@example.com",
        "Product123",
        "Hello World",
        "12345",
        "user_name_123",
        "Search query text",
        "Category: Electronics",
        "Price: 99.99",
        "2023-01-15",
        "New York",
        "Order #45678",
        "Customer feedback here",
        "Product description with spaces",
        "Valid email address",
        "Normal text input",
    ]

    # Расширение датасета вариациями
    extended_malicious = malicious_samples * 10  # Дублирование для баланса
    extended_safe = safe_samples * 10

    training_data = extended_malicious + extended_safe
    labels = [1] * len(extended_malicious) + [0] * len(extended_safe)

    # Обучение
    detector = MLDetector()
    detector.train(training_data, labels)
    detector.save_model(save_path)

    logger.info(f"Модель обучена и сохранена: {save_path}")
    return detector


# ============================================================================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ
# ============================================================================

if __name__ == "__main__":
    # Обучение модели
    print("=== Обучение ML-модели ===")
    train_initial_model()

    # Инициализация агента
    print("\n=== Инициализация агента ===")
    agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")

    # Тестовые запросы
    test_cases = [
        "john.doe@example.com",  # Безопасный
        "' OR '1'='1",  # Вредоносный
        "Product name",  # Безопасный
        "admin' --",  # Вредоносный
        "1' UNION SELECT * FROM users--",  # Вредоносный
        "Normal search query",  # Безопасный
    ]

    print("\n=== Тестирование детектирования ===")
    for test_value in test_cases:
        result = agent.analyze(test_value)
        print(f"\nЗапрос: {test_value}")
        print(f"Вредоносный: {result.is_malicious}")
        print(f"Уверенность: {result.confidence:.2%}")
        print(f"Метод: {result.detection_method}")
        print(f"Риск-скор: {result.risk_score:.2%}")
        if result.matched_patterns:
            print(f"Паттерны: {result.matched_patterns}")
