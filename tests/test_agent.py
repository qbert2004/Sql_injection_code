"""
Тесты для SQL Injection Protector AI Agent
"""

import pytest
import sys
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent.parent))

from sql_injection_detector import (
    SQLInjectionAgent,
    SignaturePolicy,
    MLDetector,
    HeuristicAnalyzer,
    train_initial_model
)

# ============================================================================
# ФИКСТУРЫ
# ============================================================================

@pytest.fixture(scope="module")
def trained_agent():
    """Агент с обученной моделью"""
    # Обучаем модель, если её нет
    try:
        agent = SQLInjectionAgent(ml_model_path="test_model.pkl")
    except:
        train_initial_model("test_model.pkl")
        agent = SQLInjectionAgent(ml_model_path="test_model.pkl")
    return agent

@pytest.fixture
def signature_policy():
    """Сигнатурный детектор"""
    return SignaturePolicy()

@pytest.fixture
def heuristic_analyzer():
    """Эвристический анализатор"""
    return HeuristicAnalyzer()

# ============================================================================
# ТЕСТЫ СИГНАТУРНОГО ДЕТЕКТОРА
# ============================================================================

class TestSignaturePolicy:
    """Тесты сигнатурного детектора"""

    def test_detect_union_injection(self, signature_policy):
        """Тест детектирования UNION инъекции"""
        text = "' UNION SELECT * FROM users--"
        is_mal, patterns, conf = signature_policy.detect(text)
        assert is_mal == True
        assert 'union_select' in patterns
        assert conf > 0.0

    def test_detect_comment_injection(self, signature_policy):
        """Тест детектирования комментариев"""
        text = "admin' --"
        is_mal, patterns, conf = signature_policy.detect(text)
        assert is_mal == True

    def test_detect_drop_table(self, signature_policy):
        """Тест детектирования DROP TABLE"""
        text = "'; DROP TABLE users--"
        is_mal, patterns, conf = signature_policy.detect(text)
        assert is_mal == True
        assert 'drop_table' in patterns

    def test_safe_email(self, signature_policy):
        """Тест безопасного email"""
        text = "john.doe@example.com"
        is_mal, patterns, conf = signature_policy.detect(text)
        assert is_mal == False
        assert len(patterns) == 0

    def test_safe_text(self, signature_policy):
        """Тест безопасного текста"""
        text = "Normal search query"
        is_mal, patterns, conf = signature_policy.detect(text)
        assert is_mal == False

    def test_url_encoded_injection(self, signature_policy):
        """Тест URL-encoded инъекции"""
        text = "%27%20OR%201=1--"
        is_mal, patterns, conf = signature_policy.detect(text)
        assert is_mal == True

# ============================================================================
# ТЕСТЫ ЭВРИСТИЧЕСКОГО АНАЛИЗАТОРА
# ============================================================================

class TestHeuristicAnalyzer:
    """Тесты эвристического анализатора"""

    def test_analyze_long_string(self, heuristic_analyzer):
        """Тест длинной строки"""
        text = "a" * 200
        risk_score, metrics = heuristic_analyzer.analyze(text)
        assert metrics['length'] == 200
        assert risk_score > 0.0

    def test_analyze_special_chars(self, heuristic_analyzer):
        """Тест специальных символов"""
        text = "!@#$%^&*(){}[]"
        risk_score, metrics = heuristic_analyzer.analyze(text)
        assert metrics['special_chars_ratio'] > 0.5
        assert risk_score > 0.0

    def test_analyze_sql_keywords(self, heuristic_analyzer):
        """Тест SQL ключевых слов"""
        text = "SELECT INSERT UPDATE DELETE UNION DROP"
        risk_score, metrics = heuristic_analyzer.analyze(text)
        assert metrics['sql_keywords_count'] >= 3
        assert risk_score > 0.0

    def test_analyze_safe_text(self, heuristic_analyzer):
        """Тест безопасного текста"""
        text = "normal user input"
        risk_score, metrics = heuristic_analyzer.analyze(text)
        assert risk_score < 0.5

# ============================================================================
# ТЕСТЫ ПОЛНОГО АГЕНТА
# ============================================================================

class TestSQLInjectionAgent:
    """Тесты полного агента"""

    def test_detect_classic_injection(self, trained_agent):
        """Тест классической инъекции"""
        result = trained_agent.analyze("' OR '1'='1")
        assert result.is_malicious == True
        assert result.confidence > 0.5

    def test_detect_union_injection(self, trained_agent):
        """Тест UNION инъекции"""
        result = trained_agent.analyze("1' UNION SELECT * FROM users--")
        assert result.is_malicious == True
        assert result.risk_score > 0.5

    def test_detect_comment_based(self, trained_agent):
        """Тест comment-based инъекции"""
        result = trained_agent.analyze("admin' --")
        assert result.is_malicious == True

    def test_detect_time_based(self, trained_agent):
        """Тест time-based инъекции"""
        result = trained_agent.analyze("' AND SLEEP(5)--")
        assert result.is_malicious == True

    def test_safe_email(self, trained_agent):
        """Тест безопасного email"""
        result = trained_agent.analyze("john.doe@example.com")
        assert result.is_malicious == False

    def test_safe_product_name(self, trained_agent):
        """Тест безопасного названия продукта"""
        result = trained_agent.analyze("Product Name 123")
        assert result.is_malicious == False

    def test_safe_url(self, trained_agent):
        """Тест безопасного URL"""
        result = trained_agent.analyze("https://example.com")
        assert result.is_malicious == False

    def test_result_has_timestamp(self, trained_agent):
        """Тест наличия timestamp в результате"""
        result = trained_agent.analyze("test")
        assert result.timestamp is not None
        assert len(result.timestamp) > 0

    def test_result_has_detection_method(self, trained_agent):
        """Тест наличия метода детектирования"""
        result = trained_agent.analyze("' OR '1'='1")
        assert result.detection_method in ['signature', 'ml_model', 'heuristic', 'combined']

    def test_siem_format(self, trained_agent):
        """Тест формата SIEM"""
        result = trained_agent.analyze("' OR '1'='1")
        siem = result.to_siem_format()
        assert 'timestamp' in siem
        assert 'event_type' in siem
        assert 'severity' in siem
        assert 'confidence' in siem

# ============================================================================
# ИНТЕГРАЦИОННЫЕ ТЕСТЫ
# ============================================================================

class TestIntegration:
    """Интеграционные тесты"""

    @pytest.mark.parametrize("text,expected", [
        ("' OR '1'='1", True),
        ("admin' --", True),
        ("1' UNION SELECT * FROM users--", True),
        ("'; DROP TABLE users--", True),
        ("john.doe@example.com", False),
        ("Product123", False),
        ("Normal text", False),
        ("https://example.com", False),
    ])
    def test_multiple_cases(self, trained_agent, text, expected):
        """Тест множества случаев"""
        result = trained_agent.analyze(text)
        assert result.is_malicious == expected, f"Failed for text: {text}"

    def test_batch_processing(self, trained_agent):
        """Тест пакетной обработки"""
        texts = [
            "' OR '1'='1",
            "john.doe@example.com",
            "admin' --",
            "Product Name",
        ]

        results = [trained_agent.analyze(text) for text in texts]

        assert len(results) == 4
        assert results[0].is_malicious == True
        assert results[1].is_malicious == False
        assert results[2].is_malicious == True
        assert results[3].is_malicious == False

    def test_performance(self, trained_agent):
        """Тест производительности"""
        import time

        texts = ["test input"] * 100
        start = time.time()

        for text in texts:
            trained_agent.analyze(text)

        elapsed = time.time() - start
        avg_time = elapsed / len(texts)

        # Должно быть быстрее 10ms на запрос
        assert avg_time < 0.01, f"Too slow: {avg_time:.4f}s per request"

# ============================================================================
# ТЕСТЫ ОБУЧЕНИЯ
# ============================================================================

class TestMLDetector:
    """Тесты ML детектора"""

    def test_train_model(self):
        """Тест обучения модели"""
        detector = MLDetector()

        training_data = [
            "' OR '1'='1",
            "admin' --",
            "john.doe@example.com",
            "Normal text"
        ]
        labels = [1, 1, 0, 0]

        detector.train(training_data, labels)
        assert detector.is_trained == True

    def test_predict_after_training(self):
        """Тест предсказания после обучения"""
        detector = MLDetector()

        training_data = ["' OR '1'='1"] * 10 + ["normal text"] * 10
        labels = [1] * 10 + [0] * 10

        detector.train(training_data, labels)

        is_mal, conf = detector.predict("' OR '1'='1")
        assert isinstance(is_mal, bool)
        assert 0.0 <= conf <= 1.0

    def test_predict_without_training(self):
        """Тест предсказания без обучения"""
        detector = MLDetector()
        is_mal, conf = detector.predict("test")

        assert is_mal == False
        assert conf == 0.0

# ============================================================================
# EDGE CASES
# ============================================================================

class TestEdgeCases:
    """Тесты граничных случаев"""

    def test_empty_string(self, trained_agent):
        """Тест пустой строки"""
        result = trained_agent.analyze("")
        assert result.is_malicious == False

    def test_very_long_string(self, trained_agent):
        """Тест очень длинной строки"""
        text = "a" * 10000
        result = trained_agent.analyze(text)
        assert result is not None

    def test_unicode_characters(self, trained_agent):
        """Тест Unicode символов"""
        texts = [
            "Привет мир",
            "你好世界",
            "مرحبا",
            "🚀🔒"
        ]

        for text in texts:
            result = trained_agent.analyze(text)
            assert result is not None
            assert result.is_malicious == False

    def test_special_characters(self, trained_agent):
        """Тест специальных символов"""
        texts = [
            "test@#$%",
            "price: $99.99",
            "50% discount",
        ]

        for text in texts:
            result = trained_agent.analyze(text)
            assert result is not None

# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
