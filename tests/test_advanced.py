"""
Advanced Test Suite для SQL Injection Detector
Комплексное тестирование с реальными сценариями
"""

import pytest
import asyncio
from sql_injection_detector import SQLInjectionAgent, train_initial_model
from typing import List, Tuple

# ============================================================================
# ТЕСТОВЫЕ ДАННЫЕ: РЕАЛЬНЫЕ АТАКИ ИЗ ДИКОЙ ПРИРОДЫ
# ============================================================================

REAL_WORLD_ATTACKS = {
    'authentication_bypass': [
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' or '1' = '1",
        "' or 'x'='x",
        "' OR 'a'='a",
        "admin' OR '1'='1",
        "user' OR 1=1--",
        "admin') OR ('1'='1'--",
    ],
    
    'union_injection': [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "1' UNION SELECT @@version--",
        "' UNION SELECT username, password FROM users--",
        "1' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT 1,2,3,4,5--",
        "-1' UNION SELECT group_concat(table_name) FROM information_schema.tables--",
    ],
    
    'time_based_blind': [
        "1' AND SLEEP(5)--",
        "1' AND WAITFOR DELAY '00:00:05'--",
        "1' AND BENCHMARK(5000000,MD5('test'))--",
        "1' AND pg_sleep(5)--",
        "1'; SELECT SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
    
    'boolean_blind': [
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' AND ASCII(SUBSTRING(@@version,1,1))>64--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "1' AND LENGTH(database())>5--",
        "1' AND SUBSTRING(version(),1,1)='5'--",
    ],
    
    'error_based': [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        "' AND UpdateXML(1,CONCAT(0x7e,@@version),1)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
    ],
    
    'stacked_queries': [
        "'; DROP TABLE users--",
        "1'; DELETE FROM users WHERE 1=1--",
        "'; CREATE TABLE hacked(id INT)--",
        "1'; EXEC sp_MSForEachTable 'DROP TABLE ?'--",
        "'; SHUTDOWN--",
    ],
    
    'out_of_band': [
        "1' UNION SELECT LOAD_FILE('/etc/passwd')--",
        "' UNION SELECT NULL,NULL INTO OUTFILE '/var/www/html/shell.php'--",
        "1'; SELECT * INTO DUMPFILE '/tmp/backdoor'--",
    ],
    
    'obfuscated': [
        # URL encoding
        "%27%20OR%20%271%27%3D%271",
        # Double encoding
        "%2527%252520OR%2525201%25253D1--",
        # Hex encoding
        "0x61646D696E' --",
        # Char encoding
        "' OR CHAR(49)=CHAR(49)--",
        # Concatenation
        "' OR 'a'||'b'='ab'--",
        # Comments in middle
        "1' UN/**/ION SE/**/LECT--",
    ],
    
    'second_order': [
        # Stored XSS-like SQLi
        "admin'; UPDATE users SET password='hacked' WHERE username='admin'--",
    ],
}

LEGITIMATE_INPUTS = {
    'emails': [
        "john.doe@example.com",
        "user+tag@domain.co.uk",
        "name.surname@subdomain.company.com",
        "test_user123@example.org",
    ],
    
    'names': [
        "John O'Brien",  # Апостроф в имени!
        "Mary-Jane Watson",
        "José García",
        "François L'Équipe",
        "O'Malley & Sons",
    ],
    
    'search_queries': [
        "laptop 15 inch",
        "women's clothing",
        "SQL tutorial for beginners",
        "C++ programming guide",
        "5-star hotels in Paris",
        "2023-2024 trends",
    ],
    
    'urls': [
        "https://example.com/page?param=value",
        "http://subdomain.example.org:8080/path",
        "ftp://files.example.com/document.pdf",
    ],
    
    'technical': [
        "SELECT * FROM products",  # Легитимный SQL в документации
        "INSERT INTO table VALUES",  # Примеры кода
        "UPDATE settings SET value",  # Инструкции
        "version 1.2.3",
        "error: null pointer exception",
    ],
    
    'special_chars': [
        "Price: $99.99",
        "Discount: 20% off!",
        "Email: info@company.com",
        "Phone: +1-555-0123",
        "(555) 123-4567",
        "C:\\Users\\Documents\\file.txt",
    ],
}

# ============================================================================
# ТЕСТОВЫЕ КЛАССЫ
# ============================================================================

class TestBasicDetection:
    """Базовое тестирование детектирования"""
    
    @pytest.fixture(scope="class")
    def agent(self):
        """Создание агента для тестов"""
        train_initial_model("test_model.pkl")
        return SQLInjectionAgent(ml_model_path="test_model.pkl")
    
    def test_detect_all_attack_types(self, agent):
        """Тест: все типы атак должны детектироваться"""
        total_attacks = 0
        detected = 0
        failed = []
        
        for category, attacks in REAL_WORLD_ATTACKS.items():
            for attack in attacks:
                total_attacks += 1
                result = agent.analyze(attack)
                
                if result.is_malicious:
                    detected += 1
                else:
                    failed.append((category, attack, result.confidence))
        
        detection_rate = detected / total_attacks
        
        print(f"\n{'='*60}")
        print(f"ATTACK DETECTION RESULTS")
        print(f"{'='*60}")
        print(f"Total attacks: {total_attacks}")
        print(f"Detected: {detected}")
        print(f"Missed: {total_attacks - detected}")
        print(f"Detection rate: {detection_rate:.2%}")
        
        if failed:
            print(f"\nFailed to detect:")
            for cat, attack, conf in failed[:10]:  # Показываем первые 10
                print(f"  [{cat}] {attack[:50]}... (confidence: {conf:.2f})")
        
        # Требуем минимум 95% detection rate
        assert detection_rate >= 0.95, f"Detection rate too low: {detection_rate:.2%}"
    
    def test_legitimate_inputs_not_blocked(self, agent):
        """Тест: легитимные запросы НЕ должны блокироваться"""
        total_legitimate = 0
        false_positives = 0
        blocked = []
        
        for category, inputs in LEGITIMATE_INPUTS.items():
            for input_val in inputs:
                total_legitimate += 1
                result = agent.analyze(input_val)
                
                if result.is_malicious:
                    false_positives += 1
                    blocked.append((category, input_val, result.confidence))
        
        fp_rate = false_positives / total_legitimate
        
        print(f"\n{'='*60}")
        print(f"FALSE POSITIVE RESULTS")
        print(f"{'='*60}")
        print(f"Total legitimate: {total_legitimate}")
        print(f"False positives: {false_positives}")
        print(f"FP rate: {fp_rate:.2%}")
        
        if blocked:
            print(f"\nFalse positives:")
            for cat, inp, conf in blocked:
                print(f"  [{cat}] {inp} (confidence: {conf:.2f})")
        
        # Требуем максимум 5% false positive rate
        assert fp_rate <= 0.05, f"False positive rate too high: {fp_rate:.2%}"


class TestEdgeCases:
    """Тестирование граничных случаев"""
    
    @pytest.fixture(scope="class")
    def agent(self):
        train_initial_model("test_model.pkl")
        return SQLInjectionAgent(ml_model_path="test_model.pkl")
    
    def test_empty_string(self, agent):
        """Пустая строка не должна вызывать ошибку"""
        result = agent.analyze("")
        assert result.is_malicious == False
    
    def test_very_long_string(self, agent):
        """Очень длинная строка"""
        long_string = "a" * 10000
        result = agent.analyze(long_string)
        assert result is not None
    
    def test_unicode_characters(self, agent):
        """Unicode символы"""
        unicode_inputs = [
            "Привет мир",
            "你好世界",
            "مرحبا بالعالم",
            "🔥💻🚀",
        ]
        for inp in unicode_inputs:
            result = agent.analyze(inp)
            assert result is not None
    
    def test_special_apostrophes(self, agent):
        """Разные типы апострофов"""
        apostrophes = [
            "John O'Brien",  # ASCII
            "John O'Brien",  # Right single quotation mark
            "John O'Brien",  # Left single quotation mark
        ]
        
        for name in apostrophes:
            result = agent.analyze(name)
            # Имена с апострофами НЕ должны блокироваться
            assert result.is_malicious == False or result.confidence < 0.3


class TestPerformance:
    """Тестирование производительности"""
    
    @pytest.fixture(scope="class")
    def agent(self):
        train_initial_model("test_model.pkl")
        return SQLInjectionAgent(ml_model_path="test_model.pkl")
    
    def test_latency_under_100ms(self, agent):
        """Проверка latency < 100ms"""
        import time
        
        test_inputs = [
            "normal input",
            "' OR 1=1--",
            "john@example.com",
            "1' UNION SELECT NULL--",
        ]
        
        latencies = []
        
        for inp in test_inputs * 25:  # 100 запросов
            start = time.time()
            agent.analyze(inp)
            latency = (time.time() - start) * 1000  # в миллисекундах
            latencies.append(latency)
        
        avg_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]
        
        print(f"\n{'='*60}")
        print(f"PERFORMANCE RESULTS")
        print(f"{'='*60}")
        print(f"Average latency: {avg_latency:.2f}ms")
        print(f"P95 latency: {p95_latency:.2f}ms")
        print(f"Max latency: {max(latencies):.2f}ms")
        
        assert p95_latency < 100, f"P95 latency too high: {p95_latency:.2f}ms"


class TestConfidenceScores:
    """Тестирование уверенности детектирования"""
    
    @pytest.fixture(scope="class")
    def agent(self):
        train_initial_model("test_model.pkl")
        return SQLInjectionAgent(ml_model_path="test_model.pkl")
    
    def test_obvious_attacks_high_confidence(self, agent):
        """Очевидные атаки должны иметь высокую уверенность"""
        obvious_attacks = [
            "' OR '1'='1--",
            "1' UNION SELECT * FROM users--",
            "'; DROP TABLE users--",
        ]
        
        for attack in obvious_attacks:
            result = agent.analyze(attack)
            assert result.is_malicious == True
            assert result.confidence > 0.6, \
                f"Confidence too low for {attack}: {result.confidence}"
    
    def test_safe_inputs_low_confidence(self, agent):
        """Безопасные входы должны иметь низкую уверенность в малициозности"""
        safe_inputs = [
            "john.doe@example.com",
            "Product Name 123",
            "normal text",
        ]
        
        for inp in safe_inputs:
            result = agent.analyze(inp)
            assert result.is_malicious == False
            assert result.confidence < 0.2, \
                f"Confidence too high for safe input {inp}: {result.confidence}"


class TestRealWorldScenarios:
    """Реальные сценарии использования"""
    
    @pytest.fixture(scope="class")
    def agent(self):
        train_initial_model("test_model.pkl")
        return SQLInjectionAgent(ml_model_path="test_model.pkl")
    
    def test_ecommerce_search(self, agent):
        """Сценарий: поиск в интернет-магазине"""
        search_queries = [
            "women's shoes size 8",
            "laptop 15 inch",
            "iPhone 13 Pro",
            "SQL injection book",  # Легитимный поиск!
        ]
        
        for query in search_queries:
            result = agent.analyze(query)
            assert result.is_malicious == False
    
    def test_user_registration(self, agent):
        """Сценарий: регистрация пользователя"""
        legitimate_names = [
            "John O'Connor",
            "Mary-Jane Smith",
            "José García",
        ]
        
        malicious_names = [
            "admin' --",
            "'; DROP TABLE users--",
        ]
        
        for name in legitimate_names:
            result = agent.analyze(name)
            # Имена с апострофами могут давать небольшой риск, но не должны блокироваться
            assert result.risk_score < 0.5
        
        for name in malicious_names:
            result = agent.analyze(name)
            assert result.is_malicious == True


# ============================================================================
# STRESS TESTING
# ============================================================================

@pytest.mark.slow
class TestStressTesting:
    """Стресс-тестирование системы"""
    
    @pytest.fixture(scope="class")
    def agent(self):
        train_initial_model("test_model.pkl")
        return SQLInjectionAgent(ml_model_path="test_model.pkl")
    
    def test_concurrent_requests(self, agent):
        """Тест: одновременная обработка множества запросов"""
        import concurrent.futures
        
        test_inputs = [
            "normal input",
            "' OR 1=1--",
            "user@example.com",
        ] * 100  # 300 запросов
        
        def analyze(inp):
            return agent.analyze(inp)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(analyze, test_inputs))
        
        assert len(results) == len(test_inputs)
        assert all(r is not None for r in results)


# ============================================================================
# MAIN RUNNER
# ============================================================================

if __name__ == "__main__":
    print("="*70)
    print("ЗАПУСК КОМПЛЕКСНОГО ТЕСТИРОВАНИЯ SQL INJECTION DETECTOR")
    print("="*70)
    
    # Запуск всех тестов
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-s",  # Показывать print output
        "--durations=10",  # Показать 10 самых медленных тестов
    ])
