# 🚀 Быстрый старт

## Установка за 3 шага

```bash
# 1. Установите зависимости
pip install -r requirements.txt

# 2. Обучите модель
python cli.py train

# 3. Запустите сервер
python app.py
```

Готово! Сервер запущен на http://localhost:8000 🎉

---

## Примеры использования

### 1️⃣ CLI - Анализ текста

```bash
# Проверить текст на SQL инъекцию
python cli.py analyze "' OR '1'='1"

# Проверить безопасный текст
python cli.py analyze "john@example.com"
```

**Вывод:**
```
✓ РЕЗУЛЬТАТ АНАЛИЗА
Вредоносный: ДА
Уверенность: 95%
Метод детектирования: signature
Риск-скор: 98%
```

---

### 2️⃣ CLI - Интерактивное тестирование

```bash
python cli.py test
```

Введите любой текст для проверки:
```
Enter text to test: admin' --
⚠ MALICIOUS DETECTED!
Confidence: 92%
```

---

### 3️⃣ CLI - Бенчмарк

```bash
python cli.py benchmark
```

Запустит тесты на 10 примерах и покажет точность:
```
✓ Email address                | Expected: False | Got: False | Conf: 15%
✓ Classic SQL injection        | Expected: True  | Got: True  | Conf: 95%
...
Accuracy: 10/10 (100%)
```

---

### 4️⃣ API - Через curl

```bash
# Запустите сервер
python app.py

# В другом терминале:
curl -X POST "http://localhost:8000/api/analyze" \
  -H "Content-Type: application/json" \
  -d '{"text": "'"'"' OR '"'"'1'"'"'='"'"'1"}'
```

**Ответ:**
```json
{
  "is_malicious": true,
  "confidence": 0.95,
  "detection_method": "signature",
  "risk_score": 0.98
}
```

---

### 5️⃣ API - Через Python requests

```python
import requests

response = requests.post(
    "http://localhost:8000/api/analyze",
    json={"text": "' OR '1'='1"}
)

result = response.json()
print(f"Вредоносный: {result['is_malicious']}")
print(f"Уверенность: {result['confidence']:.2%}")
```

---

### 6️⃣ В Python коде

```python
from sql_injection_detector import SQLInjectionAgent

# Инициализация
agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")

# Анализ
result = agent.analyze("' OR '1'='1")

if result.is_malicious:
    print(f"⚠️  SQL INJECTION DETECTED!")
    print(f"Уверенность: {result.confidence:.2%}")
    print(f"Паттерны: {result.matched_patterns}")
else:
    print("✅ Текст безопасен")
```

---

### 7️⃣ Интеграция в FastAPI

```python
from fastapi import FastAPI, HTTPException
from sql_injection_detector import SQLInjectionAgent
from fastapi_middleware import SQLInjectionMiddleware

app = FastAPI()
agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")

# Добавляем middleware для автоматической проверки
app.add_middleware(
    SQLInjectionMiddleware,
    agent=agent,
    enabled=True,
    block_on_detection=True,
    whitelist_paths=['/health', '/docs']
)

@app.get("/search")
async def search(q: str):
    # Параметр q будет автоматически проверен middleware
    return {"query": q, "results": []}
```

Теперь все запросы автоматически проверяются!

---

## 🧪 Тестирование

```bash
# Запустить все тесты
pytest tests/ -v

# Запустить с покрытием кода
pytest tests/ --cov=. --cov-report=html

# Открыть отчет о покрытии
start htmlcov/index.html  # Windows
open htmlcov/index.html   # Mac
```

---

## 📊 Мониторинг

### Метрики через API

```bash
curl http://localhost:8000/metrics
```

**Ответ:**
```json
{
  "total_requests": 1000,
  "blocked_requests": 50,
  "block_rate": 0.05,
  "uptime_seconds": 3600
}
```

### Статус сервера

```bash
python cli.py status
```

**Вывод:**
```
Server is ONLINE
Status: healthy
Agent: active

METRICS:
Total Requests: 1000
Blocked: 50
Block Rate: 5.00%
```

---

## 🔧 Полезные команды

```bash
# Обучить модель с расширенным датасетом
python train_model.py

# Обучить простую модель (быстрее)
python cli.py train --simple

# Экспортировать датасет
python cli.py export-dataset -o my_dataset.json

# Запустить сервер на другом порту
python cli.py server --port 8080

# Проверить статус удаленного сервера
python cli.py status --api-url http://example.com:8000
```

---

## 📝 Примеры вредоносных запросов

Вот несколько примеров, которые агент успешно обнаруживает:

| Запрос | Тип атаки |
|--------|-----------|
| `' OR '1'='1` | Classic |
| `admin' --` | Comment-based |
| `' UNION SELECT * FROM users--` | UNION-based |
| `'; DROP TABLE users--` | Destructive |
| `' AND SLEEP(5)--` | Time-based blind |
| `%27%20OR%201=1--` | URL-encoded |

Попробуйте их:
```bash
python cli.py analyze "' OR '1'='1"
python cli.py analyze "admin' --"
python cli.py analyze "'; DROP TABLE users--"
```

---

## 🛡️ Безопасная работа с базой данных

```python
from safe_database_layer import SafeQueryBuilder

# Вместо небезопасного:
# query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ ОПАСНО!

# Используйте:
query, params = SafeQueryBuilder.select(
    table="users",
    conditions={"id": user_id}
)
# query = "SELECT * FROM users WHERE id = :param_0"  # ✅ БЕЗОПАСНО!
# params = {"param_0": user_id}
```

---

## 🚨 Что делать при обнаружении атаки?

1. **Блокировать запрос** (middleware делает это автоматически)
2. **Логировать событие** (автоматически в structlog формате)
3. **Отправить алерт** (настройте webhook в middleware)
4. **Проанализировать** - проверьте логи для понимания источника атаки

---

## 💡 Pro Tips

1. **Используйте whitelist** для путей, которые не нужно проверять:
   ```python
   whitelist_paths=['/health', '/metrics', '/docs']
   ```

2. **Настройте пороги** для вашего случая:
   ```python
   agent.DETECTION_THRESHOLD = 0.6  # Менее чувствительный
   agent.DETECTION_THRESHOLD = 0.4  # Более чувствительный
   ```

3. **Мониторьте false positives**:
   ```bash
   # Проверьте метрики
   curl http://localhost:8000/metrics
   ```

4. **Обновляйте модель** на реальных данных:
   ```bash
   curl -X POST http://localhost:8000/api/train \
     -H "Content-Type: application/json" \
     -d '{"malicious_samples": [...], "safe_samples": [...]}'
   ```

---

## 🎓 Дополнительное обучение

- Читайте полную документацию в `README.md`
- Изучите примеры в `tests/test_agent.py`
- Посмотрите код в `sql_injection_detector.py`
- Проверьте безопасные паттерны в `safe_database_layer.py`

---

## ❓ FAQ

**Q: Как часто нужно переобучать модель?**
A: При появлении новых типов атак или false positives. Обычно раз в месяц.

**Q: Какая производительность?**
A: < 10ms на запрос. Для большинства приложений это не критично.

**Q: Можно ли использовать в production?**
A: Да! Middleware работает в non-blocking режиме и не влияет на доступность.

**Q: Что делать с false positives?**
A: Добавьте в whitelist или переобучите модель с вашими данными.

---

**Готовы начать? Запустите:**

```bash
python cli.py train && python app.py
```

🎉 Наслаждайтесь защитой от SQL инъекций!
