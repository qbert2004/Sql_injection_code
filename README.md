# SQL Injection Protector AI Agent

**Полноценный AI агент для обнаружения и предотвращения SQL инъекций**

Многоуровневая система защиты, использующая сигнатурный анализ, машинное обучение и эвристический анализ для обнаружения SQL инъекций в реальном времени.

---

## 🚀 Возможности

- ✅ **Многоуровневое детектирование**
  - Сигнатурный анализ (regex паттерны)
  - Machine Learning (TF-IDF + Logistic Regression)
  - Эвристический анализ

- ✅ **REST API** (FastAPI)
  - Endpoint для анализа текста
  - Обучение модели через API
  - Метрики и мониторинг

- ✅ **FastAPI Middleware**
  - Автоматическая проверка всех входящих запросов
  - Проверка query параметров, body, headers
  - Whitelist путей

- ✅ **CLI Interface**
  - Анализ текста
  - Обучение модели
  - Интерактивное тестирование
  - Бенчмарки

- ✅ **Безопасный Database Layer**
  - Параметризованные запросы
  - Поддержка SQLAlchemy, asyncpg, psycopg2
  - Query Builder

- ✅ **Логирование и мониторинг**
  - Structured logging (structlog)
  - SIEM-совместимый формат
  - Метрики производительности

---

## 📦 Установка

### 1. Клонирование репозитория

```bash
git clone <repository-url>
cd SQL_INJECTION_PROTECTOR_AI_AGENT
```

### 2. Создание виртуального окружения

```bash
python -m venv .venv
```

**Windows:**
```bash
.venv\Scripts\activate
```

**Linux/Mac:**
```bash
source .venv/bin/activate
```

### 3. Установка зависимостей

```bash
pip install -r requirements.txt
```

---

## 🎯 Быстрый старт

### Вариант 1: CLI

```bash
# Обучение модели
python cli.py train

# Анализ текста
python cli.py analyze "' OR '1'='1"

# Интерактивное тестирование
python cli.py test

# Бенчмарк
python cli.py benchmark
```

### Вариант 2: API сервер

```bash
# Запуск сервера
python app.py

# Или через CLI
python cli.py server
```

Сервер будет доступен по адресу: http://localhost:8000

📊 **Документация API:** http://localhost:8000/docs

### Вариант 3: Импорт в код

```python
from sql_injection_detector import SQLInjectionAgent

# Инициализация агента
agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")

# Анализ текста
result = agent.analyze("' OR '1'='1")

print(f"Вредоносный: {result.is_malicious}")
print(f"Уверенность: {result.confidence:.2%}")
print(f"Метод: {result.detection_method}")
```

---

## 📖 Документация

### CLI Команды

#### `analyze` - Анализ текста

```bash
# Локальный анализ
python cli.py analyze "text to analyze"

# Анализ через API
python cli.py analyze "text to analyze" --api
```

#### `train` - Обучение модели

```bash
# Продвинутое обучение (рекомендуется)
python cli.py train

# Быстрое обучение
python cli.py train --simple
```

#### `test` - Интерактивное тестирование

```bash
python cli.py test
```

#### `benchmark` - Запуск бенчмарка

```bash
python cli.py benchmark
```

#### `server` - Запуск API сервера

```bash
python cli.py server --host 0.0.0.0 --port 8000
```

#### `status` - Статус сервера

```bash
python cli.py status --api-url http://localhost:8000
```

#### `export-dataset` - Экспорт датасета

```bash
python cli.py export-dataset -o dataset.json --augment
```

---

### API Endpoints

#### `POST /api/analyze` - Анализ текста

**Request:**
```json
{
  "text": "' OR '1'='1",
  "source": "user_input"
}
```

**Response:**
```json
{
  "is_malicious": true,
  "confidence": 0.95,
  "detection_method": "signature",
  "matched_patterns": ["or_injection", "quote_escape"],
  "risk_score": 0.98,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### `GET /health` - Health Check

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "agent_status": "active"
}
```

#### `GET /metrics` - Метрики

```json
{
  "total_requests": 1000,
  "blocked_requests": 50,
  "suspicious_requests": 10,
  "block_rate": 0.05,
  "uptime_seconds": 3600
}
```

#### `POST /api/train` - Обучение модели

**Request:**
```json
{
  "malicious_samples": ["' OR '1'='1", "admin' --"],
  "safe_samples": ["john@example.com", "Product123"]
}
```

---

### Интеграция в FastAPI приложение

```python
from fastapi import FastAPI
from sql_injection_detector import SQLInjectionAgent
from fastapi_middleware import SQLInjectionMiddleware

app = FastAPI()

# Инициализация агента
agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")

# Добавление middleware
app.add_middleware(
    SQLInjectionMiddleware,
    agent=agent,
    enabled=True,
    block_on_detection=True,
    whitelist_paths=['/health', '/docs', '/openapi.json']
)

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    # Параметры будут автоматически проверены middleware
    return {"user_id": user_id}
```

---

### Безопасный Database Layer

```python
from safe_database_layer import SafeQueryBuilder, SafeAsyncPostgresRepository

# Query Builder
query, params = SafeQueryBuilder.select(
    table="users",
    columns=["id", "username"],
    conditions={"status": "active"},
    limit=10
)
# query: "SELECT id, username FROM users WHERE status = :param_0 LIMIT :limit"
# params: {"param_0": "active", "limit": 10}

# Async PostgreSQL
repo = SafeAsyncPostgresRepository("postgresql://user:pass@localhost/db")
await repo.initialize()

users = await repo.execute_safe_query(
    "SELECT * FROM users WHERE email = $1",
    "user@example.com"
)
```

---

## 🧪 Тестирование

### Запуск тестов

```bash
# Все тесты
pytest tests/ -v

# С покрытием
pytest tests/ --cov=. --cov-report=html

# Конкретный тест
pytest tests/test_agent.py::TestSQLInjectionAgent::test_detect_classic_injection -v
```

---

## 📊 Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    FastAPI Application                   │
│                     (app.py)                            │
└──────────────────────┬──────────────────────────────────┘
                       │
            ┌──────────▼──────────┐
            │ SQL Injection       │
            │ Middleware          │
            └──────────┬──────────┘
                       │
        ┌──────────────▼───────────────┐
        │  SQL Injection Agent         │
        │  (sql_injection_detector.py) │
        └──────────────┬───────────────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
┌──────▼──────┐ ┌─────▼─────┐ ┌──────▼──────┐
│ Signature   │ │ ML        │ │ Heuristic   │
│ Policy      │ │ Detector  │ │ Analyzer    │
│ (Regex)     │ │ (TF-IDF)  │ │ (Stats)     │
└─────────────┘ └───────────┘ └─────────────┘
```

---

## 🔒 Методы детектирования

### 1. Сигнатурный анализ (Signature Policy)

Использует регулярные выражения для поиска известных паттернов SQL инъекций:

- `UNION SELECT` атаки
- SQL комментарии (`--`, `#`, `/* */`)
- `DROP TABLE`, `DELETE`, `UPDATE` команды
- `xp_cmdshell` и другие системные команды
- Encoded инъекции (hex, URL encoding)

### 2. Machine Learning (ML Detector)

- **Алгоритм:** TF-IDF Vectorization + Logistic Regression
- **Features:** Character-level n-grams (2-5 символов)
- **Обучение:** На размеченном датасете вредоносных и безопасных запросов

### 3. Эвристический анализ (Heuristic Analyzer)

Анализирует статистические характеристики:

- Длина строки
- Процент специальных символов
- Количество SQL ключевых слов
- Энтропия строки
- Encoded символы

---

## 📈 Производительность

**Средняя скорость анализа:** < 10ms на запрос

**Точность (на тестовом датасете):**
- Accuracy: ~95%
- Precision: ~92%
- Recall: ~96%
- F1-Score: ~94%

---

## 🛡️ Примеры обнаруживаемых атак

| Тип атаки | Пример | Обнаружено |
|-----------|--------|------------|
| Classic | `' OR '1'='1` | ✅ |
| UNION-based | `' UNION SELECT * FROM users--` | ✅ |
| Comment-based | `admin' --` | ✅ |
| Time-based blind | `' AND SLEEP(5)--` | ✅ |
| Boolean-based blind | `' AND 1=1--` | ✅ |
| Stacked queries | `'; DROP TABLE users--` | ✅ |
| Encoded | `%27%20OR%201=1--` | ✅ |

---

## 🔧 Конфигурация

### Настройка порогов детектирования

```python
agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")

# Изменение порогов
agent.DETECTION_THRESHOLD = 0.6  # Default: 0.5
agent.RISK_THRESHOLD = 0.7       # Default: 0.6
```

### Настройка middleware

```python
app.add_middleware(
    SQLInjectionMiddleware,
    agent=agent,
    enabled=True,                # Включить/выключить
    block_on_detection=True,      # Блокировать или только логировать
    check_query_params=True,      # Проверять query параметры
    check_body=True,              # Проверять body
    check_headers=True,           # Проверять headers
    whitelist_paths=['/health'],  # Whitelist путей
    alert_webhook="https://...",  # Webhook для алертов
    max_request_size=1024*1024    # Максимальный размер body
)
```

---

## 📝 Логирование

Система использует структурированное логирование (structlog) с SIEM-совместимым форматом:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "sql_injection_blocked",
  "severity": "critical",
  "confidence": 0.95,
  "risk_score": 0.98,
  "detection_method": "signature",
  "matched_patterns": ["or_injection"],
  "action": "blocked",
  "client_ip": "192.168.1.100",
  "path": "/api/users",
  "processing_time_ms": 5.2
}
```

---

## 🤝 Вклад в проект

Мы приветствуем вклад в проект! Пожалуйста:

1. Форкните репозиторий
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

---

## 📄 Лицензия

Этот проект находится под лицензией MIT - см. файл [LICENSE](LICENSE) для деталей.

---

## 🙏 Благодарности

- OWASP за документацию по SQL Injection
- Сообщество FastAPI
- Scikit-learn team

---

## 📞 Контакты

Если у вас есть вопросы или предложения, создайте issue в репозитории.

---

## 🗺️ Roadmap

- [ ] Поддержка NoSQL injection
- [ ] Интеграция с Prometheus для метрик
- [ ] Dashboard для мониторинга
- [ ] Поддержка GraphQL injection
- [ ] Docker контейнер
- [ ] Kubernetes Helm chart

---

**Made with ❤️ for cybersecurity**
