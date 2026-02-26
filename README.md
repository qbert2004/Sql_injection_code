# 🛡️ SQL Injection Detection System

> Система обнаружения SQL-инъекций на основе ансамбля ML-моделей и семантического анализа.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.121-green.svg)](https://fastapi.tiangolo.com/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0%2B-red.svg)](https://pytorch.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 О проекте

Это учебный пример промышленной системы безопасности, которая анализирует текстовый ввод и определяет, является ли он SQL-инъекцией. Проект демонстрирует, как сочетать машинное обучение с классическим программным анализом для решения задачи кибербезопасности.

**Система умеет:**
- Классифицировать запросы на 4 класса: `SAFE`, `INVALID`, `SUSPICIOUS`, `INJECTION`
- Определять тип атаки (UNION, BOOLEAN, TIME-BASED, DROP TABLE и др.)
- Объяснять своё решение пошагово (explainability)
- Работать как REST API

**Ключевые характеристики:**

| Метрика | Значение |
|---|---|
| Точность обнаружения атак | **99.3%** |
| Ложные срабатывания | **1.5%** |
| Время анализа | **~60 мс / запрос** (CPU) |
| Типов атак распознаётся | **9** |

---

## 🏗️ Как это работает

Каждый запрос проходит через **6 последовательных слоёв**:

```
Входной текст
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Слой 0 — Нормализация                                  │
│  URL-декодирование, удаление null-байт, Unicode NFKC,   │
│  удаление SQL-комментариев, нормализация пробелов        │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Слой 1 — Лексический фильтр (быстрый путь)             │
│  Regex-скан по ключевым словам SQL.                      │
│  Если SQL не обнаружен → сразу SAFE (без ML)            │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Слой 2 — ML Ансамбль                                   │
│  ┌─────────────────┐     ┌──────────────────────────┐  │
│  │  Random Forest  │     │       VDCNN-9 (CNN)       │  │
│  │  вес = 0.35     │     │       вес = 0.65          │  │
│  │  TF-IDF + feat  │     │  символьная нейросеть     │  │
│  └────────┬────────┘     └────────────┬─────────────┘  │
│           └──────────────┬────────────┘                 │
│                   S = 0.35·P_rf + 0.65·P_cnn            │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Слой 3 — Семантическая валидация SQL                   │
│  Парсинг структуры SQL (sqlglot), проверка на           │
│  реальную SQL-атаку. Ключевой «предохранитель»:         │
│  ML ОДИН не может поставить INJECTION — нужна семантика │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Слой 4 — Движок решений (8 правил приоритета)          │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Слой 5 — Серьёзность и действие                        │
│  ALLOW / LOG / CHALLENGE / BLOCK                        │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Слой 6 — Объяснение (Explainability)                   │
│  Детальный trace, MITRE ATT&CK, SIEM-поля               │
└─────────────────────────────────────────────────────────┘
```

### Правила принятия решений

| Правило | Условие | Решение | Действие |
|---------|---------|---------|----------|
| 0 | P_cnn ≥ 0.70 AND P_rf < 0.50 AND sem < 2.0 | INVALID | LOG |
| 1 | S ≥ 0.60 AND sem ≥ 2.0 | **INJECTION** | **BLOCK** |
| 2 | P_cnn ≥ 0.75 AND sem ≥ 3.0 | **INJECTION** | **BLOCK** |
| 3 | P_rf ≥ 0.70 AND sem ≥ 2.0 | **INJECTION** | **BLOCK** |
| 4 | S < 0.30 | SAFE | ALLOW |
| 5 | sem ≥ 1.0 | SUSPICIOUS | CHALLENGE |
| 6 | (по умолчанию) | INVALID | LOG |

### Используемые модели

| Модель | Тип | Точность | Параметры |
|--------|-----|---------|-----------|
| **VDCNN-9** | PyTorch CNN | **99.90%** | 7M, Conneau et al. 2017 |
| **Random Forest** | scikit-learn | **99.18%** | TF-IDF + ручные признаки |
| **Ансамбль** | Fusion (0.65 CNN + 0.35 RF) | **99.30%** | — |

---

## 📁 Структура проекта

```
Sql_injection_code/
│
├── 🔧 Основной код
│   ├── sql_injection_detector.py   # Детектор — 6-слойный пайплайн
│   ├── agent.py                    # AI-агент: IP-репутация, сессии, эскалация
│   ├── api_server.py               # REST API (FastAPI)
│   ├── config.py                   # Конфигурация (env-переменные, датаклассы)
│   ├── incident_logger.py          # Логирование инцидентов (SQLite + SIEM)
│   ├── state_backend.py            # Хранилище состояния (SQLite / Redis)
│   ├── logger.py                   # Структурированные логи (structlog)
│   └── metrics.py                  # Prometheus-метрики
│
├── 🧠 Модели (models/)
│   ├── char_cnn_model.py           # Архитектура VDCNN-9
│   ├── char_bilstm_model.py        # Архитектура BiLSTM (альтернатива)
│   ├── char_tokenizer.py           # Токенизатор на уровне символов
│   ├── char_cnn_detector.pt        # Обученные веса CNN (PyTorch)
│   └── char_bilstm_detector.pt     # Обученные веса BiLSTM
│
├── 🏋️ Обучение (training/)
│   ├── train_rf.py                 # Обучение Random Forest
│   ├── train_cnn.py                # Обучение VDCNN (CUDA + AMP)
│   ├── train_bilstm.py             # Обучение BiLSTM
│   └── generate_dataset.py         # Генерация датасета
│
├── 🧪 Тесты (tests/)
│   ├── test_detector.py            # Юнит-тесты детектора
│   ├── test_api.py                 # Интеграционные тесты API
│   ├── test_adversarial_fuzz.py    # Фазз-тестирование
│   ├── test_bypass_audit.py        # Аудит попыток обхода защиты
│   ├── test_distributed.py         # Тесты распределённого состояния
│   ├── test_state_backend.py       # Тесты бэкенда хранилища
│   └── conftest.py                 # Фикстуры pytest
│
├── 📊 Данные (data/)
│   ├── dataset.csv                 # Основной датасет
│   └── massive_test_100k.csv       # 100k тестовых примеров
│
├── 🖥️ Демо и нагрузка
│   ├── streamlit_demo.py           # Интерактивное веб-демо
│   ├── benchmark.py                # Замер производительности (p50/p95/p99)
│   ├── load_test.py                # Нагрузочное тестирование (multiprocessing)
│   └── soak_test.py                # Длительное стресс-тестирование
│
├── 🐳 DevOps
│   ├── Dockerfile
│   ├── docker-compose.yml          # API + Redis + Prometheus + Grafana
│   └── .github/workflows/          # CI/CD
│
└── 📚 Документация
    ├── README.md                   # ← вы здесь
    ├── DOCUMENTATION.md            # Полная техническая документация
    ├── ARCHITECTURE_10_10.md       # Детальное описание архитектуры
    ├── SECURITY_WHITEPAPER.md      # Whitepaper по безопасности
    ├── CHANGELOG.md                # История версий
    └── VDCNN_Model.ipynb           # Jupyter-ноутбук: обучение модели
```

---

## 🚀 Быстрый старт

### 1. Клонировать репозиторий

```bash
git clone https://github.com/qbert2004/Sql_injection_code.git
cd Sql_injection_code
```

### 2. Создать виртуальное окружение

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 3. Установить зависимости

```bash
pip install -r requirements.txt
```

> ⚠️ Для полной функциональности нужны `torch` и `scikit-learn`. Без них система работает в режиме деградации (только лексический фильтр).

### 4. Запустить

**Вариант A — API-сервер:**
```bash
python api_server.py
# Сервер: http://localhost:5000
# Swagger UI: http://localhost:5000/docs
```

**Вариант B — Интерактивное демо:**
```bash
streamlit run streamlit_demo.py
# Браузер: http://localhost:8501
```

**Вариант C — Python напрямую:**
```python
from sql_injection_detector import SQLInjectionEnsemble

detector = SQLInjectionEnsemble()

# Безопасный запрос
result = detector.detect("SELECT * FROM users WHERE id = 1")
print(result['decision'])      # SAFE
print(result['action'])        # ALLOW

# SQL-инъекция
result = detector.detect("' OR '1'='1")
print(result['decision'])      # INJECTION
print(result['action'])        # BLOCK
print(result['attack_type'])   # BOOLEAN_BASED
print(result['score'])         # 1.0
print(result['severity'])      # MEDIUM
```

---

## 🔌 REST API

### Проверить одну строку

```http
POST http://localhost:5000/api/check
Content-Type: application/json

{
  "text": "' UNION SELECT username, password FROM users--"
}
```

**Ответ:**
```json
{
  "decision": "INJECTION",
  "action": "BLOCK",
  "blocked": true,
  "score": 1.0,
  "attack_type": "UNION_BASED",
  "severity": "HIGH",
  "incident_id": 42,
  "explanation": {
    "summary": "UNION-based data extraction SQL injection detected with HIGH confidence.",
    "decision_factors": [
      "Ensemble score 1.00 exceeds high-confidence threshold 0.60",
      "Semantic score 13.0 exceeds minimum threshold 2.0",
      "Model agreement: RF and CNN signals converge"
    ]
  }
}
```

### Проверить форму (несколько полей)

```http
POST http://localhost:5000/api/validate
Content-Type: application/json

{
  "fields": {
    "username": "admin",
    "password": "' OR '1'='1",
    "email": "user@example.com"
  }
}
```

**Ответ:**
```json
{
  "safe": false,
  "blocked_fields": ["password"],
  "results": {
    "username": {"decision": "SAFE",      "action": "ALLOW", "score": 0.00},
    "password": {"decision": "INJECTION", "action": "BLOCK", "score": 1.00},
    "email":    {"decision": "SAFE",      "action": "ALLOW", "score": 0.02}
  }
}
```

### Все эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/check` | Проверить одну строку |
| `POST` | `/api/validate` | Проверить форму |
| `GET` | `/api/health` | Статус сервера и моделей |
| `GET` | `/api/stats` | Статистика инцидентов |
| `GET` | `/api/incidents` | Список инцидентов (с пагинацией) |
| `GET` | `/api/export` | SIEM-экспорт (JSON / CSV / CEF) |
| `GET` | `/api/agent/stats` | Статистика AI-агента |
| `GET` | `/api/agent/ip/{ip}` | Репутация IP-адреса |
| `GET` | `/metrics` | Prometheus-метрики |
| `GET` | `/docs` | Swagger UI (автодокументация) |

---

## 🧨 Типы обнаруживаемых атак

| Тип атаки | Пример | Серьёзность |
|-----------|--------|-------------|
| `BOOLEAN_BASED` | `' OR '1'='1` | MEDIUM |
| `COMMENT_TRUNCATION` | `admin'--` | LOW |
| `UNION_BASED` | `' UNION SELECT * FROM users--` | HIGH |
| `TIME_BASED` | `' AND SLEEP(5)--` | MEDIUM |
| `STACKED_QUERY` | `'; DROP TABLE users--` | **CRITICAL** |
| `ERROR_BASED` | `' AND extractvalue(1,concat(...))--` | HIGH |
| `OS_COMMAND` | `'; EXEC xp_cmdshell('dir')--` | **CRITICAL** |
| `OUT_OF_BAND` | DNS-эксфильтрация данных | **CRITICAL** |
| `NONE` | Безопасный ввод | INFO |

**Дополнительно:** обнаруживает обфусцированные атаки через URL-кодирование (`%27%20OR`), многострочные комментарии (`'/**/OR/**/1=1--`), Unicode-подмену символов и другие техники обхода.

---

## 🧪 Запуск тестов

```bash
# Все тесты
pytest tests/ -v

# С отчётом о покрытии
pytest tests/ --cov=. --cov-report=html

# Только юнит-тесты детектора
pytest tests/test_detector.py -v

# Тесты API (нужен запущенный сервер)
pytest tests/test_api.py -v

# Фазз-тестирование (генерирует случайные атаки)
pytest tests/test_adversarial_fuzz.py -v
```

### Нагрузочное и стресс-тестирование

```bash
# Замер скорости (p50/p95/p99 латентность)
python benchmark.py

# Нагрузочный тест (4 процесса, 1000 запросов)
python load_test.py --workers 4 --requests 1000

# Длительный тест на стабильность (5 минут)
python soak_test.py --duration 300
```

---

## ⚙️ Конфигурация

Скопируйте `.env.example` в `.env` и настройте нужные параметры:

```bash
cp .env.example .env
```

Основные переменные:

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `API_HOST` | `0.0.0.0` | Адрес сервера |
| `API_PORT` | `5000` | Порт сервера |
| `API_KEY` | — | Ключ авторизации (опционально) |
| `ENSEMBLE_W_CNN` | `0.65` | Вес CNN в ансамбле |
| `ENSEMBLE_W_RF` | `0.35` | Вес Random Forest в ансамбле |
| `ENSEMBLE_TAU_HIGH` | `0.60` | Порог уверенности для блокировки |
| `LOG_LEVEL` | `INFO` | Уровень логирования (`DEBUG`/`INFO`/`WARNING`) |
| `SQLI_BACKEND` | `sqlite` | Хранилище состояния (`sqlite` / `redis`) |
| `REDIS_URL` | — | URL Redis (для распределённого режима) |

---

## 🐳 Docker

```bash
# Запустить всё (API + Redis + Prometheus + Grafana)
docker-compose up -d

# Только API-сервер
docker build -t sqli-detector .
docker run -p 5000:5000 sqli-detector
```

---

## 🤖 AI-агент

Помимо детектора, проект содержит интеллектуальный агент (`agent.py`), который работает поверх детектора:

- **Память IP** — каждый IP получает оценку репутации от 0.0 (чистый) до 1.0 (атакующий)
- **Память сессий** — отслеживает паттерны атак внутри одной сессии
- **Эскалация** — 3+ подозрительных запроса за 2 минуты → автоматическая блокировка
- **Адаптация** — при высокой репутации атакующего порог обнаружения снижается (×0.75)
- **Онлайн-обучение** — SGDClassifier адаптируется к новым атакам без переобучения

---

## 🏋️ Обучение моделей с нуля

Если хотите обучить модели самостоятельно:

```bash
# Random Forest (~2 мин, CPU)
python training/train_rf.py

# VDCNN (рекомендуется GPU, работает и на CPU)
python training/train_cnn.py --epochs 35

# BiLSTM (альтернативная архитектура)
python training/train_bilstm.py

# Посмотреть процесс обучения в Jupyter
jupyter notebook VDCNN_Model.ipynb
```

Датасет: `data/dataset.csv` и `SQL_Dataset_Extended.csv`.

---

## 📚 Дополнительные материалы

| Документ | Описание |
|----------|----------|
| [DOCUMENTATION.md](DOCUMENTATION.md) | Полная техническая документация |
| [ARCHITECTURE_10_10.md](ARCHITECTURE_10_10.md) | Детальное описание архитектуры |
| [SECURITY_WHITEPAPER.md](SECURITY_WHITEPAPER.md) | Security Whitepaper (чеклист из 24 пунктов) |
| [CHANGELOG.md](CHANGELOG.md) | История всех версий (v3.0 → v3.9) |
| [VDCNN_Model.ipynb](VDCNN_Model.ipynb) | Jupyter: обучение нейросети шаг за шагом |

---

## 🤝 Как внести вклад

1. Сделайте fork репозитория
2. Создайте ветку: `git checkout -b feature/my-feature`
3. Внесите изменения и добавьте тесты
4. Запустите тесты: `pytest tests/`
5. Отправьте Pull Request

---

## 📄 Лицензия

MIT License — см. файл [LICENSE](LICENSE).
