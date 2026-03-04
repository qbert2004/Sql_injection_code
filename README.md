# SQL Injection Detection System

Многоуровневая система обнаружения SQL-инъекций на основе ансамбля ML-моделей и семантического анализа.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.121-green.svg)](https://fastapi.tiangolo.com/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0%2B-red.svg)](https://pytorch.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

| Метрика | Значение |
|---|---|
| Точность обнаружения | **99.3%** |
| Ложные срабатывания | **1.5%** |
| Время анализа | **~60 мс / запрос** |
| Типов атак | **9** |
| Тестов | **495 passed** |

---

## Как это работает

Каждый запрос проходит **7 слоёв**:

```
Входной текст
    │
    ▼  Слой 0 — Нормализация
       URL-декодирование, null-байты, Unicode NFKC, SQL-комментарии
    │
    ▼  Слой 1 — Лексический фильтр (быстрый путь)
       Если SQL не обнаружен → сразу SAFE (без ML)
    │
    ▼  Слой 2 — ML Ансамбль
       Random Forest (35%) + VDCNN-9 CNN (65%) = score S
    │
    ▼  Слой 3 — Семантическая валидация (sqlglot)
       ML один не может поставить INJECTION — нужна семантика
    │
    ▼  Слой 4 — Движок решений (8 правил приоритета)
    │
    ▼  Слой 5 — Серьёзность и действие: ALLOW / LOG / BLOCK
    │
    ▼  Слой 6 — Объяснение (trace, MITRE ATT&CK, SIEM-поля)
```

### Модели

| Модель | Точность | Описание |
|--------|----------|----------|
| VDCNN-9 (CNN) | **99.90%** | Символьная нейросеть, PyTorch |
| Random Forest | **99.18%** | TF-IDF + ручные признаки, scikit-learn |
| Ансамбль | **99.30%** | 0.65 × CNN + 0.35 × RF |

### Типы обнаруживаемых атак

| Тип | Пример | Критичность |
|-----|--------|-------------|
| `BOOLEAN_BASED` | `' OR '1'='1` | MEDIUM |
| `COMMENT_TRUNCATION` | `admin'--` | LOW |
| `UNION_BASED` | `' UNION SELECT * FROM users--` | HIGH |
| `TIME_BASED` | `' AND SLEEP(5)--` | MEDIUM |
| `STACKED_QUERY` | `'; DROP TABLE users--` | CRITICAL |
| `ERROR_BASED` | `' AND extractvalue(1,...)--` | HIGH |
| `OS_COMMAND` | `'; EXEC xp_cmdshell('dir')--` | CRITICAL |
| `OUT_OF_BAND` | DNS-эксфильтрация | CRITICAL |

---

## Быстрый старт

### 1. Клонировать и установить

```bash
git clone https://github.com/qbert2004/Sql_injection_code.git
cd Sql_injection_code

python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS

pip install -r requirements.txt
```

### 2. Запустить API-сервер

```bash
.venv\Scripts\python -m uvicorn api_server:app --host 0.0.0.0 --port 5000
```

- API: `http://localhost:5000`
- Swagger UI: `http://localhost:5000/docs`

### 3. Запустить демо-сайт (TenderPro)

```bash
.venv\Scripts\python demo_site.py
```

- Сайт закупок: `http://localhost:8080`
- Панель безопасности (SOC): `http://localhost:8080/admin`

### 4. Использовать как библиотеку

```python
from sql_injection_detector import SQLInjectionEnsemble

detector = SQLInjectionEnsemble()

result = detector.detect("' OR '1'='1")
print(result['decision'])     # INJECTION
print(result['action'])       # BLOCK
print(result['attack_type'])  # BOOLEAN_BASED
print(result['score'])        # 1.0
```

---

## Интеграция в существующий проект

Система встаёт между вашим приложением и базой данных:

```
Пользователь → Ваш сайт → [SQL Injection Detector] → База данных
```

**Вариант 1 — через API** (любой язык):

```python
import requests

def is_safe(user_input: str) -> bool:
    r = requests.post("http://localhost:5000/api/check",
                      json={"text": user_input})
    return r.json()["decision"] == "SAFE"

# В коде сайта — перед любым SQL-запросом:
if not is_safe(request.form["username"]):
    return "403 Forbidden", 403
```

**Вариант 2 — Python middleware** (Flask/Django/FastAPI):

```python
from sql_injection_detector import SQLInjectionEnsemble

detector = SQLInjectionEnsemble()

@app.before_request
def check_sqli():
    for value in request.form.values():
        if detector.detect(value)["decision"] == "INJECTION":
            abort(403)
```

---

## REST API

### Проверить строку

```http
POST /api/check
Content-Type: application/json

{"text": "' UNION SELECT username, password FROM users--"}
```

```json
{
  "decision": "INJECTION",
  "action": "BLOCK",
  "score": 1.0,
  "attack_type": "UNION_BASED",
  "severity": "HIGH",
  "explanation": {
    "summary": "UNION-based SQL injection detected with HIGH confidence."
  }
}
```

### Проверить форму

```http
POST /api/validate
Content-Type: application/json

{"fields": {"username": "admin", "password": "' OR '1'='1"}}
```

### Все эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/check` | Проверить одну строку |
| `POST` | `/api/validate` | Проверить форму (несколько полей) |
| `GET` | `/api/health` | Статус сервера и моделей |
| `GET` | `/api/stats` | Статистика инцидентов |
| `GET` | `/api/incidents` | Список инцидентов |
| `GET` | `/api/export` | SIEM-экспорт (JSON / CSV / CEF) |
| `GET` | `/api/agent/ip/{ip}` | Репутация IP-адреса |
| `GET` | `/metrics` | Prometheus-метрики |
| `GET` | `/docs` | Swagger UI |

---

## Демо-прототип (TenderPro)

`demo_site.py` — симуляция корпоративного портала закупок с защитой.

**Запуск (2 терминала):**

```bash
# Терминал 1
.venv\Scripts\python -m uvicorn api_server:app --host 0.0.0.0 --port 5000

# Терминал 2
.venv\Scripts\python demo_site.py
```

**Что показывает:**
- Клиент вводит SQL-инъекцию в форму логина → видит generic-ошибку с кодом `INC-XXXXXXX`
- Панель SOC (`/admin`) мгновенно показывает инцидент: IP, payload, тип атаки, score
- Инциденты сохраняются в `demo_incidents.db` — не теряются при перезапуске
- Кнопка "Очистить" в панели SOC удаляет все инциденты из памяти и БД

**Атаки для демонстрации:**
```
' OR '1'='1'--
' UNION SELECT * FROM users--
admin'--
'; DROP TABLE users--
```

---

## Тесты

```bash
# Все тесты
pytest tests/ -v

# Только детектор
pytest tests/test_detector.py -v

# Аудит обходов защиты
pytest tests/test_bypass_audit.py -v

# Нагрузочный тест
python load_test.py

# Стресс-тест (72 сценария)
python tests/stress_test.py
```

---

## Конфигурация

Скопируйте `.env.example` в `.env`:

```bash
cp .env.example .env
```

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `API_PORT` | `5000` | Порт сервера |
| `API_KEY` | — | Ключ авторизации (опционально) |
| `ENSEMBLE_W_CNN` | `0.65` | Вес CNN в ансамбле |
| `ENSEMBLE_W_RF` | `0.35` | Вес Random Forest |
| `ENSEMBLE_TAU_HIGH` | `0.60` | Порог блокировки |
| `SQLI_BACKEND` | `sqlite` | Хранилище: `sqlite` или `redis` |
| `REDIS_URL` | — | URL Redis (для кластера) |

---

## Docker

```bash
# Запустить всё (API + Redis + Prometheus + Grafana)
docker-compose up -d

# Только API
docker build -t sqli-detector .
docker run -p 5000:5000 sqli-detector
```

---

## Обучение моделей

```bash
# Random Forest (~2 мин, CPU)
python training/train_rf.py

# VDCNN (рекомендуется GPU)
python training/train_cnn.py --epochs 35

# Jupyter-ноутбук
jupyter notebook VDCNN_Model.ipynb
```

Датасет: `data/dataset.csv`, `SQL_Dataset_Extended.csv`

---

## Структура проекта

```
├── sql_injection_detector.py   # Детектор — 7-слойный пайплайн
├── api_server.py               # REST API (FastAPI)
├── demo_site.py                # Демо-сайт TenderPro
├── agent.py                    # AI-агент: IP-репутация, эскалация
├── config.py                   # Конфигурация
├── incident_logger.py          # Логирование инцидентов
├── state_backend.py            # Хранилище (SQLite / Redis)
├── logger.py                   # Структурированные логи
├── metrics.py                  # Prometheus-метрики
├── models/                     # ML-модели (веса + архитектуры)
├── training/                   # Скрипты обучения
├── tests/                      # Тесты (495 passed)
├── data/                       # Датасеты
├── demo_incidents.db           # БД инцидентов демо
├── agent_state.db              # Состояние агента
├── rf_sql_model.pkl            # Веса Random Forest
├── tfidf_vectorizer.pkl        # TF-IDF векторизатор
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Лицензия

MIT License — см. [LICENSE](LICENSE).
