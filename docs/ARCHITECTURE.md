# Архитектура SQL Injection Detection System

> Дипломный проект: многоуровневая система обнаружения SQL-инъекций
> Метод интерпретации: **Character-level Occlusion Heatmap**

---

## 1. Общая схема

```
                ┌──────────────────────────────────────────────┐
                │           Внешний клиент / приложение         │
                └────────────────────┬─────────────────────────┘
                                     │ HTTP POST /api/check
                                     ▼
                ┌──────────────────────────────────────────────┐
                │              FastAPI (api_server.py)         │
                │   Rate-limit · Auth · CORS · Prometheus      │
                └────────────────────┬─────────────────────────┘
                                     │
                                     ▼
                ┌──────────────────────────────────────────────┐
                │      SQLInjectionEnsemble (детектор)         │
                │  ┌────────────────────────────────────────┐  │
                │  │  Слой 0: Нормализация                  │  │
                │  │  Слой 1: Лексический фильтр            │  │
                │  │  Слой 2: ML-ансамбль (RF + CNN)        │  │
                │  │  Слой 3: Семантическая валидация       │  │
                │  │  Слой 4: Движок решений                │  │
                │  │  Слой 5: Severity / Action             │  │
                │  │  Слой 6: Объяснение и SIEM-поля        │  │
                │  └────────────────────────────────────────┘  │
                └──────┬──────────────┬──────────────┬─────────┘
                       │              │              │
                       ▼              ▼              ▼
              IncidentLogger   StateBackend    PrometheusMetrics
              (SQLite/CEF)     (SQLite/Redis)  (/metrics endpoint)
```

---

## 2. Компоненты

### 2.1 `sql_injection_detector.py` — ядро

7-слойный пайплайн `SQLInjectionEnsemble.detect(text)`:

| Слой | Что делает | Технология |
|-----|-----------|-----------|
| **0** | URL-decode, NFKC, удаление null-byte, нормализация комментариев | `urllib.parse`, `unicodedata` |
| **1** | Быстрая проверка: есть ли вообще SQL-токены | regex |
| **2** | ML-классификация ансамблем | RF + VDCNN-9 |
| **3** | Семантический парсинг payload | `sqlglot` |
| **4** | Принятие решения по 8 правилам приоритета | `DecisionEngine` |
| **5** | Расчёт severity (LOW/MEDIUM/HIGH/CRITICAL) и action (ALLOW/LOG/BLOCK) | rule-based |
| **6** | Формирование trace, MITRE ATT&CK ID, SIEM-полей | словари |

**Ансамблирование:**
```
score = 0.35 × RF.predict_proba(x) + 0.65 × CNN.softmax(x)
```

Веса (`ENSEMBLE_W_RF`, `ENSEMBLE_W_CNN`) и пороги (`ENSEMBLE_TAU_HIGH/LOW/SAFE`) настраиваются через env vars.

### 2.2 ML-модели

| Модель | Файл | Признаки | Размер | Точность |
|-------|-----|---------|--------|----------|
| **Random Forest** | `rf_sql_model.pkl` | TF-IDF (char 2–5gram, 50 000 ngrams) + 5 ручных | ~50 005 | 99.18% |
| **VDCNN-9 (CNN)** | `models/char_cnn_detector.pt` | Char-embedding (PyTorch) | 9 conv-блоков | 99.90% |
| **Ансамбль** | оба | взвешенное среднее + правила | — | **99.30%** |

Метаданные RF — в `model_metadata.json` (версия, sklearn-версия, hash датасета, команда воспроизведения).

### 2.3 `api_server.py` — REST-фасад

- **FastAPI** с `lifespan`-управлением загрузкой моделей
- Эндпоинты: `/api/check`, `/api/validate`, `/api/health`, `/api/stats`, `/api/incidents`, `/api/export`, `/metrics`
- Аутентификация через `API_KEY` (опционально)
- CORS для локальной разработки
- Rate-limit (`RATE_LIMIT` req/min)

### 2.4 `state_backend.py` — хранилище

Абстракция над двумя реализациями (выбор через `SQLI_BACKEND`):

| Backend | Use case | Persistence |
|---------|----------|-------------|
| **SQLite** | single-node, dev, демо | файл `incidents.db` |
| **Redis** | кластер, multi-instance API | TTL `REDIS_TTL_DAYS` (по умолчанию 7) |

### 2.5 `incident_logger.py`

Сохранение инцидентов в SQLite + экспорт в SIEM-форматы:
- **JSON** (структурированный)
- **CSV** (для Excel)
- **CEF** (ArcSight, Splunk)

### 2.6 `agent.py` — IP-репутация

AI-агент, который:
- Ведёт счётчик нарушений по IP
- Эскалирует severity при повторных атаках с одного IP
- Хранит состояние в `agent_state.db`

### 2.7 `demo_site.py` — TenderPro

Симуляция корпоративного портала закупок:
- Форма логина, проверяемая через `/api/check`
- Панель SOC `/admin` с live-инцидентами
- Используется как наглядная демонстрация для защиты диплома

---

## 3. Поток данных (happy path)

```
1. POST /api/check {"text": "' OR '1'='1"}
2. APIServer → SQLInjectionEnsemble.detect()
3. Слой 0:  "' OR '1'='1"  (без изменений — нет URL-encoding)
4. Слой 1:  обнаружены SQL-токены ('OR', "'") → продолжаем
5. Слой 2:  RF=0.94, CNN=0.97 → ensemble=0.36*0.94+0.65*0.97 = 0.96
6. Слой 3:  sqlglot парсит как WHERE-clause с tautology → semantic_score=8
7. Слой 4:  правило #2 (ml_high + semantic_strong) → INJECTION
8. Слой 5:  attack_type=BOOLEAN_BASED → severity=MEDIUM, action=BLOCK
9. Слой 6:  trace, MITRE T1190, IoC → JSON-ответ
10. IncidentLogger пишет в incidents.db
11. PrometheusMetrics инкрементирует counters
12. Response: {"decision":"INJECTION","action":"BLOCK", ...}
```

Latency end-to-end: **~60 мс** (см. [EVALUATION.md](EVALUATION.md)).

---

## 4. Метод интерпретации — Occlusion Heatmap

В отличие от APT (SHAP) и IR-Agent (LIME), здесь применён **посимвольный окклюзионный анализ**, потому что вход — это последовательность символов, а не табличные признаки.

**Алгоритм** (`char_heatmap.py`):

1. Получить базовый score детектора для запроса `q`: `s_0 = detect(q).score`
2. Для каждой позиции `i` в `q`:
   - Сформировать `q_i = q[:i] + " " + q[i+1:]` (маскируем символ пробелом)
   - Получить `s_i = detect(q_i).score`
   - Атрибуция: `Δ_i = s_0 − s_i`
3. Положительный `Δ` → символ **повышает** опасность (атакующий компонент)
4. Отрицательный `Δ` → символ **маскирует** опасность

**Артефакты:**
- `models/heatmap_01..10.png` — тепловая карта по 10 заранее заданным запросам
- `heatmap_report.html` — интерактивный HTML с подсветкой каждого символа

Преимущество перед SHAP/LIME: работает с raw-последовательностью, показывает **где именно** в payload находится атакующий код.

---

## 5. Прод-готовность

| Категория | Реализация |
|-----------|------------|
| **Configuration** | `config.py` (frozen dataclasses), `.env`-загрузка через `python-dotenv` |
| **Logging** | Structured JSON через `logger.py` |
| **Metrics** | Prometheus в `metrics.py`, `/metrics`-endpoint |
| **Rate limit** | Per-IP, configurable через `RATE_LIMIT` |
| **Auth** | API-key через заголовок `X-API-Key` |
| **Persistence** | SQLite (default) или Redis (cluster) |
| **Container** | Multi-stage `Dockerfile`, `docker-compose.yml` (API + Redis + Prometheus + Grafana) |
| **CI/CD** | GitHub Actions: lint (ruff) + test matrix (py3.11/3.12/3.13) + Docker build |
| **Тесты** | pytest, 495 passed (детектор, API, обходы, fuzz, состояние) |

---

## 6. Используемые технологии

- **Python** 3.11+
- **PyTorch** 2.0+ (CNN)
- **scikit-learn** 1.8 (RF + TF-IDF)
- **sqlglot** (семантический парсер)
- **FastAPI** 0.121, **Uvicorn**
- **SQLite** / **Redis** (storage)
- **Prometheus** + **Grafana** (мониторинг)
- **Docker**, **docker-compose**
