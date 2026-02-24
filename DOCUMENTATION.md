# SQL Injection Protection System — Полная документация

> Версия системы: 3.5.0 (production-ready)
> Дата: 2026-02-24

---

## 1. Обзор системы

### Что это и зачем нужно

SQL Injection Protection System — это многоуровневая система защиты от SQL-инъекций в режиме реального времени. Она анализирует входящие текстовые данные (поля форм, параметры запросов) и определяет, являются ли они попыткой SQL-инъекции, до того как эти данные попадут в базу данных.

Система решает три ключевые задачи:

1. **Обнаружение** — точно классифицирует текст как безопасный, подозрительный или атаку.
2. **Контекст** — помнит историю атак с конкретных IP-адресов и принимает более агрессивные меры для повторных нарушителей.
3. **Интеграция** — предоставляет REST API для встраивания в любое приложение и отдает метрики в Prometheus и SIEM-системы.

### Три слоя архитектуры

```
┌─────────────────────────────────────────────────────────┐
│                  HTTP-запрос (POST /api/check)           │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Слой 1: API Сервер (api_server.py)          │
│  - Rate limiting (скользящее окно)                       │
│  - Аутентификация по API-ключу                           │
│  - Парсинг запроса, извлечение IP                        │
│  - _run_detection() в ThreadPoolExecutor                 │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Слой 2: AI Агент (agent.py)                 │
│  - Проверка бана IP                                      │
│  - Предиктивная защита (вероятность атаки)               │
│  - Адаптивные пороги (ниже для известных атакеров)       │
│  - Сигнатурная проверка (Layer 1: regex)                 │
│  - AST-анализ (Layer 1.5: sqlglot) ← NEW v3.5.0         │
│  - Вызов детектора                                       │
│  - Правила эскалации (A–F + AST)                         │
│  - Онлайн-обучение (SGD)                                 │
│  - Обновление памяти IP/сессии                           │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│          Слой 3: Детектор (sql_injection_detector.py)    │
│  - 7-слойная архитектура обнаружения                     │
│  - ML Ensemble: RandomForest (35%) + VDCNN CNN (65%)     │
│  - Семантический анализ + типизация атак                 │
│  - Объяснимость решений                                  │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              HTTP-ответ (CheckResponse JSON)             │
│  decision, action, severity, attack_type, scores, ...   │
└─────────────────────────────────────────────────────────┘
```

### Краткий поток данных

```
HTTP POST /api/check
  → rate limit check (deque, O(1))
  → API key check
  → _run_detection(text, ip, endpoint, field)
    → agent.evaluate()
      → ip_memory.get_profile(ip)
      → is_banned? → быстрый BLOCK без детектора
      → predictor.predict_attack_probability() → multiplier
      → online_learner.check_signatures(text)
      → _get_adapted_detector() → временный экземпляр с пониженными tau
      → detector.detect(text) → base_result
      → _escalate_decision() → правила B, C, E
      → online_learner.learn_from_blocked_attack()
      → coordinator.notify_block() → SIEM webhook
      → ip_memory.update() + session_memory.update()
      → explainer.explain() → agent_reason строка
      → вернуть final_result
  → log_incident() → SQLite
  → CheckResponse → HTTP 200 JSON
```

---

## 2. Структура файлов проекта

| Файл | Назначение |
|------|-----------|
| `sql_injection_detector.py` | Основной детектор: 7-слойная архитектура, ML ансамбль RF+CNN, семантический анализ, объяснимость |
| `agent.py` | AI агент: память IP/сессий, правила эскалации, адаптивные пороги, онлайн-обучение, предиктивная защита |
| `api_server.py` | FastAPI сервер: все REST endpoints, rate limiting, метаданные запросов, интеграция с Prometheus |
| `config.py` | Централизованная конфигурация через переменные окружения и датаклассы Python |
| `incident_logger.py` | Логирование инцидентов в SQLite, экспорт в JSON/CSV/CEF для SIEM |
| `logger.py` | Настройка структурированного логирования (JSON-формат для production) |
| `metrics.py` | Prometheus метрики: счетчики запросов, детекций, блокировок, латентность + 8 новых agent-метрик |
| `test_agent.py` | pytest тест-сюит для агента: 65 тестов — Rules A–F, thread safety, SQLite persistence, edge cases |
| `bypass_r4.py` | Регрессионный тест: 164 продвинутых adversarial payload'а (round 4), проверяет архитектурные уязвимости |
| `bypass_r3.py` | Регрессионный тест: ~232 adversarial payload'а (round 3), широкий охват техник обхода |
| `ultimate_test.py` | Расширенный тест с проверкой точности по категориям атак и ложных срабатываний |
| `stress_test.py` | Нагрузочный тест: параллельные запросы, измерение пропускной способности и латентности |
| `agent_state.db` | SQLite база данных агента (создаётся при первом запуске): IP-профили, баны, репутация |

---

## 3. Детектор SQL-инъекций (sql_injection_detector.py)

### 3.1 7-слойная архитектура обнаружения

Детектор обрабатывает каждый текст через 7 последовательных слоёв. Каждый слой может завершить обработку раньше (fast path) или передать управление следующему.

#### Layer 0: Нормализация входа

**Что делает:** Преобразует текст в каноническую форму, уничтожая все попытки обхода через кодировки.

Последовательность операций:
1. Обрезка по максимальной длине (10000 символов)
2. Unicode NFKC нормализация — превращает полноширинные символы (ｕｎｉｏｎ) в обычные ASCII
3. Замена гомоглифов через таблицу HOMOGLYPH_MAP (например, `ｕ` → `u`, умные кавычки `'` → `'`)
4. Карта Math Styled Letters — замена математических алфавитных символов Unicode (𝐔𝐍𝐈𝐎𝐍 → UNION)
5. Удаление zero-width символов — 22 невидимых символа используются для разрезания ключевых слов (`SE​LECT` → `SELECT`)
6. Удаление combining diacritics с ASCII-символов (S̀ELECT → SELECT)
7. Рекурсивное URL-декодирование до глубины 3 (`%27%4f%52` → `'OR`)
8. HTML decode (`&#39;` → `'`, `&lt;` → `<`)
9. Удаление null-байтов (`\x00`)
10. Приведение к нижнему регистру
11. Раскрытие MySQL conditional comments: `/*!UNION*/` → `UNION`
12. Удаление inline-комментариев: `UN/**/ION` → `UNION`
13. Схлопывание пробелов

#### Layer 1: Лексический анализ (fast-path)

**Что делает:** Быстрая проверка на наличие опасных ключевых слов SQL. Если ни одного не найдено — немедленный возврат SAFE без запуска тяжелого ML.

Проверяет наличие high-risk токенов: `select`, `union`, `insert`, `update`, `delete`, `drop`, `exec`, `sleep`, `benchmark`, `waitfor`, `information_schema` и другие.

#### Layer 2: ML Ensemble (RF + CNN)

**Что делает:** Два ML-классификатора независимо дают вероятность инъекции, результаты взвешиваются.

Подробнее — в разделе 3.2.

#### Layer 3: Семантический анализ

**Что делает:** Набор эвристических правил с числовыми весами, проверяющих структурные признаки SQL-атаки.

Примеры правил:
- Наличие `OR 1=1` или `AND 1=1` (тавтологии) — высокий вес
- `UNION SELECT` с последующими колонками — критический вес
- `--` или `/*` комментарии после кавычки — высокий вес
- Стековые запросы (`;DROP TABLE`) — критический вес
- `SLEEP(N)` / `BENCHMARK(N)` — критический вес
- `information_schema` — высокий вес

`semantic_score` — это сумма весов всех сработавших правил.

#### Layer 4: Decision Engine

**Что делает:** Принимает финальное решение на основе `P_ensemble` и `semantic_score` с учетом пороговых значений.

Критический инвариант: **ML один не может вынести решение INJECTION без semantic_score >= 2.0.** Семантика является обязательным подтверждением. Но если semantic_score >= 6.0, семантика может вынести INJECTION самостоятельно, игнорируя ML.

#### Layer 5: Severity и Action Mapping

**Что делает:** Назначает уровень серьезности (INFO/LOW/MEDIUM/HIGH/CRITICAL) и действие (ALLOW/LOG/CHALLENGE/BLOCK/ALERT) на основе типа атаки и уровня уверенности.

Примеры маппинга:
- `UNION_BASED` + HIGH confidence → CRITICAL, BLOCK
- `BOOLEAN_BASED` + MEDIUM → HIGH, ALERT
- `TIME_BASED` → CRITICAL (всегда)
- `OS_COMMAND` (xp_cmdshell) → CRITICAL, BLOCK

#### Layer 6: Explainability

**Что делает:** Формирует человекочитаемое объяснение решения: какие признаки сработали, какой слой принял решение, детализация по каждому компоненту.

Поля объяснения:
- `rule` — название правила (например, `RULE_1_HIGH_CONFIDENCE`)
- `evidence` — список конкретных признаков, найденных в тексте
- `breakdown` — вклад каждого слоя в решение
- `explanation` — структурированный словарь для SIEM
- `siem_fields` — поля для экспорта в SIEM-системы

---

### 3.2 ML Ensemble

#### RandomForest (вес 35%, `w_rf = 0.35`)

- Тип модели: `sklearn.ensemble.RandomForestClassifier`
- Загружается из файла `.pkl` через `joblib`
- Векторизация: TF-IDF на символьных n-граммах или лексических токенах
- Дает вероятность `P_rf ∈ [0.0, 1.0]`
- Быстрый, интерпретируемый, хорошо работает на известных паттернах
- Сохраняется статичным — онлайн-обучение не затрагивает его

#### VDCNN CharCNN (вес 65%, `w_cnn = 0.65`)

- Тип модели: Very Deep Convolutional Neural Network на символьном уровне (PyTorch)
- Работает с сырыми символами, не требует токенизации слов
- Хорошо обнаруживает обфусцированные атаки с нестандартными пробелами и символами
- Загружается из `.pt` файла
- Дает вероятность `P_cnn ∈ [0.0, 1.0]`
- Требует GPU опционально, работает на CPU

#### Формула смешивания

```
P_ensemble = 0.35 * P_rf + 0.65 * P_cnn
```

CNN получает больший вес (65%), потому что лучше справляется с обфускацией — главным вектором обхода. RF добавляет стабильность на хорошо известных паттернах.

Дополнительно: если оба классификатора сильно согласны (|P_rf - P_cnn| < tau_model_divergence), добавляется `agreement_bonus = 0.10` к итоговому скору.

---

### 3.3 Пороговые значения (EnsembleConfig)

| Параметр | Значение по умолчанию | Смысл |
|----------|----------------------|-------|
| `tau_high` | 0.60 | Если `P_ensemble >= 0.60` — сильное подозрение на инъекцию. В сочетании с semantic_score >= 2.0 → INJECTION |
| `tau_low` | 0.40 | Если `P_ensemble ∈ [0.40, 0.60)` — умеренное подозрение → SUSPICIOUS |
| `tau_safe` | 0.30 | Если `P_ensemble < 0.30` — безопасно → SAFE (fast exit) |
| `tau_semantic_override` | 6.0 | Если `semantic_score >= 6.0` — семантика самостоятельно выносит INJECTION независимо от ML |
| `tau_semantic_min` | 2.0 | Минимальный semantic_score, требуемый для подтверждения ML-решения INJECTION |
| `tau_cnn_override` | 0.75 | Если `P_cnn >= 0.75` — CNN один может влиять на решение даже без RF |
| `tau_rf_strong` | 0.70 | Порог "сильного" сигнала от RF |
| `agreement_bonus` | 0.10 | Бонус к P_ensemble при высоком согласии моделей |
| `tau_model_divergence` | 0.40 | Порог расхождения: если |P_rf - P_cnn| > 0.40 — модели расходятся |

---

### 3.4 Результат detect()

Метод `detector.detect(text, ...)` возвращает словарь со следующими полями:

| Поле | Тип | Описание |
|------|-----|---------|
| `decision` | str | SAFE / SUSPICIOUS / INJECTION / INVALID |
| `action` | str | ALLOW / LOG / CHALLENGE / BLOCK / ALERT |
| `score` | float | P_ensemble — итоговая вероятность инъекции [0.0, 1.0] |
| `P_rf` | float | Вероятность от RandomForest |
| `P_cnn` | float | Вероятность от CNN |
| `semantic_score` | float | Сумма весов сработавших семантических правил |
| `confidence_level` | str | HIGH / MEDIUM / LOW — уровень уверенности в решении |
| `severity` | str | INFO / LOW / MEDIUM / HIGH / CRITICAL |
| `attack_type` | str | NONE / BOOLEAN_BASED / UNION_BASED / STACKED_QUERY / TIME_BASED / ERROR_BASED / COMMENT_TRUNCATION / OUT_OF_BAND / OS_COMMAND |
| `reason` | str | Текстовое объяснение на английском |
| `rule` | str | Название сработавшего правила (RULE_1_HIGH_CONFIDENCE и т.д.) |
| `evidence` | list[str] | Список конкретных признаков, найденных в тексте |
| `breakdown` | dict | Детальный вклад каждого слоя |
| `explanation` | dict | Структурированное объяснение для SIEM |
| `siem_fields` | dict | Дополнительные поля для SIEM-экспорта |

---

### 3.5 Нормализация — что именно делается с текстом

Полный список трансформаций в порядке применения:

1. **Обрезка по длине** — текст длиннее 10000 символов отрезается
2. **Unicode NFKC** — совместимая нормализация, разворачивает лигатуры, нормализует знаки диакритики
3. **Замена гомоглифов** — таблица из 70+ символов: полноширинные буквы (ｕ→u), умные кавычки ('→'), спецсимволы
4. **Math Styled Letters** — 29 блоков Unicode математических символов (𝐁𝐨𝐥𝐝, 𝐼𝑡𝑎𝑙𝑖𝑐, 𝔽𝕣𝕒𝕜𝕥𝕦𝕣, Monospace и т.д.) → ASCII
5. **Zero-width chars removal** — удаляет 22 невидимых символа (ZWSP, ZWNJ, ZWJ, LRM, RLM, BOM, soft hyphen, bidirectional overrides RTL/LTR и др.)
6. **Combining diacritics** — удаляет диакритические знаки (category 'Mn') с ASCII-базовых символов
7. **Рекурсивный URL decode** — до 3 итераций (`%2527` → `%27` → `'`)
8. **HTML decode** — `&#39;`, `&amp;`, `&lt;`, `&gt;`, `&quot;` и числовые entity
9. **Null bytes** — удаление `\x00`
10. **Lowercase** — приведение к нижнему регистру
11. **MySQL conditional comments** — раскрытие `/*!50000 UNION*/` → `UNION`
12. **C-style inline comment removal** — `UN/*комментарий*/ION` → `UNION`; SQL однострочные комментарии `-- текст` также обрабатываются
13. **Fragment merger** — объединение фрагментов ключевых слов, разбитых обфускацией
14. **Whitespace collapse** — замена множественных пробелов одним

---

## 4. AI Агент (agent.py)

### 4.1 Зачем нужен агент

Детектор (`sql_injection_detector.py`) — это stateless компонент. Он смотрит только на текущий запрос и не помнит ничего о прошлом. Если один и тот же IP присылает атаки 10 раз подряд, детектор обрабатывает каждый запрос независимо.

Агент добавляет:
- **Память** — хранит историю атак по каждому IP и сессии
- **Эскалацию** — повышает уровень реагирования при повторных атаках
- **Адаптивность** — снижает пороги для известных атакеров (труднее проскользнуть)
- **Самообучение** — накапливает паттерны новых атак через SGD
- **Предиктивность** — предсказывает вероятность атаки до запуска детектора
- **Интеграцию** — уведомляет SIEM при блокировках

---

### 4.2 Полный пайплайн evaluate() — 11 шагов

```python
result = agent.evaluate(
    text,
    source_ip="192.168.1.100",
    session_id="sess-abc123",
    endpoint="/api/login",
    field_name="username",
    http_method="POST"
)
```

**Шаг 1: Нормализация IP / fallback**

```python
_ip = source_ip if (source_ip and source_ip != "unknown") else None
```

Если IP не задан или равен `"unknown"` — агент переходит в режим чистого детектора без памяти. Это позволяет использовать детектор без контекста IP.

**Шаг 2: Загрузка IPMemory + SessionMemory**

```python
profile = self.ip_memory.get_profile(_ip)
session = self.session_memory.get_or_create(session_id or f"auto-{_ip}")
```

Создает профили если их нет, или возвращает существующие.

**Шаг 3: Правило A — проверка бана (ДО вызова детектора)**

```python
if self.ip_memory.is_banned(_ip):
    return self._make_ban_response(...)
```

Если IP в бане — немедленно возвращает BLOCK-ответ. Детектор НЕ вызывается — экономия CPU. Бан автоматически снимается по истечению времени внутри метода `is_banned()`.

**Шаг 4: PredictiveDefense — вычисление локального multiplier**

```python
predict_prob = self.predictor.predict_attack_probability(profile, session)
predictive_multiplier = self.predictor.get_tau_multiplier(predict_prob)
```

Возвращает локальный множитель для снижения tau. Не записывает ничего в AgentConfig.

**Шаг 5: Сигнатурная проверка (OnlineLearning)**

```python
sig_hit, sig_pattern = self.online_learner.check_signatures(text)
```

Быстрая regex-проверка по базе сигнатур до запуска ML. Если совпало — это учитывается при эскалации.

**Шаг 6: _get_adapted_detector() — создание адаптированного детектора**

```python
adapted_det = self._get_adapted_detector(profile, endpoint, extra_multiplier=predictive_multiplier)
base_result = adapted_det.detect(text, ...)
```

Создает временный экземпляр детектора с пониженными tau. Модели (RF, CNN) разделяются по ссылке — не копируются.

**Шаг 7: detector.detect() — базовый результат**

Запускается через адаптированный детектор, получаем `base_result`.

**Шаг 8: _escalate_decision() — правила B, C, E**

Применяет правила эскалации поверх `base_result`. Может изменить `decision` и `action`.

**Шаг 9: OnlineLearning — дообучение**

Если решение INJECTION — добавляет пример в буфер SGD. Если буфер заполнился (10 примеров) — запускает `partial_fit`. Для известных атакеров (attack_count >= 3) также проверяет SGD вероятность и может эскалировать SAFE → SUSPICIOUS.

**Шаг 10: SystemCoordinator — уведомление SIEM**

```python
if final_result["agent_action"] in ("BLOCK", "ALERT"):
    coordinator.notify_block(ip, attack_type, severity, payload_hash)
```

Отправляет JSON webhook если `SIEM_WEBHOOK_URL` настроен.

**Шаг 11: Обновление памяти + DecisionExplainer + возврат**

```python
self.ip_memory.update(_ip, final_result, endpoint, field_name)
self.session_memory.update(_sid, final_result, field_name)

# explain() возвращает (строка, структурированный dict)
agent_reason, contributing_factors = self.explainer.explain(base_result, agent_context)
final_result["agent_reason"] = agent_reason
final_result["contributing_factors"] = contributing_factors  # NEW в v2.0
final_result["ip_profile"] = ...
final_result["session_context"] = ...
return final_result
```

> **Production v2.0:** `explain()` теперь возвращает два объекта: человекочитаемую строку `agent_reason` и машиночитаемый `contributing_factors` dict. Это устраняет необходимость парсить строку в SIEM/dashboard.

---

### 4.3 IPMemory и IPProfile

#### Что хранит IPProfile

| Поле | Тип | Описание |
|------|-----|---------|
| `ip` | str | IP-адрес |
| `first_seen` | float | Unix timestamp первого запроса |
| `last_seen` | float | Unix timestamp последнего запроса |
| `total_requests` | int | Общее количество запросов с этого IP |
| `attack_count` | int | Количество запросов с решением INJECTION или BLOCK |
| `suspicious_count` | int | Количество запросов с решением SUSPICIOUS или CHALLENGE |
| `recent_attacks` | deque(maxlen=200) | Временные метки последних атак (для скользящего окна) |
| `recent_suspicious` | deque(maxlen=200) | Временные метки последних подозрительных запросов |
| `attack_types` | Counter | Словарь `{UNION_BASED: 3, BOOLEAN_BASED: 1}` — статистика по типам |
| `endpoints_targeted` | set | Множество endpoint'ов, по которым были атаки |
| `fields_targeted` | set | Множество полей форм, которые атаковались |
| `is_banned` | bool | Флаг активного бана |
| `ban_until` | float/None | Unix timestamp окончания бана |
| `reputation_score` | float | Репутационный балл [0.0, 1.0] |

#### Формула репутации compute_reputation()

```python
score = 0.0

# Компонент 1: соотношение атак к общим запросам (вес до 0.5)
score += min(attack_count / total_requests, 1.0) * 0.5

# Компонент 2: абсолютное количество атак (лог-шкала, вес до 0.3)
score += min(attack_count / 10.0, 1.0) * 0.3

# Компонент 3: разнообразие типов атак (полиморфный атакер)
if len(attack_types) >= 3:
    score += 0.15
elif len(attack_types) >= 2:
    score += 0.08

# Компонент 4: количество атакованных endpoint'ов (сканер)
if len(endpoints_targeted) >= 5:
    score += 0.05

return min(score, 1.0)
```

Репутация 0.0 означает чистый IP, 1.0 — подтвержденный атакер. Используется для адаптации порогов.

#### cleanup_stale()

Удаляет профили IP, которые не проявляли активности дольше TTL (по умолчанию 3600 секунд). Забаненные IP НЕ удаляются, даже если истек TTL. Запускается фоновой задачей в api_server.py каждые 5 минут.

---

### 4.4 SessionMemory и SessionContext

#### Что хранит SessionContext

| Поле | Тип | Описание |
|------|-----|---------|
| `session_id` | str | Идентификатор сессии (из заголовка или `auto-{ip}`) |
| `start_time` | float | Время начала сессии |
| `last_active` | float | Время последней активности |
| `fields_probed` | list | Упорядоченный список имен полей, которые проверялись: `["username", "id", "search"]` |
| `field_probe_times` | list | Временные метки для каждого поля из fields_probed (синхронный по индексу) |
| `attack_sequence` | list | Последовательность типов атак: `["BOOLEAN_BASED", "UNION_BASED"]` |
| `escalation_level` | int | Уровень эскалации: 0=нормально, 1=наблюдение, 2=вызов, 3=блок |

#### Два синхронных списка: fields_probed + field_probe_times

Списки `fields_probed` и `field_probe_times` всегда имеют одинаковую длину и синхронизированы по индексу:

```
fields_probed:     ["username",       "email",          "search_query"]
field_probe_times: [1700000000.123,   1700000005.456,   1700000008.789]
```

Это позволяет правилу E определить, что 3 разных поля были атакованы за промежуток `time[-1] - time[0]` секунд (при сканировании < 60 секунд).

---

### 4.5 Правила эскалации A–F

#### Правило A: Бан IP

- **Условие:** `ip_memory.is_banned(ip)` возвращает True
- **Когда проверяется:** ДО вызова детектора (шаг 3)
- **Результат:** Немедленный BLOCK без ML-инференса. `score=10.0`, `severity=CRITICAL`
- **agent_reason:** `"IP banned until {iso_timestamp}"`
- **Важно:** Детектор НЕ вызывается, экономия CPU

#### Правило B: Автобан по частоте атак

- **Условие:** В скользящем временном окне (по умолчанию 300 секунд) найдено >= 3 атак
- **Временной фильтр:** `[t for t in profile.recent_attacks if now - t <= 300]` — это именно временной фильтр, а не `len(profile.recent_attacks)`. Важно: deque может содержать старые записи, которые не попадают в окно.
- **Результат:** IP банится на `ip_ban_duration_seconds` (3600 секунд), `agent_decision = "INJECTION"`, `agent_action = "BLOCK"`
- **agent_reason:** `"Auto-ban: 3 attacks in window"`

#### Правило C: Повторные SUSPICIOUS → BLOCK

- **Условие:** Текущий запрос получил `SUSPICIOUS`, и в окне 120 секунд накоплено >= 3 подозрительных запросов
- **Результат:** `agent_decision = "INJECTION"`, `agent_action = "BLOCK"`
- **agent_reason:** `"Escalated: 3 suspicious requests in window"`

#### Правило D: Адаптация tau по репутации

- **Условие:** `profile.reputation_score > 0.5`
- **Результат:** tau умножается на `reputation_tau_multiplier = 0.75` — пороги снижаются, атакеру труднее проскользнуть
- **Реализация:** Через `_get_adapted_detector()`, создает временный экземпляр детектора

#### Правило E: Обнаружение сканирования полей

- **Условие:** В течение последних 60 секунд были атакованы >= 3 разных поля формы
- **Результат:** Если текущий запрос SAFE — повышается до SUSPICIOUS/CHALLENGE
- **agent_reason:** `"Field scanning: 4 unique fields in 60s"`
- **Обнаруживает:** Автоматические сканеры SQLMap и подобные

#### Правило F: Повторная атака на тот же endpoint

- **Условие:** Текущий endpoint уже есть в `profile.endpoints_targeted` AND `attack_count >= 1`
- **Результат:** Дополнительный множитель `* 0.85` для tau (помимо репутационного)
- **Реализация:** В `_get_adapted_detector()`, умножается на общий `multiplier`

---

### 4.6 Адаптивные пороги (_get_adapted_detector)

Метод создает временный экземпляр `SQLInjectionEnsemble` с пониженными tau-порогами для подозрительных IP. ML-модели (RF, CNN) не копируются — только разделяются по ссылке.

```python
# Вычисление multiplier
multiplier = 1.0

# Правило D: reputation
if profile.reputation_score > 0.5:
    multiplier *= 0.75

# Правило F: повторная атака на endpoint
if endpoint in profile.endpoints_targeted and profile.attack_count >= 1:
    multiplier *= 0.85

# Предиктивная защита
multiplier *= extra_multiplier  # например 0.80 от PredictiveDefense

# Нижний предел: tau никогда не опускается ниже 50% от базового
multiplier = max(multiplier, 0.5)
```

Пример: IP с репутацией 0.82, вторая атака на `/login`, предиктивная вероятность 0.75:
- `multiplier = 0.75 * 0.85 * 0.80 = 0.51`
- Нижний предел: `max(0.51, 0.50) = 0.51`
- `tau_high` снижается с `0.60` до `0.60 * 0.51 = 0.306`

Если multiplier близок к 1.0 (изменение < 1%) — возвращается оригинальный `self.detector` без создания нового объекта.

```python
# Общая формула адаптации
adapted_cfg.tau_high = base_cfg.tau_high * multiplier
adapted_cfg.tau_low  = base_cfg.tau_low  * multiplier
adapted_cfg.tau_safe = base_cfg.tau_safe * multiplier

# Разделение моделей по ссылке (не копирование!)
tmp.rf_model      = self.detector.rf_model
tmp.rf_vectorizer = self.detector.rf_vectorizer
tmp.cnn_model     = self.detector.cnn_model
tmp.char_tokenizer = self.detector.char_tokenizer
```

---

### 4.7 OnlineLearning

`OnlineLearning` — это вспомогательный слой, который дообучается в реальном времени. RF и CNN не трогает.

#### Двухслойная архитектура

1. **Сигнатурная БД** — набор regex-паттернов для быстрой проверки. Быстрее ML.
2. **SGDClassifier** — инкрементальный ML-классификатор на TF-IDF символьных n-граммах (3-5 символов, 5000 признаков).

#### Seed-сигнатуры (10 встроенных)

```python
r"'\s*(or|and)\s+\d+\s*=\s*\d+"          # ' OR 1=1
r"union\s+(all\s+)?select\s+"             # UNION SELECT
r";\s*(drop|delete|truncate)\s+table"     # ; DROP TABLE
r"exec(\s+|\()\s*(xp_|sp_)"              # exec xp_cmdshell
r"into\s+(outfile|dumpfile)\s+"           # INTO OUTFILE
r"sleep\s*\(\s*\d+"                       # SLEEP(N)
r"benchmark\s*\(\s*\d+"                   # BENCHMARK(N,...)
r"waitfor\s+delay\s+"                     # WAITFOR DELAY
r"(load_file|char|ascii|hex)\s*\("        # SQL функции
r"information_schema\.(tables|columns)"  # Перечисление схемы
```

#### partial_fit на буфере

Примеры накапливаются в `deque(maxlen=1000)`. Когда буфер достигает 10 примеров (`incremental_fit_batch_size`) — запускается `_incremental_fit()`:

```python
# Первое обучение: также fit векторайзер
X = self._vectorizer.fit_transform(texts)
self._clf.partial_fit(X, labels, classes=[0, 1])

# Последующие: только transform
X = self._vectorizer.transform(texts)
self._clf.partial_fit(X, labels)
```

#### Автоматическое извлечение новых паттернов

Когда атакер совершает >= 3 атак, из текста извлекается паттерн из первых двух SQL-ключевых слов:

```python
combo = r"\bunion\b.{0,20}\bselect\b"
```

Паттерн добавляется в сигнатурную БД с весом 1.0.

#### Подавление ложных срабатываний

Если аналитик помечает результат как ложное срабатывание:

```python
self.pattern_weights[matched_pattern] *= 0.9  # умножаем вес на 0.9
# Нижний порог веса: 0.05 (паттерн не удаляется полностью)
```

Паттерны с весом < 0.1 пропускаются при проверке.

---

### 4.8 PredictiveDefense

Предсказывает вероятность атаки ДО запуска детектора на основе трех компонентов:

| Компонент | Максимальный вклад | Условие |
|-----------|-------------------|---------|
| Репутация IP | 0.3 | `profile.reputation_score * 0.3` |
| Быстрое сканирование полей | 0.3 | >= 3 уникальных поля за < 60 секунд |
| Эскалация типов атак | 0.4 | >= 3 атаки в сессии: +0.4; >= 2: +0.25; >= 1: +0.1 |

```python
# Итоговая вероятность
prob = min(rep_component + scan_component + seq_component, 1.0)

# Если prob > 0.7 → multiplier = 0.80 (снижаем tau на 20%)
# Иначе → multiplier = 1.0 (не трогаем tau)
```

**Важно:** `get_tau_multiplier()` возвращает ЛОКАЛЬНУЮ переменную. Она передается в `_get_adapted_detector()` как `extra_multiplier`, но никогда не записывается в `AgentConfig`. Каждый запрос вычисляет свой multiplier независимо.

---

### 4.9 SystemCoordinator

По умолчанию — no-op (ничего не делает). Активируется через переменные окружения.

#### Активация через env vars

```bash
export SIEM_WEBHOOK_URL="https://siem.company.com/webhook/sqli"
export ABUSEIPDB_API_KEY="your_api_key_here"
```

#### notify_block() — формат JSON payload

```json
{
  "event": "SQLI_BLOCK",
  "ip": "192.168.1.100",
  "attack_type": "UNION_BASED",
  "severity": "CRITICAL",
  "payload_hash": "a1b2c3d4e5f6g7h8",
  "escalated": true,
  "timestamp": "2026-02-23T12:00:00+00:00"
}
```

Отправляется через `urllib.request` с таймаутом 2 секунды. Никогда не обрушивает основной поток даже при ошибке сети.

#### check_threat_intel() — AbuseIPDB

```python
url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30"
# Возвращает:
{"is_known_bad": True/False, "abuse_confidence_score": 0-100}
# Порог: confidence >= 50 → is_known_bad = True
```

---

### 4.10 DecisionExplainer (v2.0: строка + структурированный объект)

Формирует **два** объекта для каждого решения агента:
1. `agent_reason` — человекочитаемая строка для логов
2. `contributing_factors` — машиночитаемый dict для dashboard/SIEM

#### Формат строки `agent_reason`

```
"Score: {score:.2f} | Rule: {rule} | {escalation_reason} | Adaptive threshold (rep={rep:.2f}) | Predictive defense (prob={prob:.2f}) | Field scanning pattern detected"
```

#### Структура `contributing_factors`

```json
{
  "detector_score": 7.2,
  "detector_rule": "RULE_1_HIGH_CONFIDENCE",
  "escalation_reason": "Auto-ban: 3 attacks in window",
  "adaptive_threshold": {
    "used": true,
    "reputation": 0.82
  },
  "predictive_defense": {
    "used": true,
    "probability": 0.91
  },
  "field_scanning": false,
  "signature_match": "union\\s+(all\\s+)?select\\s+"
}
```

Все ключи всегда присутствуют. Значение `null` означает "не применялось". Это позволяет Grafana/SIEM фильтровать и аггрегировать данные без парсинга строки.

#### Примеры `agent_reason`

```
# Нормальная инъекция
"Score: 7.20 | Rule: RULE_1_HIGH_CONFIDENCE"

# С эскалацией и адаптацией
"Score: 5.80 | Rule: RULE_2_HIGH_SEMANTIC | Auto-ban: 3 attacks in window | Adaptive threshold (rep=0.82)"

# Полный пример для сканера
"Score: 3.20 | Rule: RULE_3_MEDIUM | Field scanning: 4 unique fields in 60s | Predictive defense (prob=0.75)"

# Без IP контекста
"No IP context — pure detector mode"

# Бан IP
"IP banned until 2026-02-23T13:00:00+00:00"
```

---

### 4.11 AgentConfig — все параметры

| Параметр | По умолчанию | Описание |
|----------|-------------|---------|
| `ip_attack_threshold` | 3 | Число атак в окне, после которого срабатывает автобан |
| `ip_attack_window_seconds` | 300 | Размер скользящего окна для подсчета атак (5 минут) |
| `ip_ban_duration_seconds` | 3600 | Длительность бана (1 час) |
| `suspicious_escalation_count` | 3 | Число подозрительных запросов для эскалации до BLOCK |
| `suspicious_window_seconds` | 120 | Окно для подсчета подозрительных запросов (2 минуты) |
| `enable_adaptive_thresholds` | True | Включить адаптивное снижение tau для известных атакеров |
| `reputation_tau_multiplier` | 0.75 | Множитель tau при высокой репутации (снижает пороги на 25%) |
| `enable_predictive_defense` | True | Включить предиктивную защиту |
| `predictive_threshold` | 0.7 | Вероятность выше которой снижаются tau |
| `predictive_tau_boost` | 0.80 | Множитель tau от предиктивной защиты |
| `enable_online_learning` | True | Включить инкрементальное обучение SGD |
| `incremental_fit_batch_size` | 10 | Число примеров перед запуском partial_fit |
| `online_layer_weight` | 0.20 | Вес SGD-слоя при смешивании (только для атакеров) |
| `siem_webhook_url` | None | URL вебхука SIEM (из env SIEM_WEBHOOK_URL) |
| `threat_intel_api_key` | None | API ключ AbuseIPDB (из env ABUSEIPDB_API_KEY) |
| `ip_memory_ttl_seconds` | 3600 | TTL для профилей IP без активности |
| `session_memory_ttl_seconds` | 1800 | TTL для сессий без активности (30 минут) |
| `max_tracked_ips` | 10000 | Максимальное число IP-адресов в памяти |
| `persistence_flush_interval` | 300 | Интервал сброса состояния в SQLite (секунды) |
| `persist_min_attacks` | 1 | Минимальное число атак для сохранения IP в БД (чистые IP пропускаются) |

---

### 4.12 Возвращаемый словарь evaluate()

`evaluate()` возвращает все поля `detector.detect()` плюс дополнительные поля агента:

| Поле | Тип | Источник | Описание |
|------|-----|---------|---------|
| `decision` | str | detector | Базовое решение детектора |
| `action` | str | detector | Базовое действие детектора |
| `score` | float | detector | P_ensemble |
| `P_rf` | float | detector | Вероятность RandomForest |
| `P_cnn` | float | detector | Вероятность CNN |
| `semantic_score` | float | detector | Семантический скор |
| `confidence_level` | str | detector | HIGH/MEDIUM/LOW |
| `severity` | str | detector | INFO..CRITICAL |
| `attack_type` | str | detector | Тип атаки |
| `reason` | str | detector | Текстовое объяснение |
| `rule` | str | detector | Правило |
| `agent_reason` | str | agent | Человекочитаемое объяснение решения агента |
| `contributing_factors` | dict | agent | **Новое в v2.0** — структурированная объяснимость (JSON-совместимый dict) |
| `evidence` | list | detector | Признаки |
| `breakdown` | dict | detector | Детализация по слоям |
| `explanation` | dict | detector | Структурированное объяснение |
| `siem_fields` | dict | detector | SIEM-поля |
| `agent_decision` | str | **agent** | Финальное решение с учетом правил эскалации |
| `agent_action` | str | **agent** | Финальное действие |
| `agent_reason` | str | **agent** | Человекочитаемое объяснение агента |
| `escalated` | bool | **agent** | True если правило эскалации изменило решение |
| `adaptive_threshold_used` | bool | **agent** | True если были адаптированы пороги |
| `ip_profile` | dict/None | **agent** | Сериализованный IPProfile |
| `session_context` | dict/None | **agent** | Данные сессии (escalation_level, fields_probed_count, attack_sequence) |

---

## 5. API Сервер (api_server.py)

### 5.1 Все endpoints — полная таблица

| Метод | Путь | Описание | Auth | Rate Limit |
|-------|------|---------|------|-----------|
| POST | `/api/check` | Проверить один текст на SQL-инъекцию | Да | Да |
| POST | `/api/validate` | Проверить все поля формы сразу | Да | Да |
| GET | `/api/health` | Статус сервера и моделей | Нет | Нет |
| GET | `/api/stats` | Статистика инцидентов из SQLite | Да | Нет |
| GET | `/api/incidents` | История инцидентов с фильтрацией | Да | Нет |
| POST | `/api/incident/{id}/feedback` | Отметить инцидент как ложное срабатывание | Да | Нет |
| GET | `/api/export` | Экспорт инцидентов (JSON/CSV/CEF) | Да | Нет |
| GET | `/api/agent/stats` | Статистика агента (баны, эскалации, обучение) | Да | Нет |
| GET | `/api/agent/ip/{ip}` | Профиль репутации конкретного IP | Да | Нет |
| GET | `/api/agent/metrics` | Сводные метрики агента | Да | Нет |
| POST | `/api/agent/feedback` | Обратная связь аналитика для обучения | Да | Нет |
| GET | `/metrics` | Prometheus метрики для скрейпинга | Нет | Нет |
| GET | `/api/demo` | Интерактивная HTML демо-страница | Нет | Нет |

#### Детали по ключевым endpoints

**POST /api/check**

Параметры запроса:
```json
{
  "text": "' OR '1'='1",
  "field_name": "username"  // опционально
}
```

Пример ответа:
```json
{
  "input": "' OR '1'='1",
  "decision": "INJECTION",
  "action": "BLOCK",
  "blocked": true,
  "confidence": "HIGH",
  "severity": "MEDIUM",
  "attack_type": "BOOLEAN_BASED",
  "scores": {"ensemble": 0.9234, "rf": 0.87, "cnn": 0.95, "semantic": 7.0},
  "reason": "High-confidence SQL injection detected: boolean-based tautology",
  "rule": "RULE_1_HIGH_CONFIDENCE",
  "processing_time_ms": 12.5,
  "incident_id": 42,
  "agent_decision": "INJECTION",
  "agent_action": "BLOCK",
  "agent_reason": "Score: 0.92 | Rule: RULE_1_HIGH_CONFIDENCE | Adaptive threshold (rep=0.75)"
}
```

**POST /api/validate**

Параметры запроса:
```json
{
  "fields": {
    "username": "admin",
    "password": "' OR '1'='1",
    "email": "user@example.com"
  }
}
```

Пример ответа:
```json
{
  "safe": false,
  "blocked_fields": ["password"],
  "results": {
    "username": {"decision": "SAFE", "action": "ALLOW", "score": 0.02},
    "password": {"decision": "INJECTION", "action": "BLOCK", "score": 0.93},
    "email": {"decision": "SAFE", "action": "ALLOW", "score": 0.01}
  },
  "processing_time_ms": 35.2
}
```

**GET /api/incidents**

Параметры запроса (query string):
- `limit` — число записей (макс. 500, по умолчанию 50)
- `offset` — смещение для пагинации
- `decision` — фильтр: INJECTION / SUSPICIOUS / SAFE
- `action` — фильтр: BLOCK / ALERT / CHALLENGE
- `severity` — фильтр: CRITICAL / HIGH / MEDIUM / LOW / INFO

**GET /api/export**

Параметры:
- `format` — json / csv / cef
- `severity_min` — минимальный уровень серьезности (LOW по умолчанию)

Возвращает файл для скачивания с заголовком `Content-Disposition: attachment`.

---

### 5.2 Как работает _run_detection()

```python
async def _run_detection(text: str, **kwargs) -> dict:
    loop = asyncio.get_event_loop()

    result = await asyncio.wait_for(
        loop.run_in_executor(
            _executor,
            lambda: agent.evaluate(text, **kwargs)
        ),
        timeout=10  # INFERENCE_TIMEOUT_SECONDS
    )
    return result
```

**Зачем ThreadPoolExecutor:**
FastAPI использует asyncio (однопоточный event loop). ML-инференс (NumPy, PyTorch, sklearn) — CPU-bound операция, которая заблокирует весь event loop на время вычисления. `run_in_executor` перемещает вычисление в отдельный поток, позволяя event loop'у обрабатывать другие запросы параллельно. Пул из 4 воркеров.

**Зачем asyncio.wait_for с таймаутом 10 секунд:**
Защита от зависших инференсов. Если ML-модель застряла (например, на аномально длинном тексте), через 10 секунд запрос завершается с HTTP 504, а не висит бесконечно.

**Фallback:** Если `agent` не инициализирован — вызывается `detector.detect()` напрямую.

---

### 5.3 Rate limiting

Реализован скользящий временной окно (sliding window) с использованием `deque`:

```python
_rate_limit_store: dict[str, deque] = {}  # per-IP хранилище

def check_rate_limit(request: Request) -> None:
    ip = get_client_ip(request)
    now = time.time()
    window = 60  # секунд

    dq = _rate_limit_store.setdefault(ip, deque())

    # Удаляем устаревшие записи слева (O(1) popleft)
    while dq and (now - dq[0]) >= window:
        dq.popleft()

    if len(dq) >= rate_limit_per_minute:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    dq.append(now)  # O(1) append
```

- Структура `deque` обеспечивает O(1) операции `append` (добавить справа) и `popleft` (убрать устаревшую запись слева)
- По умолчанию лимит: 100 запросов в минуту на IP
- Очистка устаревших IP-адресов из `_rate_limit_store` происходит каждые 5 минут

---

### 5.4 Lifespan — порядок инициализации

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup (порядок важен) ──

    # 1. Создание детектора (загружает RF и CNN модели с диска)
    detector = SQLInjectionEnsemble()

    # 2. AgentStore: SQLite persistence для IP-профилей и банов
    store = AgentStore(db_path=os.environ.get("AGENT_DB_PATH", "agent_state.db"))
    agent = SQLiAgent(detector, store=store)

    # 3. Восстановление состояния с предыдущего запуска (баны + репутация)
    loaded_profiles = store.load_into(agent)  # N → лог agent_state_loaded

    # 4. Создание логгера инцидентов (открывает SQLite)
    logger = IncidentLogger(db_path=cfg.incidents.db_path)

    # 5. Настройка Prometheus метрик
    metrics.model_loaded.labels(model="rf").set(1 if detector.rf_loaded else 0)
    metrics.model_loaded.labels(model="cnn").set(1 if detector.cnn_loaded else 0)

    # 6. Запуск фоновой задачи (очистка памяти + flush в SQLite каждые 5 минут)
    cleanup_task = asyncio.create_task(agent_cleanup_loop(agent, interval_seconds=300))

    yield  # ── Приложение работает ──

    # ── Shutdown ──
    cleanup_task.cancel()

    # Финальный сброс состояния агента в SQLite перед остановкой
    agent.store.flush(agent, min_attacks=agent.config.persist_min_attacks)

    _executor.shutdown(wait=True)
```

> **Production v3.3.0:** При перезапуске сервера баны и репутация IP-адресов автоматически восстанавливаются из `agent_state.db`. Переменная окружения `AGENT_DB_PATH` позволяет указать путь к файлу.

Если API_KEY не задан — в лог выводится предупреждение, но сервер запускается.

---

### 5.5 CheckResponse — все поля

```python
class CheckResponse(BaseModel):
    input: str                          # Исходный текст запроса
    decision: str                       # SAFE/SUSPICIOUS/INJECTION/INVALID
    action: str                         # ALLOW/LOG/CHALLENGE/BLOCK/ALERT
    blocked: bool                       # True если action в (BLOCK, ALERT)
    confidence: str                     # HIGH/MEDIUM/LOW
    severity: str                       # INFO/LOW/MEDIUM/HIGH/CRITICAL
    attack_type: str                    # Тип атаки
    scores: dict[str, float]            # {ensemble, rf, cnn, semantic}
    reason: str                         # Текстовое объяснение
    rule: str                           # Название сработавшего правила
    processing_time_ms: float           # Время обработки в миллисекундах
    incident_id: int | None             # ID записи в SQLite (если залогировано)
    explanation: dict | None            # Детальное объяснение по слоям
    siem_fields: dict | None            # Поля для SIEM
    # Agent fields (None если агент не активен или нет IP)
    agent_decision: str | None          # Финальное решение агента
    agent_action: str | None            # Финальное действие агента
    agent_reason: str | None            # Объяснение агента (строка для логов)
    contributing_factors: dict | None   # Структурированная объяснимость (для dashboard/SIEM)
    escalated: bool | None              # Было ли эскалировано правилами
    adaptive_threshold_used: bool | None  # Использовались ли адаптивные пороги
    ip_profile: dict | None             # Профиль IP с историей атак
    session_context: dict | None        # Контекст сессии
```

> **Новое в v3.3.0:** поле `contributing_factors` — машиночитаемый словарь с детализацией решения. Содержит `detector_score`, `detector_rule`, `escalation_reason`, `adaptive_threshold`, `predictive_defense`, `field_scanning`, `signature_match`.

---

## 6. Команды запуска

### 6.1 Запуск сервера

```bash
# Основная команда
uvicorn api_server:app --host 0.0.0.0 --port 5000

# С автоперезагрузкой (разработка)
uvicorn api_server:app --host 0.0.0.0 --port 5000 --reload

# С несколькими воркерами (продакшн, Linux только)
uvicorn api_server:app --host 0.0.0.0 --port 5000 --workers 4
```

После запуска доступно:
- API: `http://localhost:5000/api/check`
- Swagger UI: `http://localhost:5000/docs`
- ReDoc: `http://localhost:5000/redoc`
- Демо: `http://localhost:5000/api/demo`
- Prometheus: `http://localhost:5000/metrics`

### 6.2 Запуск демо агента

```bash
py -3 agent.py
```

Запускает встроенный демо-сценарий: 11 запросов от двух IP (атакер и легитимный пользователь), показывает накопление репутации и автобан.

### 6.3 Тестовые команды (curl)

```bash
# Проверить один запрос
curl -X POST http://localhost:5000/api/check \
     -H "Content-Type: application/json" \
     -d '{"text": "'\'' OR '\''1'\''='\''1"}'

# Проверить безопасный запрос
curl -X POST http://localhost:5000/api/check \
     -H "Content-Type: application/json" \
     -d '{"text": "john_doe"}'

# Проверить UNION SELECT
curl -X POST http://localhost:5000/api/check \
     -H "Content-Type: application/json" \
     -d '{"text": "1 UNION SELECT password FROM users--"}'

# Проверить форму целиком
curl -X POST http://localhost:5000/api/validate \
     -H "Content-Type: application/json" \
     -d '{"fields": {"username": "admin", "password": "'\'' OR 1=1--"}}'

# Статус сервера
curl http://localhost:5000/api/health

# Статистика инцидентов
curl http://localhost:5000/api/stats

# История инцидентов (последние 10, только INJECTION)
curl "http://localhost:5000/api/incidents?limit=10&decision=INJECTION"

# Обратная связь по инциденту (ложное срабатывание)
curl -X POST http://localhost:5000/api/incident/42/feedback \
     -H "Content-Type: application/json" \
     -d '{"is_false_positive": true, "notes": "Valid SQL in ORM query"}'

# Экспорт для SIEM (CSV формат)
curl "http://localhost:5000/api/export?format=csv&severity_min=HIGH"

# Статистика агента
curl http://localhost:5000/api/agent/stats

# Профиль IP
curl http://localhost:5000/api/agent/ip/192.168.1.100

# Метрики агента
curl http://localhost:5000/api/agent/metrics

# Обратная связь агенту
curl -X POST http://localhost:5000/api/agent/feedback \
     -H "Content-Type: application/json" \
     -d '{"original_text": "SELECT * FROM products", "is_false_positive": true, "matched_pattern": "union.*select"}'

# Prometheus метрики
curl http://localhost:5000/metrics

# С API ключом (если настроен)
curl -X POST http://localhost:5000/api/check \
     -H "Content-Type: application/json" \
     -H "X-API-Key: your_api_key_here" \
     -d '{"text": "test"}'
```

### 6.4 Регрессионные тесты

```bash
# Round 4: ~164 продвинутых adversarial payload'а
py -3 bypass_r4.py

# Round 3: ~232 adversarial payload'а
py -3 bypass_r3.py

# Комплексный тест точности
py -3 ultimate_test.py

# Нагрузочный тест
py -3 stress_test.py
```

Ожидаемые результаты: `bypass_r4.py` — 164/164, `bypass_r3.py` — 232/232.

---

## 7. Конфигурация

### 7.1 Переменные окружения

| Переменная | Обязательна | По умолчанию | Описание |
|-----------|------------|-------------|---------|
| `API_KEY` | Нет | None | Ключ аутентификации API. Если не задан — все endpoint'ы публично доступны |
| `SIEM_WEBHOOK_URL` | Нет | None | URL для отправки JSON-уведомлений при блокировке атак |
| `ABUSEIPDB_API_KEY` | Нет | None | API ключ AbuseIPDB для проверки репутации IP |
| `PORT` | Нет | 5000 | Порт сервера (читается через config.py) |
| `LOG_LEVEL` | Нет | INFO | Уровень логирования |

### 7.2 AgentConfig в коде

Для кастомной конфигурации агента:

```python
from agent import SQLiAgent, AgentConfig
from sql_injection_detector import SQLInjectionEnsemble

# Более агрессивная защита
cfg = AgentConfig(
    ip_attack_threshold=2,          # бан после 2 атак (не 3)
    ip_attack_window_seconds=600,   # за 10 минут (не 5)
    ip_ban_duration_seconds=7200,   # бан на 2 часа (не 1)
    suspicious_escalation_count=2,  # 2 подозрительных → BLOCK
    reputation_tau_multiplier=0.65, # снижать tau на 35% для известных атакеров
    max_tracked_ips=50000,          # больше IP в памяти
)

detector = SQLInjectionEnsemble()
agent = SQLiAgent(detector, config=cfg)
```

### 7.3 EnsembleConfig (детектор)

```python
from sql_injection_detector import SQLInjectionEnsemble, EnsembleConfig

# Более чувствительная конфигурация
cfg = EnsembleConfig(
    w_rf=0.30,                  # уменьшить вес RF
    w_cnn=0.70,                 # увеличить вес CNN
    tau_high=0.50,              # снизить порог INJECTION (больше блокировок)
    tau_low=0.35,               # снизить порог SUSPICIOUS
    tau_safe=0.25,              # снизить порог SAFE
    tau_semantic_override=5.0,  # семантика перекрывает ML при score >= 5 (не 6)
)

detector = SQLInjectionEnsemble(config=cfg)
```

**Как настраивать пороги:**
- Снижение `tau_high` → больше блокировок, возможно больше ложных срабатываний
- Повышение `tau_safe` → меньше fast-exit, больше запросов идет через ML
- Снижение `tau_semantic_override` → семантика чаще перекрывает ML

---

## 8. Поток данных — полная трассировка запроса

Пример: IP `192.168.1.100` отправляет `' OR '1'='1` — это третья атака за 5 минут.

```
1. HTTP POST /api/check
   Body: {"text": "' OR '1'='1"}
   X-Forwarded-For: 192.168.1.100

2. security_headers_middleware → добавляет X-Frame-Options, CSP и др.
   request_id_middleware → генерирует UUID трассировки
   metrics_middleware → инкрементирует active_requests

3. check_rate_limit()
   - IP = "192.168.1.100"
   - deque для IP: [1700000000.1, 1700000015.3, ...] (предыдущие запросы)
   - Устаревшие < (now - 60) удаляются
   - len(dq) = 5 < 100 → ПРОПУСКАЕМ

4. check_api_key() → API_KEY не задан → ПРОПУСКАЕМ

5. _run_detection(text="' OR '1'='1", source_ip="192.168.1.100",
                  endpoint="/api/check", field_name=None)
   → run_in_executor (переносим в Thread pool)
   → asyncio.wait_for(..., timeout=10)

6. agent.evaluate() — начало основного пайплайна:

   6.1 _ip = "192.168.1.100" (не None, не "unknown")

   6.2 profile = ip_memory.get_profile("192.168.1.100")
       profile.attack_count = 2 (две предыдущих атаки)
       profile.recent_attacks = deque([t1, t2])
       profile.reputation_score = 0.65 (известный атакер)
       session = session_memory.get_or_create("auto-192.168.1.100")

   6.3 Правило A: ip_memory.is_banned("192.168.1.100") → False (еще не заблокирован)

   6.4 predict_prob = predictor.predict_attack_probability(profile, session)
       - Компонент 1: 0.65 * 0.3 = 0.195 (репутация)
       - Компонент 2: 0 (нет сканирования полей)
       - Компонент 3: 0.25 (2 атаки в сессии)
       → prob = 0.445
       predictive_multiplier = 1.0 (prob < 0.7, не превышает порог)

   6.5 sig_hit, sig_pattern = online_learner.check_signatures("' or '1'='1")
       → Совпадение с паттерном: r"'\s*(or|and)\s+\d+\s*=\s*\d+"
       sig_hit = True, sig_pattern = "...'\\s*(or|and)..."

   6.6 adapted_det = _get_adapted_detector(profile, "/api/check", extra_multiplier=1.0)
       - reputation_score=0.65 > 0.5 → multiplier = 1.0 * 0.75 = 0.75
       - endpoint "/api/check" не в endpoints_targeted (или нет атак там) → без изменений
       - extra_multiplier=1.0
       - multiplier = max(0.75, 0.5) = 0.75
       - Создается adapted_det с:
         tau_high = 0.60 * 0.75 = 0.45
         tau_low  = 0.40 * 0.75 = 0.30
         tau_safe = 0.30 * 0.75 = 0.225
       - rf_model, cnn_model разделяются по ссылке (не копируются)

   6.7 base_result = adapted_det.detect("' OR '1'='1", source_ip="192.168.1.100", ...)
       → Нормализация: "' or '1'='1" (lowercase)
       → Лексический анализ: найдены 'or', '=' → не fast-exit
       → RF: P_rf = 0.88
       → CNN: P_cnn = 0.94
       → P_ensemble = 0.35*0.88 + 0.65*0.94 = 0.308 + 0.611 = 0.919
       → semantic_score: OR тавтология (+3.0) + кавычка (+2.5) + паттерн (+1.5) = 7.0
       → P_ensemble = 0.919 > tau_high(0.45) И semantic_score(7.0) > tau_semantic_min(2.0)
       → decision = "INJECTION", action = "BLOCK"
       → attack_type = "BOOLEAN_BASED", severity = "MEDIUM"

   6.8 _escalate_decision():
       - recent_in_window = [t1, t2] — обе предыдущие атаки в окне 300s
         len(recent_in_window) = 2 < 3 (ip_attack_threshold)
         НО: base_result["decision"] = "INJECTION" → будет добавлена запись в recent_attacks

         Важно: recent_attacks обновляется в ip_memory.update() ПОСЛЕ эскалации.
         На момент проверки правила B: recent_in_window содержит ТОЛЬКО предыдущие атаки.

         len(recent_in_window) = 2 < threshold=3 → Правило B НЕ срабатывает пока

         [После обновления памяти attack_count станет 3,
          и СЛЕДУЮЩИЙ запрос сработает по Правилу B]

       - base_decision = "INJECTION" → Правило C (SUSPICIOUS escalation) не применяется

       - Проверка Правила E: fields_probed в сессии пуст → нет сканирования

       - sig_hit = True, agent_decision = "INJECTION" → sig_hit boost не меняет (уже INJECTION)

       → agent_decision = "INJECTION", agent_action = "BLOCK", escalated = False

   6.9 OnlineLearning:
       - agent_decision = "INJECTION" → learn_from_blocked_attack("' OR '1'='1", profile)
       - training_buffer.append(("' OR '1'='1", 1))
       - len(buffer) = 3 < 10 → partial_fit не запускается
       - attack_count = 2 < 3 → автосигнатура не извлекается

   6.10 SystemCoordinator:
        - agent_action = "BLOCK" → notify_block() вызывается
        - SIEM_WEBHOOK_URL не задан → no-op (тихо игнорируется)

   6.11 ip_memory.update("192.168.1.100", final_result, "/api/check", None)
        - profile.attack_count → 3
        - profile.recent_attacks.append(now) → [t1, t2, t3]
        - profile.attack_types["BOOLEAN_BASED"] += 1
        - profile.endpoints_targeted.add("/api/check")
        - profile.reputation_score = compute_reputation() → пересчитывается:
          = min(3/3, 1.0)*0.5 + min(3/10, 1.0)*0.3 + 0.08 (2 типа атак) = 0.5+0.09+0.08 = 0.67

   6.12 session_memory.update(...)
        - session.escalation_level → min(1+1, 3) = 2

   6.13 agent_reason = explainer.explain(base_result, agent_context)
        = "Score: 0.92 | Rule: RULE_1_HIGH_CONFIDENCE | Adaptive threshold (rep=0.65)"

        Примечание: sig_hit сработал, но это отдельное поле в agent_context.

   6.14 final_result["ip_profile"] = {
          "ip": "192.168.1.100",
          "reputation_score": 0.67,
          "attack_count": 3,  # теперь 3!
          "is_banned": False,
          ...
        }

        Следующий запрос от этого IP:
        recent_in_window = [t1, t2, t3], len = 3 >= threshold=3
        → Правило B СРАБОТАЕТ → IP будет заблокирован на 3600 секунд

7. Возврат результата в check_single():
   - elapsed = ~12ms
   - should_log = True (action = "BLOCK")
   - incident_id = logger.log_incident(...) → SQLite, returns 43

8. CheckResponse строится из final_result
   decision = "INJECTION", action = "BLOCK", blocked = True

9. metrics обновляются:
   - detections_total{decision="INJECTION", action="BLOCK"} += 1
   - blocked_total += 1
   - inference_duration.observe(0.012)
   - active_requests.dec()

10. HTTP 200 → JSON ответ клиенту
```

---

## 9. Безопасность и производственные аспекты

### 9.1 Что защищено из коробки

**Rate Limiting**
- Скользящее окно 60 секунд, 100 запросов на IP по умолчанию
- O(1) операции через deque
- Возвращает HTTP 429 при превышении лимита

**Security Headers (OWASP)**
Добавляются к каждому ответу автоматически:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-store, no-cache, must-revalidate
Content-Security-Policy: default-src 'self' (только для HTML)
```

**API Key аутентификация**
Опциональная, через заголовок `X-API-Key` или query parameter `api_key`.

**Log Injection защита**
```python
def _sanitize_log_value(value: str, max_len: int = 200) -> str:
    return value.replace("\n", "\\n").replace("\r", "\\r")[:max_len]
```
Все данные пользователя перед логированием очищаются от символов новой строки.

**Валидация входных данных**
- Pydantic схемы: `min_length=1, max_length=10000`
- Максимум 50 полей в `/api/validate`
- Валидация формата IP перед добавлением в rate-limit store

**Инъекция в rate-limit store**
```python
try:
    ipaddress.ip_address(raw_ip)
    return raw_ip
except ValueError:
    return "unknown"
```
Невалидные IP не попадают в store как ключи.

---

### 9.2 Что нужно настроить для продакшна

1. **Установить API_KEY:**
   ```bash
   export API_KEY="your-strong-random-key-here"
   ```

2. **Ограничить CORS origins** (в `config.py`):
   ```python
   cors_origins = {"https://your-app.com"}  # не "*"
   ```

3. **Включить SIEM webhook:**
   ```bash
   export SIEM_WEBHOOK_URL="https://siem.company.com/webhook"
   ```

4. **HTTPS через reverse proxy (nginx):**
   ```nginx
   server {
       listen 443 ssl;
       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header X-Forwarded-For $remote_addr;
       }
   }
   ```

5. **Мониторинг через Prometheus + Grafana:**
   - Scrape `/metrics` каждые 15 секунд
   - Базовые метрики: `sqli_detections_total`, `sqli_blocked_total`, `sqli_inference_duration_seconds`
   - **Метрики агента (новые в v3.3.0):**
     - `sqli_agent_active_bans` — активные баны в реальном времени (gauge)
     - `sqli_agent_tracked_ips` — число IP в памяти (gauge)
     - `sqli_agent_mean_reputation_score` — средняя репутация по всем IP (gauge, 0–1)
     - `sqli_agent_escalations_total` — счётчик эскалаций
     - `sqli_agent_auto_bans_total` — счётчик автоматических банов
     - `sqli_agent_false_positives_total` — ложные срабатывания, отмеченные аналитиком
     - `sqli_agent_persistence_saves_total` / `_loads_total` — операции с SQLite

---

### 9.3 Ограничения системы

| Ограничение | Статус | Описание | Как обойти |
|------------|--------|---------|-----------|
| ~~IP-память in-memory~~ | ✅ **Решено в v3.3.0** | Баны и репутация сохраняются в SQLite и восстанавливаются при перезапуске | `AgentStore` + `AGENT_DB_PATH` |
| SGD online layer in-memory | ⚠️ Частично | Веса SGD и сигнатуры теряются при перезапуске | `AgentStore.save_sgd_model()` + joblib (реализовано, но не вызывается автоматически) |
| RF и CNN статичны | ℹ️ Архитектурно | Основные модели не обновляются без переобучения | Плановое переобучение на накопленных инцидентах из SQLite |
| max_tracked_ips = 10000 | ℹ️ Настраиваемо | При превышении лимита новые IP не добавляются в память | Увеличить `AgentConfig.max_tracked_ips` или добавить eviction policy (LRU) |
| Один процесс | ⚠️ Важно | При `--workers 4` каждый воркер имеет свою независимую память и SQLite | Использовать shared state через Redis; при одном воркере SQLite достаточно |
| ThreadPoolExecutor: 4 потока | ℹ️ Настраиваемо | При пиковой нагрузке могут выстраиваться очереди | Увеличить `max_workers` через переменную окружения или конфиг |
| Rate limit in-memory | ℹ️ Аналогично IP | `_rate_limit_store` не персистентен | Вынести в Redis при multi-worker деплое |

---

## 10. Глоссарий

| Термин | Определение |
|--------|------------|
| **tau_high** | Порог `P_ensemble`, выше которого детектор выносит решение INJECTION (по умолчанию 0.60). Снижается для известных атакеров через адаптивные пороги. |
| **tau_low** | Порог `P_ensemble`, выше которого (но ниже tau_high) решение SUSPICIOUS (по умолчанию 0.40). |
| **tau_safe** | Порог `P_ensemble`, ниже которого решение SAFE — fast exit без полного анализа (по умолчанию 0.30). |
| **tau_semantic_override** | Порог семантического скора, при достижении которого семантика самостоятельно выносит INJECTION без подтверждения от ML (по умолчанию 6.0). |
| **reputation_score** | Числовой балл IP-адреса [0.0, 1.0]. Вычисляется из соотношения атак, их абсолютного числа, разнообразия типов атак и числа атакованных endpoint'ов. |
| **escalation** | Повышение уровня реакции агента: например, SAFE → SUSPICIOUS или SUSPICIOUS → INJECTION. Происходит по правилам B, C, E при наличии признаков системной атаки. |
| **adaptive threshold** | Временное снижение tau-порогов для конкретного IP с высокой репутацией атакера. Создается временный экземпляр детектора, оригинальные пороги не изменяются. |
| **sliding window** | Скользящее временное окно: при подсчете атак учитываются только те, что произошли в последние N секунд. Реализовано через deque с временными метками. |
| **partial_fit** | Инкрементальное дообучение SGDClassifier на новых примерах без полного переобучения. Позволяет модели учиться в реальном времени. |
| **SIEM** | Security Information and Event Management — система сбора и анализа событий безопасности. Получает уведомления через webhook при блокировке атак. |
| **WAF** | Web Application Firewall — межсетевой экран уровня приложения. Данная система выполняет функцию программного WAF для SQL-инъекций. |
| **P_rf** | Вероятность SQL-инъекции по оценке RandomForest классификатора, значение [0.0, 1.0]. |
| **P_cnn** | Вероятность SQL-инъекции по оценке VDCNN CharCNN (PyTorch), значение [0.0, 1.0]. |
| **P_ensemble** | Взвешенная комбинация: `0.35 * P_rf + 0.65 * P_cnn`. Основной скор для принятия решений. |
| **agent_decision** | Финальное решение агента после применения правил эскалации A–F. Может отличаться от `decision` детектора в большую сторону (строже), но никогда не смягчается. |
| **decision** | Базовое решение детектора (без контекста агента): SAFE / SUSPICIOUS / INJECTION / INVALID. |
| **contributing_factors** | Структурированный dict с детализацией решения агента. Содержит detector_score, escalation_reason, adaptive_threshold, predictive_defense, field_scanning, signature_match. Новое в v2.0 агента. |
| **AgentStore** | SQLite-персистентный слой агента. Хранит IP-профили (баны, репутация, счётчики атак). Загружается при старте, сбрасывается при shutdown и каждые 5 минут. |
| **no-op** | No operation — компонент существует, но ничего не делает до явной активации (например, SystemCoordinator без настроенных env vars). |
| **homoglyph** | Символ, визуально похожий на другой, но имеющий другой Unicode codepoint. Например, кириллическая `а` выглядит как латинская `a`, но это разные символы. Используется для обхода детекторов. |
| **adversarial payload** | Специально сконструированная строка SQL-инъекции, разработанная для обхода системы защиты через нестандартные кодировки, разбиение ключевых слов, Unicode и т.д. |
| **RLock** | threading.RLock — реентерабельная блокировка. Используется в IPMemory и SessionMemory для защиты от race conditions при параллельных запросах через ThreadPoolExecutor. |
| **WAL mode** | Write-Ahead Logging — режим SQLite, позволяющий читателям не блокировать писателей. Используется в AgentStore (`PRAGMA journal_mode=WAL`) для снижения задержек при частых flush. |

---

## 11. Что можно ещё подкрутить (Roadmap улучшений)

Система в текущем состоянии оценивается на **8/10**. Ниже — конкретный список того, что можно сделать следующим шагом для достижения 10/10.

### 11.1 Критичные улучшения (impact: высокий)

#### ✅ A. Автоматическое сохранение SGD-модели при shutdown *(реализовано в v3.4.0)*

**Реализовано:** `AgentStore.flush(agent, save_sgd=True)` автоматически сохраняет обученный `SGDClassifier` на диск через `joblib`. При следующем запуске `store.load_into(agent, load_sgd=True)` восстанавливает модель без переобучения.

**Конфигурация:** путь файла задаётся через `AgentConfig.sgd_model_path` (по умолчанию `"agent_sgd.joblib"`).

**Протестировано:** `TestSGDPersistence` (3 теста): сохранение, восстановление, graceful degradation при отсутствии файла.

**Эффект:** Накопленный online learning не теряется при деплое.

---

#### B. Redis-backend для multi-worker деплоя

**Проблема:** При `uvicorn --workers 4` каждый воркер имеет свою независимую SQLite и IP-память. IP с 2 атаками в воркере 1 и 2 атаками в воркере 2 = 4 атаки в реальности, но ни один воркер не видит полной картины.

**Что сделать:** Вынести `IPMemory` и `SessionMemory` в Redis (с TTL через `EXPIRE`). Достаточно Redis hash + sorted set для sliding window.

```python
# Концепция:
class RedisIPMemory:
    def __init__(self, redis_url: str): ...
    def update(self, ip, result, ...): redis.hincrby(f"ip:{ip}", "attack_count", 1)
    def is_banned(self, ip): return redis.exists(f"ban:{ip}")
    def ban(self, ip, duration): redis.setex(f"ban:{ip}", duration, 1)
```

**Эффект:** Горизонтальное масштабирование без потери контекста атак.

---

#### ✅ C. LRU eviction policy для `max_tracked_ips` *(реализовано в v3.4.0)*

**Реализовано:** `IPMemory.get_profile()` вызывает `_evict_lru()` при достижении лимита. Метод удаляет LRU (наименее недавно виденные) не-забаненные IP до `80%` от `max_tracked_ips` (гистерезис). Забаненные IP **никогда не вытесняются** — бан не может быть снят молчаливо.

```
get_profile(new_ip)
  └── if len(_profiles) >= max_tracked_ips:
        _evict_lru()   → удаляет до target = 0.80 * max_tracked_ips старых IP
        (banned IPs пропускаются при сортировке)
```

**Метрика:** `stats["memory"]["lru_evictions"]` — суммарное число вытесненных IP. Видна в `/api/agent/stats`.

**Протестировано:** `TestLRUEviction` (5 тестов): граничный предел, сохранение банов, порядок вытеснения, счётчик, batch-размер.

**Эффект:** Предсказуемое потребление памяти в продакшне (O(max_tracked_ips) вместо O(∞)).

---

### 11.2 Важные улучшения (impact: средний)

#### D. Настройка порогов через API без рестарта

**Проблема:** Изменение `AgentConfig.ip_attack_threshold` требует перезапуска сервера. В продакшне это нежелательно: аналитик не может оперативно реагировать на волну атак.

**Что сделать:** Добавить endpoint `PATCH /api/agent/config`:
```python
@app.patch("/api/agent/config")
async def update_agent_config(
    ip_attack_threshold: int | None = None,
    ip_ban_duration_seconds: int | None = None,
    ...
):
    if ip_attack_threshold:
        agent.config.ip_attack_threshold = ip_attack_threshold
    return agent.config
```

**Эффект:** Hot-reload конфигурации без даунтайма. Полезно при DDoS-инцидентах.

---

#### E. Whitelist IP/CIDR

**Проблема:** Нет способа исключить доверенные IP (офисные сети, партнёры, monitoring-системы) из правил агента.

**Что сделать:** Добавить в `AgentConfig`:
```python
@dataclass
class AgentConfig:
    ip_whitelist: list[str] = field(default_factory=list)  # ["10.0.0.0/8", "192.168.1.50"]
```

И в `evaluate()`:
```python
import ipaddress
for net in self.config.ip_whitelist:
    if _ip in ipaddress.ip_network(net, strict=False):
        return self._wrap_no_ip(self.detector.detect(text, ...))
```

**Эффект:** Исключение ложных срабатываний от внутренних инструментов.

---

#### F. Переобучение RF/CNN по расписанию

**Проблема:** RandomForest и CNN статичны. Новые паттерны атак (например, JSON-based SQLi, GraphQL injection) не покрываются без ручного переобучения.

**Что сделать:**
1. Экспортировать инциденты из SQLite через `/api/export?format=json`
2. Запустить дообучение в отдельном процессе раз в неделю
3. Атомарно заменить `detector.rf_model` и `detector.cnn_model` без рестарта сервера

```python
# В api_server.py:
@app.post("/api/admin/retrain")
async def trigger_retrain():
    asyncio.create_task(_retrain_models_async())
    return {"status": "scheduled"}
```

**Эффект:** Модели адаптируются к эволюции атак в конкретной среде.

---

#### G. Дашборд в реальном времени (WebSocket)

**Проблема:** Текущий мониторинг — только Prometheus (pull-модель, 15-секундный scrape interval). Аналитик не видит атаки мгновенно.

**Что сделать:** Добавить WebSocket endpoint `GET /ws/live-feed`:
```python
@app.websocket("/ws/live-feed")
async def live_feed(websocket: WebSocket):
    await websocket.accept()
    while True:
        stats = agent.get_stats()
        await websocket.send_json(stats)
        await asyncio.sleep(1)  # push каждую секунду
```

**Эффект:** Реальный мониторинг атак без Grafana.

---

### 11.3 Желательные улучшения (impact: низкий, но повышают зрелость)

#### H. Полное покрытие тестами API-слоя

**Что есть:** 97 тестов для agent.py (`test_agent.py`), тесты детектора (`bypass_r4.py`).

**Чего нет:** pytest-тесты для api_server.py с mock-инжекцией detector/agent.

**Что сделать:** `test_api.py` с `TestClient(app)` от FastAPI:
```python
from fastapi.testclient import TestClient
from api_server import app

def test_check_injection():
    resp = TestClient(app).post("/api/check", json={"text": "' OR 1=1--"})
    assert resp.status_code == 200
    assert resp.json()["decision"] == "INJECTION"
```

**Эффект:** CI/CD пайплайн не сломается при рефакторинге API.

---

#### I. Алерт-правила для Prometheus

**Что сделать:** Добавить `alerts.yml` для Prometheus Alertmanager:
```yaml
groups:
  - name: sqli_agent
    rules:
      - alert: HighBanRate
        expr: increase(sqli_agent_auto_bans_total[5m]) > 10
        labels: {severity: warning}
        annotations:
          summary: "Волна атак: {{ $value }} автобанов за 5 минут"

      - alert: HighReputationMean
        expr: sqli_agent_mean_reputation_score > 0.3
        labels: {severity: critical}
        annotations:
          summary: "Средняя репутация IP выше 0.3 — возможная DDoS-волна"

      - alert: InferenceLatencyHigh
        expr: histogram_quantile(0.95, sqli_inference_duration_seconds_bucket) > 1.0
        labels: {severity: warning}
        annotations:
          summary: "p95 латентность детекции > 1 секунды"
```

**Эффект:** PagerDuty/Slack уведомления при аномалиях без ручного мониторинга.

---

#### J. Экспорт банлиста в форматах nginx/iptables

**Что сделать:** Добавить endpoint `GET /api/agent/banlist?format=nginx`:
```
# nginx deny list (auto-generated by SQLi Protector)
deny 1.2.3.4;
deny 5.6.7.8;
```

**Эффект:** Автоматическое обновление nginx/iptables правил из банлиста агента.

---

#### K. Интеграция с VirusTotal/Shodan для threat intel

**Проблема:** AbuseIPDB — платный при больших объёмах. VirusTotal имеет бесплатный tier.

**Что сделать:** Расширить `SystemCoordinator.check_threat_intel()`:
```python
# Добавить источник VIRUSTOTAL_API_KEY
# Добавить кэширование результатов (TTL 24h) через functools.lru_cache или Redis
```

**Эффект:** Более богатый threat context без дополнительных расходов.

---

### 11.4 Итоговая таблица приоритетов

| # | Улучшение | Сложность | Эффект | Приоритет |
|---|-----------|-----------|--------|-----------|
| ✅ A | Автосохранение SGD модели | Малая (30 строк) | Средний | Готово (v3.4.0) |
| B | Redis backend для multi-worker | Высокая | Критический | 🔴 Высокий |
| ✅ C | LRU eviction для max_tracked_ips | Малая (20 строк) | Средний | Готово (v3.4.0) |
| D | Hot-reload конфигурации через API | Малая (40 строк) | Высокий | 🟡 Средний |
| E | Whitelist IP/CIDR | Малая (15 строк) | Средний | 🟡 Средний |
| F | Переобучение RF/CNN по расписанию | Высокая | Высокий | 🟡 Средний |
| G | WebSocket live feed | Средняя | Средний | 🟢 Низкий |
| H | pytest тесты API-слоя | Средняя | Средний | 🟡 Средний |
| I | Prometheus alert rules | Малая | Высокий (ops) | 🟡 Средний |
| J | Экспорт банлиста nginx/iptables | Малая (20 строк) | Низкий | 🟢 Низкий |
| K | VirusTotal/Shodan интеграция | Средняя | Низкий | 🟢 Низкий |
| ✅ L | AST layer (sqlglot) | Малая (~120 строк) | Высокий (detection) | Готово (v3.5.0) |
| ✅ M | Atomic SGD persistence | Малая (15 строк) | Средний (reliability) | Готово (v3.5.0) |

**Минимальный набор для 9/10:** ~~A~~ ✅ + ~~C~~ ✅ + ~~L~~ ✅ + D + E + I.

**Для 10/10 (enterprise-grade):** + B (Redis) + F (periodic retraining) + H (API tests).

---

## 12. Руководство по production-деплою

Этот раздел содержит ответы на вопросы, которые обязательно возникнут при развёртывании системы в реальном продакшне.

---

### 12.1 Количество воркеров и IP-память

**Критическое ограничение:** IP-память (`IPMemory`) и сессионная память (`SessionMemory`) хранятся **в RAM каждого воркера** независимо. При `--workers 4` у каждого воркера своя копия. IP с 3 атаками, распределёнными по воркерам, не получит автобан.

**Рекомендуемые варианты:**

| Сценарий | Настройка | Компромисс |
|----------|-----------|------------|
| Разработка / малая нагрузка | `--workers 1` | Нет проблемы. Безопасно. |
| Средняя нагрузка | nginx `ip_hash` + `--workers N` | Один IP всегда попадает в один воркер. Требует nginx перед uvicorn. |
| Высокая нагрузка (продакшн) | Redis backend (Roadmap B) | Полноценное решение. Требует Redis. |

**Запуск в single-worker режиме:**

```bash
# Безопасный старт (по умолчанию для этой архитектуры):
uvicorn api_server:app --host 0.0.0.0 --port 5000 --workers 1

# С персистентностью:
uvicorn api_server:app --workers 1 --log-level info
```

**Конфигурация nginx с ip_hash (workaround для multi-worker):**

```nginx
upstream sqli_backend {
    ip_hash;               # ← один IP всегда идёт в один воркер
    server 127.0.0.1:5001;
    server 127.0.0.1:5002;
    server 127.0.0.1:5003;
    server 127.0.0.1:5004;
}

server {
    listen 80;
    location /api/ {
        proxy_pass http://sqli_backend;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

> ⚠️ `ip_hash` не работает при наличии CDN/Cloudflare — все запросы идут с одного IP (CDN-ноды). В этом случае нужен заголовок `CF-Connecting-IP` или Redis backend.

---

### 12.2 Circuit breaker — защита от каскадного отказа

**Проблема:** Если SQLi Protection API недоступен (перезапуск, OOM, высокая нагрузка), вызывающее приложение должно принять решение: пропустить запрос (fail-open) или заблокировать (fail-closed).

**Политика по умолчанию: fail-open**. Большинство production-систем выбирают fail-open: временный сбой защитной системы не должен останавливать работу приложения.

| Политика | Поведение при недоступности API | Когда применять |
|----------|--------------------------------|-----------------|
| **fail-open** | Запрос пропускается, приложение работает | Общий случай: опыт пользователя важнее, падение редкое |
| **fail-closed** | Запрос блокируется с 503 | Финансовые операции, sensitive data, регуляторные требования |

**Реализация circuit breaker на стороне вызывающего приложения:**

```python
# Установка: pip install circuitbreaker
from circuitbreaker import circuit
import httpx

@circuit(
    failure_threshold=5,    # 5 неудач → открыть circuit
    recovery_timeout=30,    # через 30s попробовать снова
    expected_exception=httpx.HTTPError,
)
async def check_sqli(text: str, ip: str) -> dict:
    async with httpx.AsyncClient(timeout=1.0) as client:
        resp = await client.post(
            "http://localhost:5000/api/check",
            json={"text": text},
            headers={"X-Forwarded-For": ip},
        )
        resp.raise_for_status()
        return resp.json()

# В middleware:
async def protect_request(text: str, ip: str) -> bool:
    """Returns True if request should be blocked."""
    try:
        result = await check_sqli(text, ip)
        return result.get("agent_action") == "BLOCK"
    except Exception:
        # Circuit open или timeout → fail-open: пропустить запрос
        return False  # ← изменить на True для fail-closed
```

**Рекомендуемые таймауты:**

| Параметр | Значение | Обоснование |
|----------|---------|-------------|
| `httpx.AsyncClient(timeout=...)` | `1.0` сек | p99 латентность системы ≈ 55ms; 1s = 18× запас |
| `failure_threshold` | `5` | 5 таймаутов подряд → circuit open |
| `recovery_timeout` | `30` сек | Время на перезапуск uvicorn/systemd |

---

### 12.3 Бюджет латентности

Полный путь запроса с учётом всех компонентов:

```
Клиент → nginx (0.1ms) → uvicorn (0.2ms)
  → api_server.py rate limit check (0.1ms)
  → agent.evaluate():
      ban check (0.05ms)
      predictive defense (0.05ms)
      signature check (0.5ms)
      _get_adapted_detector (0.1ms)
      detector.detect():
          RF inference (3–8ms)       ← доминирует при hit
          CNN inference (15–40ms)    ← доминирует при VDCNN
          semantic analysis (0.5ms)
      escalation rules (0.1ms)
      memory update (0.2ms)
  → JSON serialization (0.1ms)
→ ответ клиенту

Итого p50: ~20ms | p95: ~45ms | p99: ~55ms
```

> При `--workers 1` весь ThreadPoolExecutor на 4 потока. Параллельные запросы обслуживаются конкурентно. Узкое место — CNN (GPU не используется в текущей реализации; можно добавить `device="cuda"` в `CNNDetector`).

---

### 12.4 Детекция vs Предотвращение

**Важно понимать:** эта система — **детектор, а не WAF**. Она классифицирует текст как атаку и возвращает решение `BLOCK` / `ALLOW` / `CHALLENGE`. Фактическое блокирование запроса — ответственность **вызывающего кода**.

```
[ваш API] ← BLOCK решение ← [SQLi Protector]
     │
     └── вы решаете: вернуть 400? залогировать? дропнуть?
```

Система **не заменяет**:
- Параметризованные SQL-запросы (prepared statements) — единственная надёжная защита от SQL-инъекций
- WAF (ModSecurity, AWS WAF) — работают на уровне HTTP до парсинга
- ORM с эскейпингом — SQLAlchemy, Django ORM автоматически экранируют значения

**Правильная многоуровневая архитектура:**

```
Запрос → nginx WAF (Layer 0) → SQLi Protector (Layer 1, обнаружение) → ORM (Layer 2, предотвращение)
```

---

### 12.5 Ограничения, которые нужно знать до деплоя

| Ограничение | Описание | Workaround |
|-------------|----------|------------|
| **Second-order injection** | Система не видит значения, которые были сохранены ранее и теперь используются в SQL | Проверять данные при извлечении из БД (отдельный вызов API) |
| **Multi-worker** | IP-память несогласованна между воркерами | `--workers 1` или nginx `ip_hash` или Redis |
| **No GPU** | CNN работает на CPU (~15–40ms вместо ~2ms на GPU) | `torch.device("cuda")` если GPU доступен |
| **Vendor-specific** | `LPAD()`, `EXTRACTVALUE()`, `SYS.USER$` не все покрыты | Расширить сигнатуры в `OnlineLearning` |
| ✅ **AST-анализ** | ~~Семантически корректный SQL может пройти~~ | Реализовано в v3.5.0 (`ASTLayer` + sqlglot) |

**AST Layer 1.5 реализован в v3.5.0** (`agent.py → class ASTLayer`):

- UNION SELECT после закрывающей кавычки — детектируется
- Stacked queries (`;DROP TABLE`) — детектируется
- SELECT с FROM — детектируется
- Subquery в UNION — детектируется
- Тавтологии (`1=1`), комментарии (`--`), email — **не** детектируются (0 FP на тестовом наборе)
- `pip install sqlglot` / graceful degradation если не установлен
- Статистика: `stats["ast_layer"]["hits"]` + `stats["ast_layer"]["escalations"]`

---

### 12.6 Graceful shutdown и защита SGD-модели

Потеря данных при перезапуске — реальная операционная проблема. Ниже описаны три уровня защиты, реализованные в v3.4.0.

**Уровень 1: Периодический flush (agent_cleanup_loop)**

Каждые 300 секунд (настраивается через `persistence_flush_interval`) фоновая задача сохраняет IP-профили в SQLite. Максимальная потеря данных при SIGKILL — 5 минут.

**Уровень 2: FastAPI lifespan shutdown**

При штатной остановке (`Ctrl+C`, `systemctl stop`) выполняется `store.flush(save_sgd=True)`. SGD-модель и IP-профили сохраняются до завершения процесса.

**Уровень 3: atexit + SIGTERM handler (v3.4.0)**

```
SIGTERM (systemd stop) → _sigterm_handler() → _emergency_flush() → выход
sys.exit() / исключение  → atexit.register()  → _emergency_flush()
SIGKILL (OOM killer)     → ❌ нельзя поймать  → только Level 1 спасает
```

`_emergency_flush()` в `api_server.py` — простая, exception-safe функция:
```python
def _emergency_flush() -> None:
    if agent is None or agent.store is None:
        return
    agent.store.flush(agent, min_attacks=..., save_sgd=True)
```

Хук регистрируется в `_register_shutdown_hooks()`, который вызывается в lifespan сразу после создания агента.

**Максимально возможная потеря данных:**

| Сценарий остановки | Потеря IP-данных | Потеря SGD |
|--------------------|-----------------|------------|
| `Ctrl+C` / `systemctl stop` | 0 (lifespan flush) | 0 |
| SIGTERM | 0 (signal handler) | 0 |
| Необработанное исключение | 0 (atexit) | 0 |
| SIGKILL / OOM killer | ≤ 5 минут | ≤ 5 минут |
| Аппаратный сбой | ≤ 5 минут | ≤ 5 минут |

---

### 12.7 Защита от DoS на уровне ввода (v3.4.1)

**Проблема из threat model (D — Denial of Service):** очень длинная строка на вход CNN создаёт линейную нагрузку. До v3.4.1 `POST /api/validate` не ограничивал длину отдельных значений полей.

**Что реализовано:**

| Ограничение | Эндпоинт | Значение | Поведение при превышении |
|-------------|----------|---------|--------------------------|
| Длина текста | `POST /api/check` | 10 000 символов | Pydantic → HTTP 422 |
| Длина значения поля | `POST /api/validate` | 10 000 символов | Truncate + сообщить в `truncated_fields` |
| Длина ключа поля | `POST /api/validate` | 256 символов | HTTP 400 |
| Количество полей | `POST /api/validate` | 50 полей | HTTP 400 |

**Почему truncate, а не reject для `/api/validate`:** атаки в 99% случаев содержат паттерн в первых нескольких сотнях символов. Rejection при превышении 10k символов создаёт ложные срабатывания для текстовых полей (комментарии, биографии). Truncation позволяет проверить видимую часть и сообщить о факте усечения.

```json
// Ответ при усечённых полях:
{
  "safe": true,
  "blocked_fields": [],
  "results": {...},
  "truncated_fields": ["bio", "description"],
  "processing_time_ms": 34.2
}
```

---

### 12.8 Kubernetes / health endpoints

Доступны два стандартных probe endpoint (не требуют API-ключа, не логируются):

```yaml
# kubernetes deployment.yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 5000
  initialDelaySeconds: 10
  periodSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readyz
    port: 5000
  initialDelaySeconds: 30      # время загрузки моделей
  periodSeconds: 5
  failureThreshold: 2
```

| Endpoint | Проверяет | HTTP 200 когда | HTTP 503 когда |
|----------|-----------|----------------|----------------|
| `GET /healthz` | Процесс жив, event loop отвечает | Всегда (если процесс запущен) | Никогда* |
| `GET /readyz` | RF или CNN загружен, агент инициализирован | Модели загружены | Инициализация не завершена |
| `GET /api/health` | Всё + статистика инцидентов | Всегда | Никогда |

\* Если `/healthz` не отвечает — процесс завис, k8s перезапускает pod.

**Разделение liveness и readiness критически важно:** если использовать один endpoint для обоих, медленная загрузка моделей (~15-30s) приведёт к бесконечному циклу перезапуска pod.

---

### 12.9 Чеклист перед первым деплоем

- [ ] Установить `API_KEY` в переменных окружения (`export API_KEY=<32-char-hex>`)
- [ ] Убедиться, что `--workers 1` или настроен nginx `ip_hash`
- [ ] Выбрать политику fail-open/fail-closed и зафиксировать её в коде
- [ ] Установить таймаут на стороне клиента ≤ 1 секунда
- [ ] Добавить circuit breaker (5 ошибок → 30s pause)
- [ ] Настроить systemd / supervisor для автоперезапуска (`Restart=on-failure`)
- [ ] Убедиться, что systemd использует `KillSignal=SIGTERM` (по умолчанию) — не SIGKILL
- [ ] Настроить `/healthz` как liveness probe, `/readyz` как readiness probe
- [ ] Проверить доступность `/metrics` для Prometheus scrape
- [ ] Запустить демо: `py -3 agent.py` — убедиться, что эскалация и автобан работают
- [ ] Запустить регрессию: `py -3 bypass_r4.py` — 164/164 (100%)
- [ ] Запустить тесты: `py -3 -m pytest test_agent.py` — 73/73 passed
