# Архитектура системы обнаружения SQL-инъекций

## Обзор

Каждый входной текст проходит **7 последовательных слоёв** обработки.
Слои спроектированы с принципом defense-in-depth: каждый слой независимо проверяет
и уточняет решение предыдущего.

```
Входной текст
     │
     ▼──────────────────────────────────────────────────
     │  Слой 0 — Нормализация
     │  URL-decode → unicode NFKC → null-bytes strip → comment expand
     ▼──────────────────────────────────────────────────
     │  Слой 1 — Лексический фильтр (быстрый путь)
     │  Если SQL-паттерн НЕ найден → SAFE (выход без ML)
     ▼──────────────────────────────────────────────────
     │  Слой 2 — ML Ансамбль
     │  Random Forest (35%) + VDCNN-9 CNN (65%) → score S ∈ [0,1]
     ▼──────────────────────────────────────────────────
     │  Слой 3 — Семантическая валидация (sqlglot AST)
     │  Инвариант: ML один НЕ МОЖЕТ → INJECTION без semantic_score ≥ τ
     ▼──────────────────────────────────────────────────
     │  Слой 4 — Движок решений (8 правил приоритета)
     ▼──────────────────────────────────────────────────
     │  Слой 5 — Серьёзность и действие: ALLOW / LOG / BLOCK / ALERT
     ▼──────────────────────────────────────────────────
     │  Слой 6 — Объяснение (trace, MITRE ATT&CK, SIEM CEF-поля)
     ▼
  Результат
```

---

## Слой 0 — Нормализация

**Цель:** привести входной текст к каноническому виду, устранить обфускацию.

Операции (применяются последовательно):
1. URL-декодирование (`%27` → `'`, `%20` → ` `)
2. Unicode NFKC нормализация (полноширинные символы → ASCII)
3. Удаление null-байтов (`\x00`)
4. Раскрытие SQL-комментариев:
   - `/*comment*/` → пробел
   - `--остаток строки` → пустая строка
   - `/*!50000 version-specific */` → раскрывается

**Пример:**
```
Вход:  %27%20OR%20%271%27%3D%271
После: ' OR '1'='1
```

---

## Слой 1 — Лексический фильтр

**Цель:** быстрый выход для 100% безопасных входных данных (без ML).

Проверяет наличие SQL-лексем: `SELECT`, `UNION`, `INSERT`, `UPDATE`, `DELETE`, `DROP`,
`EXEC`, `CAST`, `CONVERT`, `SLEEP`, `BENCHMARK`, `--`, `/*`, `'`, `;`.

Если ни одна лексема не найдена → результат `SAFE` немедленно, без обращения к ML.
Это снижает нагрузку на ~40% запросов (обычные поля форм без SQL).

---

## Слой 2 — ML Ансамбль

### 2.1 Random Forest

| Параметр | Значение |
|----------|---------|
| Алгоритм | RandomForestClassifier (sklearn) |
| Деревья | 200 |
| Глубина | 30 |
| Веса классов | balanced |
| Признаки | TF-IDF char_wb 2-5gram (50 000) + 5 рукописных |
| Рукописные признаки | length, num_digits, num_special, num_quotes, num_keywords |
| Итого признаков | 50 005 |

### 2.2 VDCNN-9 (Very Deep CNN)

Архитектура по статье **Conneau et al. (2017) "Very Deep Convolutional Networks for Text Classification"**.

| Параметр | Значение |
|----------|---------|
| Входной алфавит | 70 символов (ASCII печатаемые) |
| Max length | 200 символов |
| Embedding dim | 16 |
| Глубина | 9 свёрточных блоков |
| k-max pooling | k=8 |
| FC dim | 1024 |
| Параметры | 7 003 089 |
| Optimizer | AdamW (lr=0.001, weight_decay=1e-4) |
| Criterion | BCEWithLogitsLoss + label smoothing 0.05 |
| Обучение | 35 эпох, mixed precision (GPU/CPU) |

### 2.3 Ансамблирование

```
P_ensemble = 0.65 × P_cnn + 0.35 × P_rf
```

Веса выбраны эмпирически: CNN имеет лучший recall (меньше пропущенных атак),
RF обеспечивает высокую precision (почти 0 ложных тревог).
Вес 0.65 для CNN смещает ансамбль в сторону recall при сохранении precision ансамбля выше RF.

---

## Слой 3 — Семантическая валидация

**Инструмент:** `sqlglot` — SQL-парсер с поддержкой 20+ диалектов.

**Ключевой инвариант системы:**
> ML classifier score ≥ threshold → CANDIDATE
> Но: `INJECTION` выставляется только если ТАКЖЕ `semantic_score ≥ τ_semantic_min`

Это исключает ложные срабатывания ML на безвредных строках, похожих на SQL.

Семантический анализ определяет:
- Тип атаки: BOOLEAN_BASED, UNION_BASED, STACKED_QUERY, TIME_BASED и др.
- Наличие опасных конструкций: `DROP TABLE`, `EXEC xp_cmdshell`, `SLEEP()`, `UNION SELECT`

---

## Слой 4 — Движок решений

8 правил с жёстким приоритетом (порядок важен):

| Приоритет | Правило | Действие |
|-----------|---------|---------|
| 1 | Явная семантика STACKED_QUERY / OS_COMMAND | INJECTION (CRITICAL) |
| 2 | `P_ensemble ≥ 0.95` И semantic подтверждение | INJECTION |
| 3 | `P_ensemble ≥ 0.85` | SUSPICIOUS |
| 4 | semantic_score ≥ τ без ML | INJECTION (semantic-only) |
| 5 | `P_ensemble ≥ 0.65` | SUSPICIOUS (LOW) |
| 6 | Известный безопасный паттерн (whitelist) | SAFE |
| 7 | `P_ensemble < τ_safe` | SAFE |
| 8 | Default | LOG (неопределённый) |

---

## Слой 5 — Серьёзность и действие

| Класс | Severity | Действие | Примеры |
|-------|----------|---------|---------|
| STACKED_QUERY, OS_COMMAND | CRITICAL | BLOCK + ALERT | `'; DROP TABLE--`, `xp_cmdshell` |
| UNION_BASED, ERROR_BASED | HIGH | BLOCK | `UNION SELECT`, `extractvalue()` |
| BOOLEAN_BASED, TIME_BASED | MEDIUM | LOG + BLOCK | `' OR 1=1`, `SLEEP(5)` |
| COMMENT_TRUNCATION | LOW | LOG | `admin'--` |
| OUT_OF_BAND | CRITICAL | BLOCK + ALERT | DNS-exfil |

---

## Слой 6 — Объяснение

Каждый результат содержит:
- `decision_trace` — пошаговое логирование решения
- `mitre_technique` — маппинг на MITRE ATT&CK (T1190 — Exploit Public-Facing Application)
- SIEM CEF-поля: `src_ip`, `event_id`, `severity`, `signature`
- Для BLOCK: `block_reason` и `recommendation`

---

## AI-Агент (agent.py)

Автономный агент поверх детектора:

- **IP-память** — RLock-защищённый словарь истории по IP
- **Онлайн обучение** — SGDClassifier partial_fit() на потоке событий
- **Эскалация** — автоматическое повышение severity при паттернах атаки
- **State backend** — SQLite (dev) или Redis (prod) для персистентности между перезапусками

---

## Структура файлов

```
sql_injection_detector.py  — 7-слойный пайплайн (~2000 строк)
config.py                  — параметры (env vars, dataclass frozen=True)
agent.py                   — AI-агент
api_server.py              — FastAPI + Prometheus
demo_site.py               — TenderPro демо
incident_logger.py         — SQLite инциденты
state_backend.py           — SQLite / Redis backend
models/
├── char_cnn_detector.pt   — VDCNN-9 веса (PyTorch, 27 MB)
├── char_cnn_model.py      — архитектура модели
├── char_tokenizer.py/json — символьный токенизатор
├── bilstm_sql_detector.pt — BiLSTM (альтернатива)
└── char_bilstm_model.py
rf_sql_model.pkl           — Random Forest
tfidf_vectorizer.pkl       — TF-IDF векторизатор
training/
├── train_cnn.py           — обучение VDCNN-9
├── train_rf.py            — обучение RF
├── generate_dataset.py    — генерация/аугментация датасета
└── *_training_log.json    — логи обучения
```
