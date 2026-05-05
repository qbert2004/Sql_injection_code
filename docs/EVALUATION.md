# Оценка SQL Injection Detection System

> Методология, метрики, анализ ошибок, ограничения

---

## 1. Постановка задачи

**Цель:** Бинарная классификация пользовательского ввода — `SAFE` vs `INJECTION` —
с расширенной типизацией атак (9 классов) и production-grade latency.

**Критерии успеха:**
- F1 ансамбля ≥ 0.99 на тестовой выборке
- False-Positive Rate ≤ 2 %
- p95 latency ≤ 100 мс на одном CPU-ядре
- Робастность к обходам (URL-encode, Unicode, комментарии)

---

## 2. Датасет

| Источник | Тип | Кол-во |
|----------|-----|--------|
| `data/dataset.csv` (базовый) | benign + injection (открытые корпуса) | ~30 000 |
| `SQL_Dataset_Extended.csv` | дополненный (обфускации, edge cases) | ~30 000 |

Hash датасета (для воспроизводимости): `b3f2af8da4b4b240…` — см. `model_metadata.json`.

**Стратифицированный split** (70 / 15 / 15) train / val / test.

---

## 3. Модели

### 3.1 Random Forest

| Гиперпараметр | Значение |
|---------------|----------|
| `n_estimators` | 200 |
| `max_depth` | 30 |
| `class_weight` | `balanced` |
| Признаки | TF-IDF (`char_wb`, ngram 2-5, max 50 000) ⊕ 5 ручных (length, num_digits, num_special, num_quotes, num_keywords) |
| **Total features** | 50 005 |

**Метрики на test:**

| | Precision | Recall | F1 |
|---|:---:|:---:|:---:|
| SAFE      | 0.989 | 0.994 | 0.991 |
| INJECTION | 0.994 | 0.989 | 0.992 |
| **weighted** | **0.992** | **0.992** | **0.992** |

Команда воспроизведения:
```bash
python training/train_rf.py
```

### 3.2 VDCNN-9 (CNN)

Очень-глубокая char-CNN (Conneau et al. 2017), адаптированная под SQL:
9 conv-блоков, k-max pooling, char-embedding 16-dim, vocab 95 ASCII printable.

| Гиперпараметр | Значение |
|---------------|----------|
| Epochs | 35 |
| Optimizer | Adam (lr=1e-3) |
| Batch size | 256 |
| Loss | Cross-entropy |
| Регуляризация | dropout 0.3, weight decay 1e-5 |

**Метрики на test:** F1 = 0.999, ROC-AUC = 0.9998.

Команда:
```bash
python training/train_cnn.py --epochs 35
```

### 3.3 Ансамбль

Простое взвешенное среднее `0.65·CNN + 0.35·RF` + 8 правил приоритета (см. `DecisionEngine`).
Семантическая валидация (`sqlglot`) обязательна для финального вердикта `INJECTION`.

**Финальные метрики:**

| Метрика | Значение |
|---------|----------|
| Accuracy | 99.30 % |
| Precision (INJECTION) | 99.4 % |
| Recall (INJECTION) | 99.2 % |
| **F1 weighted** | **0.993** |
| FPR | 1.5 % |

---

## 4. Производительность

Бенчмарк (`benchmark.py`, single core, Python 3.13, без GPU):

| Этап | p50, мс | p95, мс |
|------|:---:|:---:|
| Нормализация (Слой 0) | 0.4 | 1.1 |
| Лексический фильтр (Слой 1) | 0.2 | 0.5 |
| RF inference | 8 | 14 |
| CNN inference (CPU) | 38 | 56 |
| Семантика (`sqlglot`) | 9 | 21 |
| Decision + severity | 0.3 | 0.8 |
| **End-to-end** | **~58** | **~95** |

Throughput при `RATE_LIMIT=0`: **~17 RPS** на одном ядре, линейно масштабируется числом воркеров uvicorn.

Стресс-тест (`tests/stress_test.py`, 72 сценария): без regression-ов >0.1 % score.

---

## 5. Робастность к обходам

`tests/test_bypass_audit.py` проверяет 6 классов техник обхода:

| Техника | Пример | Detection |
|---------|--------|:---:|
| URL-encoding | `%27%20OR%201%3D1` | ✅ |
| Двойное URL-encoding | `%2527%2520OR…` | ✅ |
| Unicode-омоглифы | `′ OR 1=1` (U+2032) | ✅ |
| SQL-комментарии в середине | `OR/**/1=1` | ✅ |
| Null-byte | `' OR 1=1\x00--` | ✅ |
| Смешанный регистр + whitespace tricks | `' Or\t1\n=\r1--` | ✅ |

Все 6 классов покрыты регрессионными тестами.

---

## 6. Анализ ошибок

### 6.1 False Positives (1.5 %)

Чаще всего — ложно-сработавшие правила на «программистских» вводах:
- `O'Brien`, `D'Angelo` (фамилии с апострофом)
- `SELECT TOP 10 …` в полях поиска кода
- Запросы из stackoverflow-stackexchange-подобных форумов

Mitigation: семантическая валидация (`sqlglot`) гасит ~70 % таких случаев.

### 6.2 False Negatives

Редкие случаи (<0.5 %):
- Многоступенчатые **out-of-band** атаки с DNS-эксфильтрацией без классических токенов
- Полная обфускация через `CHAR()`/`CHR()` без символов кавычек

---

## 7. Метод интерпретации — Occlusion Heatmap

Для каждого прогноза вычисляется атрибуция на уровне отдельных символов:

```
Δ_i = score(query) − score(query_with_char_i_masked)
```

- `Δ > 0` — символ **увеличивает** опасность (часть payload)
- `Δ < 0` — символ **снижает** опасность (отвлекающая «маска»)

**10 примеров** заранее визуализированы (`models/heatmap_01..10.png`):
boolean, UNION, time-based, comment-truncation, stacked, encoded, плюс 4 безопасных
запроса (контроль).

**HTML-отчёт** (`heatmap_report.html`): hover на символе показывает Δ.

Преимущество перед SHAP/LIME: оператор SOC видит **позицию** атакующего фрагмента,
а не «вес признака» — это критично для триажа инцидентов.

---

## 8. Ограничения

| # | Ограничение | Митигация |
|---|-------------|-----------|
| 1 | CNN на CPU добавляет ~40 мс latency | Опциональный GPU-режим (PyTorch CUDA) |
| 2 | Не покрывает NoSQL-инъекции (Mongo, Redis) | Out of scope — только SQL |
| 3 | Семантический парсер не знает все диалекты | `sqlglot` поддерживает 20+ диалектов; неизвестные парсятся в generic SQL |
| 4 | Datasets могут устаревать (новые техники) | CI-пайплайн поддерживает периодическое переобучение |
| 5 | Occlusion-объяснения медленные на длинных запросах | Линейная сложность O(n×T_inference); ограничение `max_input_length=10 000` |

---

## 9. Воспроизводимость

```bash
# 1. Установить
pip install -r requirements.txt

# 2. Переобучить RF (~2 мин CPU)
python training/train_rf.py

# 3. Переобучить CNN (рекомендуется GPU)
python training/train_cnn.py --epochs 35

# 4. Прогнать тесты
pytest tests/ -v       # 495 passed

# 5. Бенчмарк latency
python benchmark.py

# 6. Сгенерировать heatmap-отчёт
python char_heatmap.py
```

Hash датасета и версии библиотек — в `model_metadata.json`.
