# Changelog

Все значимые изменения проекта документируются в этом файле.

Формат — [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
версионирование — [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [3.1.0] — 2026-04

### Added
- `docs/ARCHITECTURE.md` — полное описание 7-слойной архитектуры
- `docs/EVALUATION.md` — методология оценки, метрики, анализ обходов
- `.env.example` — шаблон конфигурации со всеми переменными окружения
- Секция "Метод интерпретации (Occlusion Heatmap)" в README
- `CHANGELOG.md` — этот файл

### Changed
- README: добавлены ссылки на документы и секция интерпретации

---

## [3.0.0] — 2026-02

### Added
- **VDCNN-9** (PyTorch) — 9-слойная символьная CNN, заменила старую LSTM
- **Char-level Occlusion Heatmap** (`char_heatmap.py`) — уникальный метод интерпретации
- **Семантическая валидация** через `sqlglot` (Слой 3)
- **Redis-backend** для распределённого хранения состояния
- **Prometheus**-метрики на `/metrics`
- **CEF-экспорт** инцидентов (для ArcSight/Splunk)
- **TenderPro** demo-сайт (`demo_site.py`) с SOC-панелью
- 495 тестов в `tests/` (детектор, API, обходы, fuzz, distributed)
- CI/CD: GitHub Actions, matrix py3.11/3.12/3.13

### Changed
- Ансамбль перешёл с 3 моделей (LSTM+CNN+RF) на 2 (CNN+RF) с весами 0.65 / 0.35
- Конфигурация — все пороги через env-vars (`config.py`)
- Логи — JSON structured (через `logger.py`)

### Performance
- F1 ансамбля: 0.985 → **0.993**
- p95 latency: 140 мс → **~95 мс**
- Throughput: 8 RPS → **17 RPS** (single core)

---

## [2.0.0] — 2025-Q4

### Added
- Random Forest на TF-IDF (char_wb, 2-5gram) + 5 ручных признаков
- FastAPI-сервер (`api_server.py`)
- Логирование инцидентов в SQLite (`incident_logger.py`)
- IP-репутация-агент (`agent.py`)
- 9 типов атак с MITRE ATT&CK mapping
- Dockerfile + docker-compose

---

## [1.0.0] — 2025-Q3

### Added
- Первая версия: rule-based детектор + LSTM-classifier
- CLI-интерфейс
- Базовый датасет (~30K примеров)
