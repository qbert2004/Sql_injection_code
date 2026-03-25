# Changelog

## [3.9.0] — 2026

### Added
- TenderPro: демо-сайт корпоративного портала закупок с панелью безопасности SOC
- Унифицированный README с полной документацией на русском языке
- Исправления тестов: `probabilities` всегда возвращает все 3 ключа класса

## [3.7.0] — 2025

### Added
- VDCNN-9 (Very Deep CNN) — символьная нейросеть на PyTorch, 7M параметров
  - test F1=99.89%, AUC=99.97%, FPR=0.055%, FNR=0.147%
  - Архитектура по статье Conneau et al. 2017
  - AdamW + cosine LR decay, label smoothing 0.05, mixed precision (GPU)
- BiLSTM символьный детектор (альтернативная архитектура)
- Ансамблирование: `0.65 × CNN + 0.35 × RF`
- `char_tokenizer.py`: символьная токенизация, max_length=200

## [3.1.0] — 2025

### Added
- AI-агент (`agent.py`): IP-память, онлайн обучение (SGD), эскалация угроз
- `state_backend.py`: подключаемое хранилище состояния (SQLite / Redis)
- `incident_logger.py`: SQLite-база инцидентов
- Распределённые тесты (`test_distributed.py`): multi-worker state isolation
- Stress-тесты (72 сценария), load-тесты, soak-тесты

## [2.0.0] — 2025

### Added
- Random Forest: TF-IDF char_wb 2-5gram + 5 рукописных признаков, 200 деревьев
  - test F1=99.14%, AUC=99.98%, FPR=0.023%
- FastAPI-сервер: `/check`, `/validate`, `/stats`, `/export`, Prometheus `/metrics`
- 7-слойный пайплайн обнаружения (нормализация → лексика → ML → семантика → решение → серьёзность → объяснение)
- sqlglot AST семантическая валидация
- Инвариант безопасности: ML один не может выставить INJECTION без `semantic_score ≥ τ`

## [1.0.0] — 2024

### Added
- Базовый XOR-фильтр SQL-ключевых слов
- Нормализация входного текста (URL-decode, null-байты, unicode NFKC)
- Простой REST-эндпоинт на Flask
