# 🚀 КАК ЗАПУСТИТЬ AI АГЕНТ

## ✅ Всё уже готово! Система работает!

---

## 📋 3 СПОСОБА ЗАПУСКА

### 1️⃣ ПРОСТОЙ ТЕСТ (CLI)

```bash
# Анализ текста
python cli.py analyze "' OR '1'='1"

# Интерактивное тестирование
python cli.py test

# Бенчмарк
python cli.py benchmark
```

---

### 2️⃣ API СЕРВЕР (Рекомендуется)

```bash
# Запустить сервер
python app.py
```

**Откроется на:** http://localhost:8000

**Документация API:** http://localhost:8000/docs

**Проверить статус:**
```bash
curl http://localhost:8000/health
```

**Проанализировать текст:**
```bash
curl -X POST "http://localhost:8000/api/analyze" ^
  -H "Content-Type: application/json" ^
  -d "{\"text\": \"' OR '1'='1\"}"
```

---

### 3️⃣ В PYTHON КОДЕ

```python
from sql_injection_detector import SQLInjectionAgent

# Инициализация
agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")

# Анализ
result = agent.analyze("' OR '1'='1")

print(f"Вредоносный: {result.is_malicious}")
print(f"Уверенность: {result.confidence:.2%}")
print(f"Метод: {result.detection_method}")
```

---

## 🧪 БЫСТРЫЙ ТЕСТ

```bash
# 1. Проверка детектора
python sql_injection_detector.py

# 2. Запуск тестов
pytest tests/test_agent.py -v

# 3. CLI тесты
python cli.py analyze "admin' --"
python cli.py analyze "john@example.com"
```

---

## 📊 ПОЛНЫЕ КОМАНДЫ CLI

```bash
# Обучение модели
python cli.py train

# Анализ текста
python cli.py analyze "текст для анализа"

# Интерактивное тестирование
python cli.py test

# Бенчмарк
python cli.py benchmark

# Запуск сервера
python cli.py server --port 8000

# Статус сервера
python cli.py status

# Экспорт датасета
python cli.py export-dataset -o dataset.json
```

---

## 🎯 ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ

### Проверка вредоносных запросов:

```bash
python cli.py analyze "' OR '1'='1"
python cli.py analyze "admin' --"
python cli.py analyze "1' UNION SELECT * FROM users--"
python cli.py analyze "'; DROP TABLE users--"
```

### Проверка безопасных запросов:

```bash
python cli.py analyze "john.doe@example.com"
python cli.py analyze "Product Name 123"
python cli.py analyze "Search query"
```

---

## 🔥 ИНТЕГРАЦИЯ В ВАШ ПРОЕКТ

### FastAPI:

```python
from fastapi import FastAPI
from sql_injection_detector import SQLInjectionAgent
from fastapi_middleware import SQLInjectionMiddleware

app = FastAPI()
agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")

# Добавить middleware
app.add_middleware(
    SQLInjectionMiddleware,
    agent=agent,
    enabled=True,
    block_on_detection=True
)

# Теперь все запросы автоматически проверяются!
```

---

## 📁 СТРУКТУРА ПРОЕКТА

```
SQL_INJECTION_PROTECTOR_AI_AGENT/
├── app.py                      # Главное FastAPI приложение
├── cli.py                      # CLI интерфейс
├── sql_injection_detector.py  # Ядро детектора
├── train_model.py             # Обучение модели
├── fastapi_middleware.py      # Middleware
├── safe_database_layer.py     # Безопасный DB слой
├── tests/                     # Тесты
│   └── test_agent.py
├── requirements.txt           # Зависимости
├── README.md                  # Полная документация
├── QUICKSTART.md             # Быстрый старт
└── START.md                  # Это руководство
```

---

## ⚙️ НАСТРОЙКА

### Изменить порог детектирования:

```python
agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")
agent.DETECTION_THRESHOLD = 0.6  # Более строгий (по умолчанию 0.5)
agent.RISK_THRESHOLD = 0.7       # Более строгий (по умолчанию 0.6)
```

---

## 🆘 РЕШЕНИЕ ПРОБЛЕМ

### Модель не найдена?
```bash
python sql_injection_detector.py  # Обучит модель автоматически
```

### Порт 8000 занят?
```bash
python cli.py server --port 8080  # Используйте другой порт
```

### Нужна помощь?
```bash
python cli.py --help
```

---

## 📈 МЕТРИКИ И МОНИТОРИНГ

```bash
# Запустите сервер
python app.py

# Проверьте метрики
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

---

## 🎓 ДОПОЛНИТЕЛЬНО

- **Полная документация:** README.md
- **Быстрый старт:** QUICKSTART.md
- **API документация:** http://localhost:8000/docs (после запуска сервера)

---

## ✨ ГОТОВО!

Ваш AI агент для защиты от SQL инъекций полностью настроен и работает!

**Запустите сейчас:**
```bash
python app.py
```

И откройте http://localhost:8000/docs

🎉 **Наслаждайтесь защитой!**
