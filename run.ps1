# run.ps1 - Универсальный runner для SQL Injection Protector
# Использование: .\run.ps1 <command>

param(
    [Parameter(Position=0)]
    [string]$Command = "help"
)

# Функция для цветного вывода
function Write-Color {
    param([string]$Color, [string]$Text)
    Write-Host $Text -ForegroundColor $Color
}

# Активация виртуального окружения
function Activate-Venv {
    if (Test-Path ".venv\Scripts\Activate.ps1") {
        & ".\.venv\Scripts\Activate.ps1"
    }
}

# Команды
switch ($Command.ToLower()) {
    "help" {
        Write-Color "Cyan" "╔══════════════════════════════════════════════════════════════╗"
        Write-Color "Cyan" "║  SQL Injection Protector - Доступные команды                ║"
        Write-Color "Cyan" "╚══════════════════════════════════════════════════════════════╝"
        Write-Host ""
        Write-Color "Yellow" "Основные команды:"
        Write-Host "  start           - Запустить приложение"
        Write-Host "  test            - Запустить тесты"
        Write-Host "  test-advanced   - Запустить продвинутые тесты"
        Write-Host "  train           - Обучить ML модель"
        Write-Host "  clean           - Очистить временные файлы"
        Write-Host "  docker-up       - Запустить Docker Compose"
        Write-Host "  docker-down     - Остановить Docker Compose"
        Write-Host "  logs            - Показать логи"
        Write-Host "  health          - Проверить здоровье приложения"
        Write-Host "  setup           - Полная настройка проекта"
        Write-Host ""
        Write-Color "Yellow" "Примеры:"
        Write-Host "  .\run.ps1 start"
        Write-Host "  .\run.ps1 test"
        Write-Host "  .\run.ps1 docker-up"
        Write-Host ""
    }

    "setup" {
        Write-Color "Cyan" "🚀 Запуск полной настройки..."
        .\setup.ps1
    }

    "start" {
        Write-Color "Cyan" "🚀 Запуск приложения..."
        Activate-Venv
        python app.py
    }

    "dev" {
        Write-Color "Cyan" "🚀 Запуск в dev режиме (с auto-reload)..."
        Activate-Venv
        python -m uvicorn app:app --reload --host 0.0.0.0 --port 8000
    }

    "test" {
        Write-Color "Cyan" "🧪 Запуск тестов..."
        Activate-Venv
        pytest tests\ -v
    }

    "test-advanced" {
        Write-Color "Cyan" "🧪 Запуск продвинутых тестов..."
        Activate-Venv
        pytest tests\test_advanced.py -v -s
    }

    "test-coverage" {
        Write-Color "Cyan" "🧪 Запуск тестов с покрытием..."
        Activate-Venv
        pytest tests\ -v --cov=src --cov-report=html
        Write-Color "Green" "✅ Отчет: htmlcov\index.html"
    }

    "train" {
        Write-Color "Cyan" "🎓 Обучение ML модели..."
        Activate-Venv
        python scripts\train_model.py
    }

    "train-eval" {
        Write-Color "Cyan" "🎓 Обучение и оценка модели..."
        Activate-Venv
        python scripts\train_model.py --evaluate
    }

    "clean" {
        Write-Color "Cyan" "🧹 Очистка временных файлов..."
        Get-ChildItem -Path . -Include __pycache__,*.pyc,*.pyo,.pytest_cache -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path htmlcov -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path .coverage -Force -ErrorAction SilentlyContinue
        Write-Color "Green" "✅ Очистка завершена"
    }

    "docker-up" {
        Write-Color "Cyan" "🐳 Запуск Docker Compose..."
        docker-compose up -d
        Write-Color "Green" "✅ Контейнеры запущены"
        Write-Color "Yellow" "API: http://localhost:8000"
        Write-Color "Yellow" "Docs: http://localhost:8000/docs"
        Write-Color "Yellow" "Grafana: http://localhost:3000"
    }

    "docker-down" {
        Write-Color "Cyan" "🐳 Остановка Docker Compose..."
        docker-compose down
        Write-Color "Green" "✅ Контейнеры остановлены"
    }

    "docker-logs" {
        Write-Color "Cyan" "🐳 Логи Docker..."
        docker-compose logs -f api
    }

    "docker-restart" {
        Write-Color "Cyan" "🐳 Перезапуск Docker..."
        docker-compose down
        docker-compose up -d
        Write-Color "Green" "✅ Docker перезапущен"
    }

    "logs" {
        Write-Color "Cyan" "📋 Показ логов..."
        if (Test-Path "logs\security.log") {
            Get-Content "logs\security.log" -Tail 50 -Wait
        } else {
            Write-Color "Yellow" "⚠️  Лог файл не найден"
        }
    }

    "health" {
        Write-Color "Cyan" "🏥 Проверка здоровья..."
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get
            $response | ConvertTo-Json
            Write-Color "Green" "✅ Приложение работает"
        } catch {
            Write-Color "Red" "❌ Приложение не отвечает"
        }
    }

    "metrics" {
        Write-Color "Cyan" "📈 Метрики приложения..."
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:8000/metrics" -Method Get
            $response | ConvertTo-Json
        } catch {
            Write-Color "Red" "❌ Приложение не отвечает"
        }
    }

    "format" {
        Write-Color "Cyan" "✨ Форматирование кода..."
        Activate-Venv
        black src\ tests\ --line-length=120
        isort src\ tests\
        Write-Color "Green" "✅ Код отформатирован"
    }

    "lint" {
        Write-Color "Cyan" "🔍 Проверка кода..."
        Activate-Venv
        flake8 src\ tests\ --max-line-length=120
    }

    "install" {
        Write-Color "Cyan" "📦 Установка зависимостей..."
        Activate-Venv
        pip install --upgrade pip
        pip install -r requirements.txt
        Write-Color "Green" "✅ Зависимости установлены"
    }

    "info" {
        Write-Color "Cyan" "╔══════════════════════════════════════════════════════════════╗"
        Write-Color "Cyan" "║  SQL Injection Protector - Project Info                     ║"
        Write-Color "Cyan" "╚══════════════════════════════════════════════════════════════╝"
        Write-Host ""
        Write-Color "Green" "Project:        sql-injection-protector"
        Write-Host "Python:         $(python --version)"
        Write-Host "Pip:            $(pip --version)"
        Write-Host ""
        Write-Color "Green" "Directories:"
        Write-Host "  Source:       src\"
        Write-Host "  Tests:        tests\"
        Write-Host "  Models:       models\"
        Write-Host "  Logs:         logs\"
        Write-Host ""
    }

    default {
        Write-Color "Red" "❌ Неизвестная команда: $Command"
        Write-Host ""
        Write-Color "Yellow" "Используйте: .\run.ps1 help"
    }
}