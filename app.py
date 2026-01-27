"""
SQL Injection Protector AI Agent - Главное приложение
Полноценный AI агент для предотвращения SQL инъекций
"""

import uvicorn
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from datetime import datetime
import structlog

# Импорт наших модулей
from sql_injection_detector import SQLInjectionAgent, DetectionResult, train_initial_model
from fastapi_middleware import SQLInjectionMiddleware
from safe_database_layer import SafeAsyncPostgresRepository

# ============================================================================
# НАСТРОЙКА ЛОГИРОВАНИЯ
# ============================================================================

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)

logger = structlog.get_logger()

# ============================================================================
# PYDANTIC МОДЕЛИ
# ============================================================================

class AnalyzeRequest(BaseModel):
    """Запрос на анализ текста"""
    text: str
    source: Optional[str] = "api"

class AnalyzeResponse(BaseModel):
    """Ответ анализа"""
    is_malicious: bool
    confidence: float
    detection_method: str
    matched_patterns: List[str]
    risk_score: float
    timestamp: str
    sanitized_value: Optional[str] = None

class TrainRequest(BaseModel):
    """Запрос на обучение модели"""
    malicious_samples: List[str]
    safe_samples: List[str]

class StatsResponse(BaseModel):
    """Статистика работы агента"""
    total_requests: int
    blocked_requests: int
    suspicious_requests: int
    block_rate: float
    uptime_seconds: float

# ============================================================================
# ГЛОБАЛЬНЫЙ АГЕНТ
# ============================================================================

agent: Optional[SQLInjectionAgent] = None
start_time: datetime = None

# ============================================================================
# LIFECYCLE MANAGEMENT
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Управление жизненным циклом приложения"""
    global agent, start_time

    logger.info("Starting SQL Injection Protector AI Agent...")
    start_time = datetime.now()

    # Инициализация агента
    try:
        # Попытка загрузить существующую модель
        agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")
        logger.info("Loaded existing ML model")
    except:
        # Если модели нет, обучаем новую
        logger.info("Training new ML model...")
        train_initial_model("sql_injection_model.pkl")
        agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")
        logger.info("ML model trained and loaded successfully")

    logger.info("SQL Injection Protector AI Agent started successfully")

    yield

    logger.info("Shutting down SQL Injection Protector AI Agent...")

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="SQL Injection Protector AI Agent",
    description="Полноценный AI агент для обнаружения и предотвращения SQL инъекций",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQL Injection Protection Middleware
sql_middleware = None

@app.on_event("startup")
async def setup_middleware():
    """Настройка middleware после инициализации агента"""
    global sql_middleware
    if agent:
        sql_middleware = SQLInjectionMiddleware(
            app=app,
            agent=agent,
            enabled=True,
            block_on_detection=True,
            check_query_params=True,
            check_body=True,
            check_headers=True,
            whitelist_paths=['/health', '/metrics', '/docs', '/openapi.json', '/api/analyze', '/api/train'],
        )
        app.add_middleware(
            SQLInjectionMiddleware,
            agent=agent,
            enabled=True,
            block_on_detection=True,
            whitelist_paths=['/health', '/metrics', '/docs', '/openapi.json', '/api/analyze', '/api/train'],
        )
        logger.info("SQL Injection middleware activated")

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Корневой endpoint"""
    return {
        "name": "SQL Injection Protector AI Agent",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "agent_status": "active" if agent else "not initialized"
    }

@app.get("/metrics", response_model=StatsResponse)
async def get_metrics():
    """Получение метрик работы агента"""
    if not sql_middleware:
        raise HTTPException(status_code=503, detail="Middleware not initialized")

    stats = sql_middleware.get_stats()
    uptime = (datetime.now() - start_time).total_seconds()

    return StatsResponse(
        total_requests=stats['total_requests'],
        blocked_requests=stats['blocked_requests'],
        suspicious_requests=stats['suspicious_requests'],
        block_rate=stats['block_rate'],
        uptime_seconds=uptime
    )

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_text(request: AnalyzeRequest):
    """
    Анализ текста на наличие SQL инъекций

    Пример использования:
    ```json
    {
        "text": "' OR '1'='1",
        "source": "user_input"
    }
    ```
    """
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    try:
        result = agent.analyze(request.text)

        logger.info(
            "analyze_request",
            text_length=len(request.text),
            is_malicious=result.is_malicious,
            confidence=result.confidence,
            source=request.source
        )

        return AnalyzeResponse(
            is_malicious=result.is_malicious,
            confidence=result.confidence,
            detection_method=result.detection_method,
            matched_patterns=result.matched_patterns,
            risk_score=result.risk_score,
            timestamp=result.timestamp,
            sanitized_value=result.sanitized_value
        )

    except Exception as e:
        logger.error("analyze_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/train")
async def train_model(request: TrainRequest):
    """
    Дообучение ML модели на новых данных

    Пример использования:
    ```json
    {
        "malicious_samples": ["' OR '1'='1", "admin' --"],
        "safe_samples": ["john.doe@example.com", "Product123"]
    }
    ```
    """
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    try:
        # Подготовка данных для обучения
        training_data = request.malicious_samples + request.safe_samples
        labels = [1] * len(request.malicious_samples) + [0] * len(request.safe_samples)

        # Обучение модели
        agent.ml_detector.train(training_data, labels)
        agent.ml_detector.save_model("sql_injection_model.pkl")

        logger.info(
            "model_trained",
            malicious_count=len(request.malicious_samples),
            safe_count=len(request.safe_samples)
        )

        return {
            "status": "success",
            "message": f"Model trained on {len(training_data)} samples",
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error("train_error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/status")
async def get_status():
    """Подробный статус агента"""
    return {
        "agent": {
            "initialized": agent is not None,
            "ml_model_trained": agent.ml_detector.is_trained if agent else False,
            "detection_threshold": agent.DETECTION_THRESHOLD if agent else None,
            "risk_threshold": agent.RISK_THRESHOLD if agent else None
        },
        "middleware": {
            "active": sql_middleware is not None,
            "stats": sql_middleware.get_stats() if sql_middleware else None
        },
        "uptime_seconds": (datetime.now() - start_time).total_seconds(),
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================================================
# DEMO ENDPOINTS (для демонстрации работы)
# ============================================================================

@app.get("/demo/users/{user_id}")
async def demo_get_user(user_id: str, search: Optional[str] = None):
    """
    Демо endpoint - параметры будут проверены middleware
    Попробуйте: /demo/users/1?search=' OR '1'='1
    """
    return {
        "user_id": user_id,
        "search": search,
        "message": "This request was analyzed by SQL injection protection middleware"
    }

@app.post("/demo/search")
async def demo_search(data: Dict[str, Any]):
    """
    Демо endpoint - тело запроса будет проверено middleware
    Попробуйте: {"query": "' OR '1'='1"}
    """
    return {
        "query": data,
        "message": "This request was analyzed by SQL injection protection middleware"
    }

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Обработчик HTTP ошибок"""
    logger.error(
        "http_error",
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url.path)
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Обработчик общих ошибок"""
    logger.error(
        "unexpected_error",
        error=str(exc),
        error_type=type(exc).__name__,
        path=request.url.path
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url.path)
        }
    )

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  SQL INJECTION PROTECTOR AI AGENT                             ║
    ║  Полноценный AI агент для защиты от SQL инъекций              ║
    ╚═══════════════════════════════════════════════════════════════╝

    🚀 Запуск сервера...
    📊 Документация API: http://localhost:8080/docs
    🔍 Health Check: http://localhost:8080/health
    📈 Метрики: http://localhost:8080/metrics

    """)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        log_level="info",
        access_log=True
    )
