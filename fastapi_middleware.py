"""
FastAPI Middleware для защиты от SQL-инъекций
Runtime-интеграция с SQLInjectionAgent
"""

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import FormData
import json
import asyncio
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime
import time

# Импорт детектора (предполагается, что код из первого артефакта находится в sql_injection_agent.py)
# from sql_injection_agent import SQLInjectionAgent, DetectionResult

logger = logging.getLogger("SQLInjectionMiddleware")


class SQLInjectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware для перехвата и анализа всех входящих запросов
    """
    
    def __init__(
        self,
        app,
        agent,  # SQLInjectionAgent instance
        enabled: bool = True,
        block_on_detection: bool = True,
        check_query_params: bool = True,
        check_body: bool = True,
        check_headers: bool = True,
        whitelist_paths: Optional[List[str]] = None,
        alert_webhook: Optional[str] = None,
        max_request_size: int = 1024 * 1024  # 1MB
    ):
        super().__init__(app)
        self.agent = agent
        self.enabled = enabled
        self.block_on_detection = block_on_detection
        self.check_query_params = check_query_params
        self.check_body = check_body
        self.check_headers = check_headers
        self.whitelist_paths = whitelist_paths or []
        self.alert_webhook = alert_webhook
        self.max_request_size = max_request_size
        
        # Метрики
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'suspicious_requests': 0,
            'false_positives': 0
        }
    
    async def dispatch(self, request: Request, call_next):
        """Основной обработчик запросов"""
        
        if not self.enabled:
            return await call_next(request)
        
        # Whitelist: пропускаем без проверки
        if self._is_whitelisted(request.path):
            return await call_next(request)
        
        self.stats['total_requests'] += 1
        start_time = time.time()
        
        # Анализ запроса
        try:
            detection_results = await self._analyze_request(request)
            
            # Проверка на вредоносность
            malicious_results = [r for r in detection_results if r.is_malicious]
            
            if malicious_results:
                self.stats['blocked_requests'] += 1
                
                # Логирование и алерты
                await self._handle_malicious_request(
                    request,
                    malicious_results,
                    time.time() - start_time
                )
                
                # Блокировка или предупреждение
                if self.block_on_detection:
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "Forbidden",
                            "message": "Potential SQL injection detected",
                            "request_id": self._generate_request_id(request),
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    )
                else:
                    # Пропускаем, но логируем
                    self.stats['suspicious_requests'] += 1
            
            # Пропускаем запрос дальше
            response = await call_next(request)
            
            # Добавляем security headers
            response.headers["X-SQL-Injection-Check"] = "passed"
            response.headers["X-Request-ID"] = self._generate_request_id(request)
            
            return response
        
        except Exception as e:
            logger.error(f"Error in SQL injection middleware: {e}", exc_info=True)
            # В случае ошибки пропускаем запрос (fail-open для доступности)
            return await call_next(request)
    
    async def _analyze_request(self, request: Request) -> List:
        """Анализ всех компонентов запроса"""
        results = []
        
        # 1. Query параметры
        if self.check_query_params:
            for key, value in request.query_params.items():
                result = self.agent.analyze(str(value))
                result.source = f"query_param:{key}"
                results.append(result)
        
        # 2. Path параметры (извлечение из URL)
        path_parts = request.url.path.split('/')
        for i, part in enumerate(path_parts):
            if part and not part.isalpha():  # Проверяем только динамические части
                result = self.agent.analyze(part)
                result.source = f"path_param:{i}"
                results.append(result)
        
        # 3. Headers (выборочно)
        if self.check_headers:
            suspicious_headers = ['user-agent', 'referer', 'x-forwarded-for']
            for header in suspicious_headers:
                if header in request.headers:
                    result = self.agent.analyze(request.headers[header])
                    result.source = f"header:{header}"
                    results.append(result)
        
        # 4. Body (JSON, form-data)
        if self.check_body and request.method in ['POST', 'PUT', 'PATCH']:
            body_data = await self._extract_body(request)
            if body_data:
                for key, value in self._flatten_dict(body_data).items():
                    if isinstance(value, str):
                        result = self.agent.analyze(value)
                        result.source = f"body:{key}"
                        results.append(result)
        
        return results
    
    async def _extract_body(self, request: Request) -> Optional[Dict]:
        """Извлечение данных из body"""
        try:
            content_type = request.headers.get('content-type', '')
            
            # JSON
            if 'application/json' in content_type:
                body = await request.body()
                if len(body) > self.max_request_size:
                    logger.warning("Request body too large, skipping")
                    return None
                return json.loads(body)
            
            # Form data
            elif 'application/x-www-form-urlencoded' in content_type or 'multipart/form-data' in content_type:
                form = await request.form()
                return {key: value for key, value in form.items()}
            
            return None
        
        except Exception as e:
            logger.error(f"Error extracting body: {e}")
            return None
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
        """Рекурсивное извлечение всех значений из вложенных структур"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.extend(self._flatten_dict(item, f"{new_key}[{i}]", sep=sep).items())
                    else:
                        items.append((f"{new_key}[{i}]", str(item)))
            else:
                items.append((new_key, str(v)))
        return dict(items)
    
    def _is_whitelisted(self, path: str) -> bool:
        """Проверка whitelist путей"""
        return any(path.startswith(wp) for wp in self.whitelist_paths)
    
    def _generate_request_id(self, request: Request) -> str:
        """Генерация уникального ID запроса"""
        return f"{int(time.time())}-{hash(request.url.path)}"
    
    async def _handle_malicious_request(
        self,
        request: Request,
        results: List,
        processing_time: float
    ):
        """Обработка обнаруженного вредоносного запроса"""
        
        # Формирование события для SIEM
        siem_event = {
            "event_type": "sql_injection_blocked",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "critical",
            "request_id": self._generate_request_id(request),
            "client_ip": request.client.host if request.client else "unknown",
            "method": request.method,
            "path": request.url.path,
            "user_agent": request.headers.get('user-agent', 'unknown'),
            "detections": [
                {
                    "source": r.source,
                    "confidence": r.confidence,
                    "risk_score": r.risk_score,
                    "detection_method": r.detection_method,
                    "matched_patterns": r.matched_patterns
                }
                for r in results
            ],
            "processing_time_ms": processing_time * 1000,
            "action": "blocked" if self.block_on_detection else "logged"
        }
        
        # Логирование в структурированном формате
        logger.critical(f"SQL_INJECTION_DETECTED: {json.dumps(siem_event, indent=2)}")
        
        # Отправка webhook алерта (опционально)
        if self.alert_webhook:
            await self._send_alert_webhook(siem_event)
    
    async def _send_alert_webhook(self, event: Dict):
        """Отправка алерта на webhook (Slack, Teams, etc.)"""
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                await client.post(
                    self.alert_webhook,
                    json=event,
                    timeout=5.0
                )
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
    
    def get_stats(self) -> Dict:
        """Получение статистики работы middleware"""
        return {
            **self.stats,
            'block_rate': self.stats['blocked_requests'] / max(self.stats['total_requests'], 1),
            'suspicious_rate': self.stats['suspicious_requests'] / max(self.stats['total_requests'], 1)
        }


# ============================================================================
# FASTAPI APPLICATION С MIDDLEWARE
# ============================================================================

def create_protected_app() -> FastAPI:
    """Создание FastAPI приложения с защитой от SQL-инъекций"""
    
    app = FastAPI(
        title="SQL Injection Protected API",
        description="API с интегрированной защитой от SQL-инъекций",
        version="1.0.0"
    )
    
    # Инициализация агента
    # agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")
    
    # Добавление middleware
    # app.add_middleware(
    #     SQLInjectionMiddleware,
    #     agent=agent,
    #     enabled=True,
    #     block_on_detection=True,
    #     whitelist_paths=['/health', '/metrics', '/docs', '/openapi.json'],
    #     alert_webhook="https://hooks.slack.com/your-webhook-url"
    # )
    
    # Health check endpoint
    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}
    
    # Metrics endpoint
    @app.get("/metrics")
    async def get_metrics(request: Request):
        # middleware = next(m for m in app.user_middleware if isinstance(m[0], SQLInjectionMiddleware))
        # return middleware.get_stats()
        return {"message": "Metrics endpoint"}
    
    # Пример защищенного endpoint
    @app.get("/users/{user_id}")
    async def get_user(user_id: str, search: Optional[str] = None):
        """
        Endpoint с параметрами, которые будут проверены middleware
        """
        return {
            "user_id": user_id,
            "search": search,
            "message": "User data retrieved successfully"
        }
    
    @app.post("/users/search")
    async def search_users(request: Dict[str, Any]):
        """
        Endpoint с JSON body, который будет проверен middleware
        """
        return {
            "results": [],
            "query": request,
            "message": "Search completed"
        }
    
    return app


# ============================================================================
# ПРИМЕР ЗАПУСКА
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Создание приложения
    app = create_protected_app()
    
    # Комментарий: в реальном использовании раскомментируйте инициализацию агента и middleware
    """
    from sql_injection_agent import SQLInjectionAgent
    
    agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")
    
    app.add_middleware(
        SQLInjectionMiddleware,
        agent=agent,
        enabled=True,
        block_on_detection=True,
        whitelist_paths=['/health', '/metrics', '/docs', '/openapi.json'],
    )
    """
    
    # Запуск сервера
    print("Starting server with SQL Injection Protection...")
    print("Docs available at: http://localhost:8000/docs")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
