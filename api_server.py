"""
SQL Injection Protection API Server (FastAPI)
==============================================
Production-grade REST API with authentication, rate limiting, CORS, and OpenAPI docs.

Endpoints:
    POST /api/check         - Check single text for SQL injection
    POST /api/validate      - Validate entire form (multi-field)
    GET  /api/health        - Health check and model status
    GET  /api/stats         - Incident statistics
    GET  /api/incidents     - Query logged incidents (paginated)
    POST /api/incident/{id}/feedback - Submit false positive/negative feedback
    GET  /api/export        - SIEM export (JSON, CSV, CEF)

Usage:
    uvicorn api_server:app --host 0.0.0.0 --port 5000

    curl -X POST http://localhost:5000/api/check \\
         -H "Content-Type: application/json" \\
         -d '{"text": "admin\\'--"}'
"""

import time
import html as html_module
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, HTMLResponse
from pydantic import BaseModel, Field

from sql_injection_detector import SQLInjectionEnsemble, ExplainabilityModule
from incident_logger import IncidentLogger
from config import get_config
from logger import get_logger, setup_logging

# ═══ Configuration ═══
cfg = get_config()
setup_logging(level=cfg.logging.level, format=cfg.logging.format)
log = get_logger("api_server")

# ═══ FastAPI App ═══
app = FastAPI(
    title="SQL Injection Protector API",
    description="Production-grade SQL injection detection with ML ensemble + semantic validation.",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(cfg.api.cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══ Global State ═══
detector: Optional[SQLInjectionEnsemble] = None
logger: Optional[IncidentLogger] = None

# Rate limiting (simple in-memory)
_rate_limit_store: Dict[str, list] = {}


@app.on_event("startup")
async def startup():
    """Initialize detector and logger on startup."""
    global detector, logger
    log.info("server_starting", port=cfg.api.port)

    detector = SQLInjectionEnsemble()
    logger = IncidentLogger(db_path=cfg.incidents.db_path)

    log.info("server_ready",
             rf=detector.rf_loaded,
             cnn=detector.cnn_loaded,
             bilstm=detector.bilstm_loaded,
             db=cfg.incidents.db_path)


# ═══ Dependencies ═══

def get_client_ip(request: Request) -> str:
    """Extract client IP from request headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def check_rate_limit(request: Request) -> None:
    """Simple in-memory rate limiter."""
    if cfg.api.rate_limit_per_minute <= 0:
        return

    ip = get_client_ip(request)
    now = time.time()
    window = 60  # 1 minute

    if ip not in _rate_limit_store:
        _rate_limit_store[ip] = []

    # Clean old entries
    _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if now - t < window]

    if len(_rate_limit_store[ip]) >= cfg.api.rate_limit_per_minute:
        log.warning("rate_limit_exceeded", ip=ip)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    _rate_limit_store[ip].append(now)


def check_api_key(request: Request) -> None:
    """Optional API key authentication."""
    if not cfg.api.api_key:
        return  # No API key configured, allow all

    key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    if key != cfg.api.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ═══ Request / Response Models ═══

class CheckRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="Text to analyze")
    field_name: Optional[str] = Field(None, description="Field name for logging context")


class ValidateRequest(BaseModel):
    fields: Dict[str, str] = Field(..., description="Form fields to validate")


class FeedbackRequest(BaseModel):
    is_false_positive: bool = Field(..., description="True if the detection was a false positive")
    notes: Optional[str] = Field(None, description="Reviewer notes")


class CheckResponse(BaseModel):
    input: str
    decision: str
    action: str
    blocked: bool
    confidence: str
    severity: str
    attack_type: str
    scores: Dict[str, float]
    reason: str
    rule: str
    processing_time_ms: float
    incident_id: Optional[int] = None
    explanation: Optional[Dict] = None
    siem_fields: Optional[Dict] = None


# ═══ Endpoints ═══

@app.get("/api/health", tags=["System"])
async def health():
    """Health check endpoint with model status."""
    return {
        "status": "ok",
        "version": "3.0.0",
        "models": {
            "rf": detector.rf_loaded if detector else False,
            "cnn": detector.cnn_loaded if detector else False,
            "bilstm": detector.bilstm_loaded if detector else False,
        },
        "incidents_logged": logger.get_incident_count() if logger else 0,
        "config": {
            "rate_limit_per_minute": cfg.api.rate_limit_per_minute,
            "max_input_length": cfg.normalization.max_input_length,
            "auth_enabled": cfg.api.api_key is not None,
        },
    }


@app.post("/api/check", response_model=CheckResponse, tags=["Detection"],
          dependencies=[Depends(check_rate_limit), Depends(check_api_key)])
async def check_single(req: CheckRequest, request: Request):
    """
    Check single text for SQL injection.

    Returns detection result with decision, severity, attack type, and explanation.
    """
    client_ip = get_client_ip(request)
    start = time.time()

    result = detector.detect(
        req.text,
        source_ip=client_ip,
        endpoint=str(request.url.path),
        field_name=req.field_name,
        http_method=request.method,
    )

    elapsed = (time.time() - start) * 1000

    # Log incident
    should_log = result['action'] in ('BLOCK', 'ALERT', 'CHALLENGE') or cfg.api.log_all_requests
    incident_id = None

    if should_log and logger:
        incident_id = logger.log_incident(
            input_text=req.text,
            result=result,
            source_ip=client_ip,
            user_agent=request.headers.get("User-Agent"),
            endpoint=str(request.url.path),
            field_name=req.field_name,
            metadata={
                "processing_time_ms": round(elapsed, 2),
                "attack_type": result.get("attack_type"),
                "severity": result.get("severity"),
            },
        )

    response = CheckResponse(
        input=req.text,
        decision=result["decision"],
        action=result["action"],
        blocked=result["action"] in ("BLOCK", "ALERT"),
        confidence=result["confidence_level"],
        severity=result.get("severity", "INFO"),
        attack_type=result.get("attack_type", "NONE"),
        scores={
            "ensemble": round(result["score"], 4),
            "rf": round(result["P_rf"], 4),
            "cnn": round(result["P_cnn"], 4),
            "bilstm": round(result.get("P_bilstm", 0.0), 4),
            "semantic": result["semantic_score"],
        },
        reason=result["reason"],
        rule=result.get("rule", ""),
        processing_time_ms=round(elapsed, 2),
        incident_id=incident_id,
        explanation=result.get("explanation"),
        siem_fields=result.get("siem_fields"),
    )

    log.info("api_check",
             decision=result["decision"],
             action=result["action"],
             ip=client_ip,
             time_ms=round(elapsed, 2))

    return response


@app.post("/api/validate", tags=["Detection"],
          dependencies=[Depends(check_rate_limit), Depends(check_api_key)])
async def validate_form(req: ValidateRequest, request: Request):
    """
    Validate entire form for SQL injection.

    Checks all fields and returns per-field results.
    """
    client_ip = get_client_ip(request)
    start = time.time()

    results = {}
    blocked_fields = []
    incident_ids = []

    for fname, fvalue in req.fields.items():
        if isinstance(fvalue, str) and len(fvalue) > 0:
            result = detector.detect(
                fvalue,
                source_ip=client_ip,
                endpoint=str(request.url.path),
                field_name=fname,
                http_method=request.method,
            )
            results[fname] = {
                "decision": result["decision"],
                "action": result["action"],
                "score": round(result["score"], 4),
                "severity": result.get("severity", "INFO"),
                "attack_type": result.get("attack_type", "NONE"),
            }

            if result["action"] in ("BLOCK", "ALERT"):
                blocked_fields.append(fname)

            if result["action"] in ("BLOCK", "ALERT", "CHALLENGE") and logger:
                inc_id = logger.log_incident(
                    input_text=fvalue,
                    result=result,
                    source_ip=client_ip,
                    user_agent=request.headers.get("User-Agent"),
                    endpoint=str(request.url.path),
                    field_name=fname,
                )
                incident_ids.append(inc_id)

    elapsed = (time.time() - start) * 1000

    return {
        "safe": len(blocked_fields) == 0,
        "blocked_fields": blocked_fields,
        "results": results,
        "processing_time_ms": round(elapsed, 2),
        "incident_ids": incident_ids if incident_ids else None,
    }


@app.get("/api/stats", tags=["Analytics"],
         dependencies=[Depends(check_api_key)])
async def get_stats():
    """Get incident statistics."""
    if not logger:
        raise HTTPException(status_code=503, detail="Logger not initialized")
    return logger.get_statistics()


@app.get("/api/incidents", tags=["Analytics"],
         dependencies=[Depends(check_api_key)])
async def get_incidents(
    limit: int = 50,
    offset: int = 0,
    decision: Optional[str] = None,
    action: Optional[str] = None,
    severity: Optional[str] = None,
):
    """Query incident history with filters and pagination."""
    if not logger:
        raise HTTPException(status_code=503, detail="Logger not initialized")

    limit = min(limit, 500)
    incidents = logger.get_incidents(
        limit=limit,
        offset=offset,
        decision=decision,
        action=action,
        severity=severity,
    )

    return {
        "incidents": incidents,
        "count": len(incidents),
        "limit": limit,
        "offset": offset,
    }


@app.post("/api/incident/{incident_id}/feedback", tags=["Active Learning"],
          dependencies=[Depends(check_api_key)])
async def submit_feedback(incident_id: int, req: FeedbackRequest):
    """Submit feedback for active learning."""
    if not logger:
        raise HTTPException(status_code=503, detail="Logger not initialized")

    logger.mark_false_positive(
        incident_id=incident_id,
        is_false_positive=req.is_false_positive,
        reviewer_notes=req.notes,
    )

    log.info("feedback_submitted",
             incident_id=incident_id,
             is_fp=req.is_false_positive)

    return {"status": "ok", "incident_id": incident_id}


@app.get("/api/export", tags=["SIEM Integration"],
         dependencies=[Depends(check_api_key)])
async def export_incidents(
    format: str = "json",
    severity_min: str = "LOW",
):
    """Export incidents for SIEM integration (JSON, CSV, CEF)."""
    if not logger:
        raise HTTPException(status_code=503, detail="Logger not initialized")

    export_data = logger.export_to_siem(format=format, severity_min=severity_min)

    content_types = {
        "json": "application/json",
        "csv": "text/csv",
        "cef": "text/plain",
    }

    return Response(
        content=export_data,
        media_type=content_types.get(format, "application/json"),
        headers={"Content-Disposition": f"attachment; filename=incidents.{format}"},
    )


@app.get("/api/demo", response_class=HTMLResponse, tags=["Demo"])
async def demo():
    """Interactive demo page."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SQL Injection Detector v3.0 - Demo</title>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 960px; margin: 50px auto; padding: 20px; background: #f8f9fa; }
            h1 { color: #1a1a2e; }
            .input-group { display: flex; gap: 10px; margin: 20px 0; }
            input { flex: 1; padding: 12px; font-size: 16px; border: 2px solid #dee2e6; border-radius: 8px; }
            button { padding: 12px 24px; font-size: 16px; border: none; border-radius: 8px; cursor: pointer; background: #0d6efd; color: white; }
            button:hover { background: #0a58ca; }
            .result { margin-top: 20px; padding: 20px; border-radius: 12px; }
            .safe { background: #d4edda; border: 2px solid #28a745; }
            .blocked { background: #f8d7da; border: 2px solid #dc3545; }
            .invalid { background: #e2e3e5; border: 2px solid #6c757d; }
            .suspicious { background: #fff3cd; border: 2px solid #ffc107; }
            .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }
            .badge-severity { background: #6c757d; }
            .badge-attack { background: #0d6efd; }
            .quick-tests { display: flex; flex-wrap: wrap; gap: 8px; margin: 20px 0; }
            .quick-tests button { font-size: 13px; padding: 8px 16px; background: #6c757d; }
            .quick-tests button:hover { background: #5a6268; }
        </style>
    </head>
    <body>
        <h1>SQL Injection Detection Agent v3.0</h1>
        <p>Multi-layer ensemble: RF + CNN + BiLSTM + Semantic Validation | Attack Typing | Severity | Explainability</p>

        <div class="input-group">
            <input type="text" id="input" placeholder="Enter text to check for SQL injection...">
            <button onclick="checkInput()">Analyze</button>
        </div>

        <div class="quick-tests">
            <button onclick="test('john_doe')">Safe: john_doe</button>
            <button onclick="test(`O'Brien`)">Safe: O'Brien</button>
            <button onclick="test(`Please select an option`)">Safe: select word</button>
            <button onclick="test(`' OR '1'='1`)">SQLi: OR tautology</button>
            <button onclick="test(`admin'--`)">SQLi: comment</button>
            <button onclick="test(`' UNION SELECT password FROM users--`)">SQLi: UNION</button>
            <button onclick="test(`'; DROP TABLE users--`)">SQLi: DROP TABLE</button>
            <button onclick="test(`'1'1'1=1'1'1'1`)">Invalid: garbage</button>
        </div>

        <div id="result"></div>

        <script>
            async function checkInput() {
                const text = document.getElementById('input').value;
                await test(text);
            }

            async function test(text) {
                document.getElementById('input').value = text;
                const response = await fetch('/api/check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({text: text})
                });
                const data = await response.json();

                let cssClass = 'safe';
                if (data.blocked) cssClass = 'blocked';
                else if (data.decision === 'INVALID') cssClass = 'invalid';
                else if (data.decision === 'SUSPICIOUS') cssClass = 'suspicious';

                const safeInput = escapeHtml(data.input);
                const safeReason = escapeHtml(data.reason);

                document.getElementById('result').innerHTML =
                    '<div class="result ' + cssClass + '">' +
                    '<h2>' + data.decision + ' — ' + data.action + '</h2>' +
                    '<p><b>Input:</b> <code>' + safeInput + '</code></p>' +
                    '<p><span class="badge badge-severity">Severity: ' + data.severity + '</span> ' +
                    '<span class="badge badge-attack">Attack: ' + data.attack_type + '</span></p>' +
                    '<p><b>Scores:</b> Ensemble=' + data.scores.ensemble +
                    ', RF=' + data.scores.rf +
                    ', CNN=' + data.scores.cnn +
                    ', BiLSTM=' + data.scores.bilstm +
                    ', Semantic=' + data.scores.semantic + '</p>' +
                    '<p><b>Rule:</b> ' + data.rule + '</p>' +
                    '<p><b>Reason:</b> ' + safeReason + '</p>' +
                    '<p><b>Time:</b> ' + data.processing_time_ms + 'ms</p>' +
                    (data.incident_id ? '<p><b>Incident ID:</b> ' + data.incident_id + '</p>' : '') +
                    '</div>';
            }

            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }
        </script>
    </body>
    </html>
    """


# ═══ Run ═══

if __name__ == "__main__":
    import uvicorn

    print("\n" + "=" * 60)
    print("SQL Injection Protection API Server v3.0")
    print("=" * 60)
    print(f"\nDocs:     http://localhost:{cfg.api.port}/docs")
    print(f"Demo:     http://localhost:{cfg.api.port}/api/demo")
    print(f"Health:   http://localhost:{cfg.api.port}/api/health")
    print("=" * 60 + "\n")

    uvicorn.run(app, host=cfg.api.host, port=cfg.api.port)
