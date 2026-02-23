"""
SQL Injection Protection API Server (FastAPI)
==============================================
Production-grade REST API with AI agent, authentication, rate limiting, CORS, and OpenAPI docs.

Endpoints:
    POST /api/check                   - Check single text for SQL injection (via AI agent)
    POST /api/validate                - Validate entire form (multi-field)
    GET  /api/health                  - Health check and model status
    GET  /api/stats                   - Incident statistics
    GET  /api/incidents               - Query logged incidents (paginated)
    POST /api/incident/{id}/feedback  - Submit false positive/negative feedback
    GET  /api/export                  - SIEM export (JSON, CSV, CEF)
    GET  /api/agent/stats             - AI agent statistics (escalations, bans, learning)
    GET  /api/agent/ip/{ip}           - IP reputation profile
    GET  /api/agent/metrics           - Agent metrics summary
    POST /api/agent/feedback          - Analyst feedback → online learning

Usage:
    uvicorn api_server:app --host 0.0.0.0 --port 5000

    curl -X POST http://localhost:5000/api/check \\
         -H "Content-Type: application/json" \\
         -d '{"text": "admin\\'--"}'
    curl http://localhost:5000/api/agent/ip/192.168.1.100
    curl http://localhost:5000/api/agent/metrics
"""

import asyncio
import atexit
import ipaddress
import os
import signal
import time
import traceback
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

from agent import AgentConfig, AgentStore, SQLiAgent, agent_cleanup_loop
from config import get_config
from incident_logger import IncidentLogger
from logger import get_logger, setup_logging
from metrics import metrics
from sql_injection_detector import SQLInjectionEnsemble

# ═══ Configuration ═══
cfg = get_config()
setup_logging(level=cfg.logging.level, format=cfg.logging.format)
log = get_logger("api_server")

# ═══ Constants ═══
VERSION = "3.4.0"
INFERENCE_TIMEOUT_SECONDS = 10  # Max time for a single detection call
MAX_FIELDS = 50                 # Max fields per /api/validate request
MAX_TEXT_LENGTH = 10_000        # Max characters per text input (DoS mitigation)
MAX_FIELD_KEY_LENGTH = 256      # Max length of a field name key in /api/validate

# Thread pool for CPU-bound inference (prevents blocking async event loop)
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="sqli-inference")

# ═══ Global State ═══
detector: SQLInjectionEnsemble | None = None
agent: SQLiAgent | None = None
logger: IncidentLogger | None = None

# Rate limiting (sliding window with deque for O(1) append/popleft)
_rate_limit_store: dict[str, deque] = {}
_rate_limit_last_cleanup: float = 0.0

# ── Emergency shutdown flush ────────────────────────────────────────────
# Called by atexit (process exit) and SIGTERM handler.
# Ensures SGD weights and IP profiles are persisted even when:
#   - uvicorn receives SIGKILL (OOM killer) → atexit NOT called
#   - SIGTERM (systemd stop / docker stop) → atexit IS called
#   - Unhandled exception that exits the process → atexit IS called
#
# Note: atexit functions run in LIFO order, in the same thread that called
#       sys.exit().  Keep this function fast and exception-safe.

def _emergency_flush() -> None:
    """
    Best-effort flush of agent state on unexpected process exit.
    Idempotent — safe to call multiple times.
    """
    global agent
    if agent is None:
        return
    if agent.store is None:
        return
    try:
        saved = agent.store.flush(
            agent,
            min_attacks=agent.config.persist_min_attacks,
            save_sgd=True,
        )
        # Avoid using structured logger here — it may already be torn down
        print(
            f"[api_server] emergency_flush: {saved} profiles saved, "
            f"sgd={'saved' if agent.online_learner._is_fitted else 'not fitted'}",
            flush=True,
        )
    except Exception as exc:
        print(f"[api_server] emergency_flush FAILED: {exc}", flush=True)


def _register_shutdown_hooks() -> None:
    """
    Register atexit and SIGTERM handlers for emergency flush.

    Why both?
    - atexit: covers normal exit, unhandled exceptions, sys.exit()
    - SIGTERM: covers systemd/docker graceful stop (before atexit fires)

    SIGKILL cannot be caught — nothing survives it.  The periodic flush
    in agent_cleanup_loop (every 300s) limits data loss to ≤5 minutes.
    """
    atexit.register(_emergency_flush)

    # Install SIGTERM handler only on non-Windows (uvicorn manages signals on Win)
    if os.name != "nt":
        def _sigterm_handler(signum, frame):  # noqa: ARG001
            _emergency_flush()
            # Re-raise default SIGTERM so the process actually exits
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            os.kill(os.getpid(), signal.SIGTERM)

        signal.signal(signal.SIGTERM, _sigterm_handler)


# ═══ Lifespan (startup + shutdown) ═══

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize on startup, cleanup on shutdown."""
    # ── Startup ──
    global detector, agent, logger
    log.info("server_starting", port=cfg.api.port)

    detector = SQLInjectionEnsemble()

    # AgentStore: SQLite persistence for IP bans + reputation across restarts
    agent_db_path = os.environ.get("AGENT_DB_PATH", "agent_state.db")
    store = AgentStore(db_path=agent_db_path)
    agent = SQLiAgent(detector, store=store)

    # Register atexit + SIGTERM emergency flush (must be done after agent is created)
    _register_shutdown_hooks()

    # Restore persisted bans, reputation, and SGD model from previous run
    loaded_profiles = store.load_into(agent, load_sgd=True)
    if loaded_profiles:
        log.info("agent_state_loaded", profiles=loaded_profiles, db=agent_db_path)
        try:
            metrics.agent_persistence_loads.inc()
        except Exception:
            pass
    if agent.online_learner._is_fitted:
        log.info("agent_sgd_restored",
                 path=agent.config.sgd_model_path,
                 msg="SGD online layer restored from disk — no retraining needed")

    logger = IncidentLogger(db_path=cfg.incidents.db_path)

    if not cfg.api.api_key:
        log.warning("api_key_not_set",
                     msg="No API_KEY configured — all endpoints are publicly accessible. "
                         "Set API_KEY env var for production.")

    # Set Prometheus gauges
    metrics.model_loaded.labels(model="rf").set(1 if detector.rf_loaded else 0)
    metrics.model_loaded.labels(model="cnn").set(1 if detector.cnn_loaded else 0)
    metrics.app_info.info({
        "version": VERSION,
        "rf_loaded": str(detector.rf_loaded),
        "cnn_loaded": str(detector.cnn_loaded),
    })

    log.info("server_ready",
             version=VERSION,
             rf=detector.rf_loaded,
             cnn=detector.cnn_loaded,
             db=cfg.incidents.db_path)

    # Start agent memory cleanup background task (every 5 minutes)
    cleanup_task = asyncio.create_task(agent_cleanup_loop(agent, interval_seconds=300))

    yield  # ── App is running ──

    # ── Shutdown ──
    cleanup_task.cancel()
    log.info("server_shutting_down")

    # Final persistence flush before shutdown (save all active bans + reputation + SGD)
    if agent is not None and agent.store is not None:
        try:
            saved = agent.store.flush(
                agent,
                min_attacks=agent.config.persist_min_attacks,
                save_sgd=True,  # ← persist fitted SGD weights across restarts
            )
            sgd_saved = agent.online_learner._is_fitted
            log.info("agent_state_flushed_on_shutdown",
                     profiles_saved=saved,
                     sgd_saved=sgd_saved,
                     sgd_path=agent.config.sgd_model_path if sgd_saved else None)
            try:
                metrics.agent_persistence_saves.inc()
            except Exception:
                pass
        except Exception as e:
            log.error("agent_state_flush_failed", error=str(e))

    _executor.shutdown(wait=True, cancel_futures=False)
    log.info("server_stopped")


# ═══ FastAPI App ═══
app = FastAPI(
    title="SQL Injection Protector API",
    description="Production-grade SQL injection detection with ML ensemble + semantic validation.",
    version=VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(cfg.api.cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══ Security Headers Middleware ═══

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses (OWASP recommendations)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    # CSP only on HTML pages (demo), not API JSON responses
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
    return response


# ═══ Request ID Middleware ═══

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Attach a unique request ID for tracing and correlation."""
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ═══ Metrics Middleware ═══

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Track request count, duration, and active requests for Prometheus."""
    endpoint = request.url.path
    method = request.method

    # Skip metrics endpoint itself to avoid recursion
    if endpoint == "/metrics":
        return await call_next(request)

    metrics.active_requests.labels(endpoint=endpoint).inc()
    start = time.time()

    try:
        response = await call_next(request)
        duration = time.time() - start
        status = response.status_code

        metrics.requests_total.labels(endpoint=endpoint, method=method, status=status).inc()
        metrics.request_duration.labels(endpoint=endpoint, method=method).observe(duration)

        return response
    except Exception:
        duration = time.time() - start
        metrics.requests_total.labels(endpoint=endpoint, method=method, status=500).inc()
        metrics.request_duration.labels(endpoint=endpoint, method=method).observe(duration)
        metrics.errors_total.labels(error_type="unhandled").inc()
        raise
    finally:
        metrics.active_requests.labels(endpoint=endpoint).dec()


# ═══ Global Exception Handler ═══

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch all unhandled exceptions and return structured error response."""
    error_id = f"ERR-{int(time.time())}"
    request_id = getattr(request.state, "request_id", "N/A")
    log.error("unhandled_exception",
              error_id=error_id,
              request_id=request_id,
              path=str(request.url.path),
              method=request.method,
              ip=get_client_ip(request),
              error_type=type(exc).__name__,
              error=str(exc),
              traceback=traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "error_id": error_id,
            "request_id": request_id,
            "detail": "An unexpected error occurred. Contact support with the error_id.",
        },
    )


# ═══ Helpers ═══

def _sanitize_log_value(value: str, max_len: int = 200) -> str:
    """Sanitize a user-controlled value before including it in log entries.

    Strips newlines (prevents log injection / CRLF attacks) and truncates
    to avoid gigabyte-sized log lines.
    """
    if not isinstance(value, str):
        value = str(value)
    return value.replace("\n", "\\n").replace("\r", "\\r")[:max_len]


async def _run_detection(text: str, **kwargs) -> dict[str, Any]:
    """Run agent.evaluate() (or detector.detect() fallback) in thread pool with timeout."""
    loop = asyncio.get_event_loop()
    start = time.time()
    try:
        if agent is not None:
            result = await asyncio.wait_for(
                loop.run_in_executor(_executor, lambda: agent.evaluate(text, **kwargs)),
                timeout=INFERENCE_TIMEOUT_SECONDS,
            )
        else:
            result = await asyncio.wait_for(
                loop.run_in_executor(_executor, lambda: detector.detect(text, **kwargs)),
                timeout=INFERENCE_TIMEOUT_SECONDS,
            )
        # Record inference latency
        metrics.inference_duration.observe(time.time() - start)

        # Use agent decision if available, fall back to base detector decision
        decision = result.get("agent_decision") or result.get("decision", "UNKNOWN")
        action = result.get("agent_action") or result.get("action", "UNKNOWN")
        attack_type = result.get("attack_type", "NONE")
        metrics.detections_total.labels(decision=decision, action=action, attack_type=attack_type).inc()
        metrics.severity_total.labels(severity=result.get("severity", "INFO")).inc()

        if action in ("BLOCK", "ALERT"):
            metrics.blocked_total.inc()

        return result
    except TimeoutError as exc:
        metrics.inference_timeouts.inc()
        metrics.errors_total.labels(error_type="inference_timeout").inc()
        log.error("inference_timeout", text_length=len(text), timeout=INFERENCE_TIMEOUT_SECONDS)
        raise HTTPException(
            status_code=504,
            detail=f"Detection timed out after {INFERENCE_TIMEOUT_SECONDS}s"
        ) from exc


def _safe_log_incident(input_text: str, result: dict, **kwargs) -> int | None:
    """Log incident with error handling — never crash the request if DB fails."""
    try:
        if logger:
            return logger.log_incident(input_text=input_text, result=result, **kwargs)
    except Exception as e:
        log.error("incident_log_failed", error=str(e), decision=result.get("decision"))
    return None


# ═══ Dependencies ═══

def get_client_ip(request: Request) -> str:
    """Extract and validate client IP from request headers.

    Validates that the IP is a well-formed address to prevent
    header-injection attacks against the rate limiter.
    """
    raw_ip = "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        raw_ip = forwarded.split(",")[0].strip()
    elif request.client:
        raw_ip = request.client.host

    # Validate to prevent spoofed / garbage IPs from polluting rate-limit store
    try:
        ipaddress.ip_address(raw_ip)
        return raw_ip
    except ValueError:
        return "unknown"


def check_rate_limit(request: Request) -> None:
    """Sliding-window rate limiter using deque (O(1) append/trim).

    Tracks per-IP request timestamps in a deque and rejects if the window
    contains more than ``rate_limit_per_minute`` entries.  Stale IPs are
    pruned every 5 minutes to bound memory.
    """
    global _rate_limit_last_cleanup

    if cfg.api.rate_limit_per_minute <= 0:
        return

    ip = get_client_ip(request)
    now = time.time()
    window = 60  # 1 minute

    # Periodic cleanup of stale IPs (every 5 minutes)
    if now - _rate_limit_last_cleanup > 300:
        stale_ips = [
            k for k, v in _rate_limit_store.items()
            if not v or (now - v[-1]) > window
        ]
        for stale_ip in stale_ips:
            del _rate_limit_store[stale_ip]
        _rate_limit_last_cleanup = now

    if ip not in _rate_limit_store:
        _rate_limit_store[ip] = deque()

    dq = _rate_limit_store[ip]

    # Trim timestamps outside the sliding window from the left
    while dq and (now - dq[0]) >= window:
        dq.popleft()

    if len(dq) >= cfg.api.rate_limit_per_minute:
        metrics.rate_limit_exceeded.inc()
        log.warning("rate_limit_exceeded", ip=ip)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    dq.append(now)


def check_api_key(request: Request) -> None:
    """Optional API key authentication."""
    if not cfg.api.api_key:
        return  # No API key configured, allow all

    key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    if key != cfg.api.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ═══ Request / Response Models ═══

class CheckRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TEXT_LENGTH,
        description="Text to analyze for SQL injection",
    )
    field_name: str | None = Field(
        None,
        max_length=MAX_FIELD_KEY_LENGTH,
        description="Field name for logging context",
    )


class ValidateRequest(BaseModel):
    """
    Multi-field form validation request.

    Security limits:
      - max MAX_FIELDS fields per request (prevents CPU exhaustion)
      - each field value capped at MAX_TEXT_LENGTH (prevents DoS on CNN)
      - each field key capped at MAX_FIELD_KEY_LENGTH (prevents log bloat)

    Fields exceeding the value length limit are truncated server-side
    after validation — the truncation itself is reported in the response.
    """
    fields: dict[str, str] = Field(
        ...,
        description=f"Form fields to validate. Max {MAX_FIELDS} fields, "
                    f"max {MAX_TEXT_LENGTH} chars per value.",
    )


class FeedbackRequest(BaseModel):
    is_false_positive: bool = Field(..., description="True if the detection was a false positive")
    notes: str | None = Field(None, description="Reviewer notes")


class CheckResponse(BaseModel):
    input: str
    decision: str
    action: str
    blocked: bool
    confidence: str
    severity: str
    attack_type: str
    scores: dict[str, float]
    reason: str
    rule: str
    processing_time_ms: float
    incident_id: int | None = None
    explanation: dict | None = None
    siem_fields: dict | None = None
    # Agent fields (None when agent is disabled or no IP context)
    agent_decision: str | None = None
    agent_action: str | None = None
    agent_reason: str | None = None
    contributing_factors: dict | None = None   # structured explainability object
    escalated: bool | None = None
    adaptive_threshold_used: bool | None = None
    ip_profile: dict | None = None
    session_context: dict | None = None


class AgentFeedbackRequest(BaseModel):
    original_text: str = Field(..., description="The text that was incorrectly classified")
    is_false_positive: bool = Field(..., description="True if detection was a false positive")
    matched_pattern: str | None = Field(None, description="Signature pattern to suppress")


# ═══ Endpoints ═══

@app.get("/api/health", tags=["System"])
async def health():
    """Health check endpoint with model status."""
    incident_count = 0
    if logger:
        try:
            incident_count = logger.get_incident_count()
        except Exception:
            pass  # health check should never fail due to DB

    return {
        "status": "ok",
        "version": VERSION,
        "models": {
            "rf": detector.rf_loaded if detector else False,
            "cnn": detector.cnn_loaded if detector else False,
        },
        "incidents_logged": incident_count,
        "config": {
            "rate_limit_per_minute": cfg.api.rate_limit_per_minute,
            "max_input_length": cfg.normalization.max_input_length,
            "auth_enabled": cfg.api.api_key is not None,
        },
    }


@app.get("/healthz", tags=["System"], include_in_schema=False)
async def liveness():
    """
    Kubernetes liveness probe — is the process alive?

    Returns 200 if the process is running and the event loop is responsive.
    Does NOT check model state or database connectivity (those are readiness concerns).
    A failing liveness probe causes k8s to restart the pod.

    curl http://localhost:5000/healthz
    """
    return {"status": "alive"}


@app.get("/readyz", tags=["System"], include_in_schema=False)
async def readiness():
    """
    Kubernetes readiness probe — is the server ready to serve traffic?

    Returns 200 only if:
      - At least one ML model (RF or CNN) is loaded
      - The agent is initialized

    Returns 503 if the server is still starting up (models loading).
    A failing readiness probe causes k8s to stop routing traffic to this pod
    without restarting it — correct behavior during model loading.

    curl http://localhost:5000/readyz
    """
    if detector is None or agent is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "reason": "Server initializing — models not yet loaded",
            },
        )

    if not detector.rf_loaded and not detector.cnn_loaded:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "reason": "No ML models loaded — RF and CNN both unavailable",
                "rf_loaded": False,
                "cnn_loaded": False,
            },
        )

    return {
        "status": "ready",
        "rf_loaded": detector.rf_loaded,
        "cnn_loaded": detector.cnn_loaded,
        "agent_active": agent is not None,
        "tracked_ips": len(agent.ip_memory._profiles) if agent else 0,
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

    result = await _run_detection(
        req.text,
        source_ip=client_ip,
        endpoint=str(request.url.path),
        field_name=req.field_name,
        http_method=request.method,
    )

    elapsed = (time.time() - start) * 1000

    # Log incident (non-fatal on failure)
    should_log = result['action'] in ('BLOCK', 'ALERT', 'CHALLENGE') or cfg.api.log_all_requests
    incident_id = None

    if should_log:
        incident_id = _safe_log_incident(
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

    # Use agent decision if available, fall back to detector decision
    final_decision = result.get("agent_decision") or result.get("decision", "SAFE")
    final_action = result.get("agent_action") or result.get("action", "ALLOW")

    response = CheckResponse(
        input=req.text,
        decision=final_decision,
        action=final_action,
        blocked=final_action in ("BLOCK", "ALERT"),
        confidence=result["confidence_level"],
        severity=result.get("severity", "INFO"),
        attack_type=result.get("attack_type", "NONE"),
        scores={
            "ensemble": round(result["score"], 4),
            "rf": round(result["P_rf"], 4),
            "cnn": round(result["P_cnn"], 4),
            "semantic": result["semantic_score"],
        },
        reason=result["reason"],
        rule=result.get("rule", ""),
        processing_time_ms=round(elapsed, 2),
        incident_id=incident_id,
        explanation=result.get("explanation"),
        siem_fields=result.get("siem_fields"),
        # Agent fields
        agent_decision=result.get("agent_decision"),
        agent_action=result.get("agent_action"),
        agent_reason=result.get("agent_reason"),
        contributing_factors=result.get("contributing_factors"),
        escalated=result.get("escalated"),
        adaptive_threshold_used=result.get("adaptive_threshold_used"),
        ip_profile=result.get("ip_profile"),
        session_context=result.get("session_context"),
    )

    log.info("api_check",
             request_id=getattr(request.state, "request_id", "N/A"),
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

    if len(req.fields) > MAX_FIELDS:
        raise HTTPException(
            status_code=400,
            detail=f"Too many fields: {len(req.fields)}. Maximum allowed: {MAX_FIELDS}"
        )

    # Validate field key lengths (prevent log injection / memory bloat)
    oversized_keys = [k for k in req.fields if len(k) > MAX_FIELD_KEY_LENGTH]
    if oversized_keys:
        raise HTTPException(
            status_code=400,
            detail=f"Field key(s) exceed maximum length of {MAX_FIELD_KEY_LENGTH}: "
                   f"{[k[:40] + '...' for k in oversized_keys[:5]]}",
        )

    results = {}
    blocked_fields = []
    incident_ids = []
    truncated_fields: list[str] = []   # fields whose values were truncated

    for fname, fvalue in req.fields.items():
        if isinstance(fvalue, str) and len(fvalue) > 0:
            # Truncate oversized values — run detection on first MAX_TEXT_LENGTH chars
            # to prevent CNN DoS while still catching injection in the visible portion.
            if len(fvalue) > MAX_TEXT_LENGTH:
                fvalue = fvalue[:MAX_TEXT_LENGTH]
                truncated_fields.append(fname)
            result = await _run_detection(
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

            if result["action"] in ("BLOCK", "ALERT", "CHALLENGE"):
                inc_id = _safe_log_incident(
                    input_text=fvalue,
                    result=result,
                    source_ip=client_ip,
                    user_agent=request.headers.get("User-Agent"),
                    endpoint=str(request.url.path),
                    field_name=fname,
                )
                if inc_id:
                    incident_ids.append(inc_id)

    elapsed = (time.time() - start) * 1000

    return {
        "safe": len(blocked_fields) == 0,
        "blocked_fields": blocked_fields,
        "results": results,
        "processing_time_ms": round(elapsed, 2),
        "incident_ids": incident_ids if incident_ids else None,
        # Operational transparency: inform caller if values were truncated
        "truncated_fields": truncated_fields if truncated_fields else None,
    }


@app.get("/api/stats", tags=["Analytics"],
         dependencies=[Depends(check_api_key)])
async def get_stats():
    """Get incident statistics."""
    if not logger:
        raise HTTPException(status_code=503, detail="Logger not initialized")
    try:
        return logger.get_statistics()
    except Exception as e:
        log.error("stats_query_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics") from e


@app.get("/api/incidents", tags=["Analytics"],
         dependencies=[Depends(check_api_key)])
async def get_incidents(
    limit: int = 50,
    offset: int = 0,
    decision: str | None = None,
    action: str | None = None,
    severity: str | None = None,
):
    """Query incident history with filters and pagination."""
    if not logger:
        raise HTTPException(status_code=503, detail="Logger not initialized")

    limit = min(limit, 500)
    try:
        incidents = logger.get_incidents(
            limit=limit,
            offset=offset,
            decision=decision,
            action=action,
            severity=severity,
        )
    except Exception as e:
        log.error("incidents_query_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve incidents") from e

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

    try:
        logger.mark_false_positive(
            incident_id=incident_id,
            is_false_positive=req.is_false_positive,
            reviewer_notes=req.notes,
        )
    except Exception as e:
        log.error("feedback_failed", incident_id=incident_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to save feedback") from e

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

    try:
        export_data = logger.export_to_siem(format=format, severity_min=severity_min)
    except Exception as e:
        log.error("export_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to export incidents") from e

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


@app.get("/api/agent/stats", tags=["AI Agent"],
         dependencies=[Depends(check_api_key)])
async def get_agent_stats():
    """Get AI agent operational statistics (escalations, bans, adaptive triggers, learning)."""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    return agent.get_stats()


@app.get("/api/agent/ip/{ip_address}", tags=["AI Agent"],
         dependencies=[Depends(check_api_key)])
async def get_ip_reputation(ip_address: str):
    """Get reputation profile for a specific IP address."""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    try:
        import ipaddress as _ipmod
        _ipmod.ip_address(ip_address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    return agent.get_ip_report(ip_address)


@app.get("/api/agent/metrics", tags=["AI Agent"],
         dependencies=[Depends(check_api_key)])
async def get_agent_metrics():
    """Get agent metrics: escalations, auto_bans, patterns_learned, memory usage."""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    stats = agent.get_stats()
    return {
        "escalations_total": stats["escalations"],
        "auto_bans_total": stats["auto_bans"],
        "ban_blocks_total": stats["ban_blocks"],
        "adaptive_threshold_triggers": stats["adaptive_threshold_triggers"],
        "signature_escalations": stats["signature_escalations"],
        "patterns_learned": stats["online_learning"]["patterns_learned"],
        "false_positives_corrected": stats["online_learning"]["false_positives_corrected"],
        "sgd_fitted": stats["online_learning"]["sgd_fitted"],
        "tracked_ips": stats["memory"]["tracked_ips"],
        "tracked_sessions": stats["memory"]["tracked_sessions"],
    }


@app.post("/api/agent/feedback", tags=["AI Agent"],
          dependencies=[Depends(check_api_key)])
async def submit_agent_feedback(req: AgentFeedbackRequest):
    """
    Submit analyst feedback for active learning.
    Marks a previously blocked text as false positive → agent suppresses that pattern.
    """
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    if req.is_false_positive:
        agent.learn_false_positive(
            text=req.original_text,
            matched_pattern=req.matched_pattern,
        )
        log.info("agent_feedback_fp",
                 text_preview=_sanitize_log_value(req.original_text, 60),
                 pattern=req.matched_pattern)
        return {
            "status": "ok",
            "action": "false_positive_learned",
            "message": "Pattern weight suppressed. Thank you for the feedback.",
        }
    else:
        return {
            "status": "ok",
            "action": "confirmed_positive",
            "message": "Confirmed true positive recorded.",
        }


@app.get("/metrics", tags=["Monitoring"])
async def prometheus_metrics():
    """Prometheus metrics endpoint for scraping."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/api/demo", response_class=HTMLResponse, tags=["Demo"])
async def demo():
    """Interactive demo page."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SQL Injection Detector v3.1 - Demo</title>
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
        <h1>SQL Injection Detection Agent v3.1</h1>
        <p>Multi-layer ensemble: RF + CNN + Semantic Validation | Attack Typing | Severity | Explainability</p>

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
    print(f"SQL Injection Protection API Server v{VERSION}")
    print("=" * 60)
    print(f"\nDocs:     http://localhost:{cfg.api.port}/docs")
    print(f"Demo:     http://localhost:{cfg.api.port}/api/demo")
    print(f"Health:   http://localhost:{cfg.api.port}/api/health")
    print("=" * 60 + "\n")

    uvicorn.run(app, host=cfg.api.host, port=cfg.api.port)
