"""
TenderPro Demo — Корпоративный портал закупок с защитой от SQL-инъекций
=======================================================================
Клиент  → видит обычный сайт; при атаке получает generic-ошибку
Админ   → видит все инциденты в реальном времени (авто-обновление 4 с)

Запуск:
    python demo_site.py

URLs:
    http://localhost:8080         — портал закупок  (клиентская сторона)
    http://localhost:8080/admin   — панель безопасности (только для SOC)
"""

import sqlite3
import time
import uvicorn
from collections import deque
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from sql_injection_detector import SQLInjectionEnsemble

# ── Init ──────────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None)
detector = SQLInjectionEnsemble()
incidents: deque = deque(maxlen=500)

DB_PATH = Path(__file__).parent / "demo_incidents.db"


def _db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _db_init() -> None:
    """Create table if not exists and load last 500 rows into memory deque."""
    with _db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id          TEXT PRIMARY KEY,
                ts          TEXT NOT NULL,
                ip          TEXT NOT NULL,
                endpoint    TEXT NOT NULL,
                field       TEXT NOT NULL,
                payload     TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity    TEXT NOT NULL,
                score       REAL NOT NULL,
                decision    TEXT NOT NULL,
                rule        TEXT NOT NULL
            )
        """)
        conn.commit()
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY rowid DESC LIMIT 500"
        ).fetchall()
    # Load into deque (newest first)
    for row in rows:
        incidents.append(dict(row))
    print(f"  [DB] Загружено {len(rows)} инцидентов из {DB_PATH.name}")


def _db_save(inc: dict) -> None:
    """Persist one incident to SQLite (non-blocking, fire-and-forget)."""
    try:
        with _db_connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO incidents
                   (id, ts, ip, endpoint, field, payload,
                    attack_type, severity, score, decision, rule)
                   VALUES (:id,:ts,:ip,:endpoint,:field,:payload,
                           :attack_type,:severity,:score,:decision,:rule)""",
                inc,
            )
            conn.commit()
    except Exception as e:
        print(f"  [DB] Ошибка записи: {e}")

# ── Fake tender data ──────────────────────────────────────────────────────────
TENDERS = [
    {"id": "2024-ЭА-1142", "title": "Поставка компьютерного оборудования МВД России",
     "org": "МВД России", "budget": "12 450 000 ₽", "deadline": "15.04.2024", "status": "active"},
    {"id": "2024-ЭА-1143", "title": "Капитальный ремонт здания администрации г. Москвы",
     "org": "Мэрия Москвы", "budget": "87 300 000 ₽", "deadline": "20.04.2024", "status": "active"},
    {"id": "2024-ОК-1144", "title": "Закупка медицинского оборудования для ГКРБ №5",
     "org": "Минздрав России", "budget": "34 700 000 ₽", "deadline": "25.04.2024", "status": "active"},
    {"id": "2024-ЗП-1145", "title": "IT-инфраструктура и серверное оборудование ФНС",
     "org": "ФНС России", "budget": "156 200 000 ₽", "deadline": "01.05.2024", "status": "review"},
    {"id": "2024-ЭА-1146", "title": "Транспортные услуги для перевозки сотрудников",
     "org": "Росстат", "budget": "8 900 000 ₽", "deadline": "10.05.2024", "status": "active"},
    {"id": "2024-ОК-1147", "title": "Разработка программного обеспечения для системы ЕГЭ",
     "org": "Рособрнадзор", "budget": "45 600 000 ₽", "deadline": "12.05.2024", "status": "active"},
    {"id": "2024-ЭА-1148", "title": "Строительство дороги федерального значения М-12",
     "org": "Росавтодор", "budget": "320 000 000 ₽", "deadline": "30.05.2024", "status": "active"},
    {"id": "2024-ОК-1149", "title": "Поставка форменного обмундирования для МО",
     "org": "Минобороны", "budget": "62 100 000 ₽", "deadline": "05.06.2024", "status": "review"},
]


def _inc_id() -> str:
    return f"INC-{int(time.time() * 1000) % 10_000_000:07d}"


def check(text: str, field: str, ip: str, endpoint: str) -> dict:
    """Run detector; if blocked — log incident to memory + SQLite."""
    result = detector.detect(text, source_ip=ip, endpoint=endpoint, field_name=field)
    if result["decision"] in ("INJECTION", "SUSPICIOUS"):
        inc_id = _inc_id()
        inc = {
            "id": inc_id,
            "ts": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            "ip": ip,
            "endpoint": endpoint,
            "field": field,
            "payload": text[:150],
            "attack_type": result.get("attack_type", "UNKNOWN"),
            "severity": result.get("severity", "INFO"),
            "score": round(result.get("score", 0), 4),
            "decision": result["decision"],
            "rule": result.get("rule", "-"),
        }
        incidents.appendleft(inc)
        _db_save(inc)          # ← сохраняем в SQLite
        return {"blocked": True, "incident_id": inc_id}
    return {"blocked": False}


# ─────────────────────────────────────────────────────────────────────────────
#  HTML TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TenderPro — Вход в систему</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<style>
  body{background:linear-gradient(135deg,#0d3b66 0%,#1a6fa0 100%);min-height:100vh;font-family:'Segoe UI',sans-serif;}
  .card{border:none;border-radius:16px;box-shadow:0 24px 64px rgba(0,0,0,.4);}
  .logo-icon{font-size:3.2rem;color:#0d3b66;}
  .logo-text{font-size:1.8rem;font-weight:800;color:#0d3b66;letter-spacing:-.5px;}
  .logo-sub{font-size:.78rem;color:#6c757d;margin-top:-4px;}
  .btn-login{background:#0d3b66;border:none;padding:.7rem;font-weight:600;letter-spacing:.4px;}
  .btn-login:hover{background:#1a6fa0;}
  .form-control:focus{border-color:#1a6fa0;box-shadow:0 0 0 .2rem rgba(26,111,160,.2);}
  .hint-box{background:#f0f7ff;border-left:4px solid #1a6fa0;border-radius:6px;}
  .arch-box{background:rgba(255,255,255,.08);border-radius:10px;font-size:.78rem;color:rgba(255,255,255,.7);}
</style>
</head>
<body class="d-flex align-items-center justify-content-center py-5">
<div style="width:440px">
  <div class="card p-4 p-md-5">
    <div class="text-center mb-4">
      <i class="bi bi-shield-check logo-icon"></i>
      <div class="logo-text">TenderPro</div>
      <div class="logo-sub">Единая система государственных закупок</div>
    </div>
    __ERROR_BLOCK__
    <form method="POST" action="/login" autocomplete="off">
      <div class="mb-3">
        <label class="form-label fw-semibold small text-uppercase text-muted">Логин</label>
        <div class="input-group">
          <span class="input-group-text bg-light"><i class="bi bi-person text-muted"></i></span>
          <input type="text" name="username" class="form-control" placeholder="Введите логин" autofocus>
        </div>
      </div>
      <div class="mb-4">
        <label class="form-label fw-semibold small text-uppercase text-muted">Пароль</label>
        <div class="input-group">
          <span class="input-group-text bg-light"><i class="bi bi-lock text-muted"></i></span>
          <input type="password" name="password" class="form-control" placeholder="Введите пароль">
        </div>
      </div>
      <button type="submit" class="btn btn-login btn-primary w-100 text-white">
        <i class="bi bi-box-arrow-in-right me-2"></i>Войти в систему
      </button>
    </form>
    <div class="hint-box p-3 mt-4">
      <div class="fw-semibold small mb-1"><i class="bi bi-bug me-1 text-primary"></i>Демо — попробуйте SQL-инъекцию:</div>
      <code class="d-block text-danger small mt-1">' OR '1'='1'--</code>
      <code class="d-block text-danger small">' UNION SELECT * FROM users--</code>
      <code class="d-block text-danger small">admin'--</code>
    </div>
  </div>
  <div class="arch-box mt-3 p-3 text-center">
    <i class="bi bi-diagram-3 me-1"></i>
    Запрос → <strong class="text-white">SQL Injection Detector</strong> → БД
  </div>
  <div class="text-center mt-2 text-white-50 small">
    © 2024 TenderPro · Министерство экономического развития РФ
  </div>
</div>
</body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TenderPro — Актуальные закупки</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<style>
  body{font-family:'Segoe UI',sans-serif;background:#f4f6f9;}
  .navbar{background:#0d3b66!important;}
  .stat-card{border:none;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);}
  .stat-icon{font-size:1.8rem;width:52px;height:52px;display:flex;align-items:center;justify-content:center;border-radius:12px;}
  .table-hover tbody tr:hover{background:#f0f7ff;}
  .badge-active{background:#d1e7dd;color:#0f5132;padding:3px 12px;border-radius:20px;font-size:.78rem;font-weight:600;}
  .badge-review{background:#fff3cd;color:#664d03;padding:3px 12px;border-radius:20px;font-size:.78rem;font-weight:600;}
  .search-input:focus{border-color:#1a6fa0;box-shadow:0 0 0 .2rem rgba(26,111,160,.15);}
</style>
</head>
<body>
<nav class="navbar navbar-dark px-4 py-3">
  <a class="navbar-brand fw-bold" href="/dashboard"><i class="bi bi-shield-check me-2"></i>TenderPro</a>
  <div class="ms-auto d-flex align-items-center gap-3">
    <span class="text-white-50 small"><i class="bi bi-person-circle me-1"></i>__USER__</span>
    <a href="/" class="btn btn-outline-light btn-sm"><i class="bi bi-box-arrow-right me-1"></i>Выйти</a>
  </div>
</nav>
<div class="container-fluid py-4 px-4">
  <div class="row g-3 mb-4">
    <div class="col-md-3"><div class="card stat-card p-3"><div class="d-flex align-items-center gap-3">
      <div class="stat-icon bg-primary bg-opacity-10 text-primary"><i class="bi bi-file-text"></i></div>
      <div><div class="fw-bold fs-4">1 847</div><div class="text-muted small">Всего тендеров</div></div>
    </div></div></div>
    <div class="col-md-3"><div class="card stat-card p-3"><div class="d-flex align-items-center gap-3">
      <div class="stat-icon bg-success bg-opacity-10 text-success"><i class="bi bi-check-circle"></i></div>
      <div><div class="fw-bold fs-4">342</div><div class="text-muted small">Активных</div></div>
    </div></div></div>
    <div class="col-md-3"><div class="card stat-card p-3"><div class="d-flex align-items-center gap-3">
      <div class="stat-icon bg-warning bg-opacity-10 text-warning"><i class="bi bi-clock"></i></div>
      <div><div class="fw-bold fs-4">89</div><div class="text-muted small">На рассмотрении</div></div>
    </div></div></div>
    <div class="col-md-3"><div class="card stat-card p-3"><div class="d-flex align-items-center gap-3">
      <div class="stat-icon bg-info bg-opacity-10 text-info"><i class="bi bi-currency-exchange"></i></div>
      <div><div class="fw-bold fs-4">₽ 4.2B</div><div class="text-muted small">Общий объём</div></div>
    </div></div></div>
  </div>

  <div class="card border-0 shadow-sm rounded-3 mb-4">
    <div class="card-body p-3">
      <form method="POST" action="/search" class="d-flex gap-2">
        <input type="text" name="query" class="form-control search-input"
               placeholder="Поиск по тендерам, организациям, номерам закупок...">
        <button type="submit" class="btn btn-primary px-4">
          <i class="bi bi-search me-1"></i>Найти
        </button>
      </form>
    </div>
  </div>

  <div class="card border-0 shadow-sm rounded-3">
    <div class="card-header bg-white border-0 pt-3 pb-0 px-4">
      <h5 class="fw-bold text-dark mb-3"><i class="bi bi-list-ul me-2 text-primary"></i>Актуальные закупки</h5>
    </div>
    <div class="card-body p-0">
      <table class="table table-hover mb-0 align-middle">
        <thead class="table-light">
          <tr>
            <th class="ps-4">Реестровый №</th>
            <th>Наименование закупки</th>
            <th>Заказчик</th>
            <th>Начальная цена</th>
            <th>Срок подачи</th>
            <th class="pe-4">Статус</th>
          </tr>
        </thead>
        <tbody>__ROWS__</tbody>
      </table>
    </div>
  </div>
</div>
</body></html>"""

ERROR_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TenderPro — Ошибка обработки запроса</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<style>
  body{background:#f4f6f9;font-family:'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;}
  .err-card{border:none;border-radius:16px;max-width:520px;box-shadow:0 8px 32px rgba(0,0,0,.1);}
  .ref-box{background:#f8f9fa;border-radius:8px;font-family:monospace;border:1px solid #dee2e6;}
</style>
</head>
<body>
<div class="err-card card p-5 text-center mx-3">
  <i class="bi bi-exclamation-triangle-fill text-danger mb-3" style="font-size:4rem"></i>
  <h4 class="fw-bold mb-2">Ошибка обработки запроса</h4>
  <p class="text-muted mb-4">
    При обработке вашего запроса произошла техническая ошибка.<br>
    Это может быть связано с некорректными входными данными<br>
    или временными неполадками на сервере.
  </p>
  <div class="ref-box p-3 mb-4">
    <div class="text-muted small mb-1">Код ошибки для службы технической поддержки:</div>
    <div class="fw-bold fs-5">__INCIDENT_ID__</div>
  </div>
  <div class="text-muted small mb-4">
    Если проблема повторяется, обратитесь в поддержку:<br>
    <strong>support@tenderpro.gov.ru</strong> &nbsp;·&nbsp; тел. <strong>8 (800) 100-00-01</strong>
  </div>
  <a href="/" class="btn btn-primary px-4"><i class="bi bi-arrow-left me-2"></i>Вернуться на главную</a>
</div>
</body></html>"""

ADMIN_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TenderPro — Центр безопасности (SOC)</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
<style>
  *{box-sizing:border-box;}
  body{font-family:'Segoe UI',sans-serif;background:#0f1923;color:#dde6f0;min-height:100vh;display:flex;margin:0;}
  /* sidebar */
  .sidebar{width:230px;background:#0a1520;min-height:100vh;flex-shrink:0;display:flex;flex-direction:column;}
  .sb-brand{background:#c82333;padding:18px 20px;}
  .sb-brand .name{font-size:1.1rem;font-weight:800;color:#fff;}
  .sb-brand .sub{font-size:.72rem;color:rgba(255,255,255,.6);margin-top:2px;}
  .nav-link{color:#7a8fa3;padding:10px 20px;font-size:.875rem;border-radius:0;display:flex;align-items:center;gap:10px;}
  .nav-link:hover,.nav-link.active{background:rgba(255,255,255,.05);color:#fff;}
  /* main */
  .main{flex:1;padding:24px;overflow-x:hidden;}
  /* stat cards */
  .sc{background:#1a2535;border:1px solid #243447;border-radius:12px;padding:16px;}
  .sc .lbl{font-size:.75rem;color:#7a8fa3;margin-bottom:4px;}
  .sc .val{font-size:2rem;font-weight:700;line-height:1;}
  /* table */
  .panel{background:#1a2535;border:1px solid #243447;border-radius:12px;overflow:hidden;}
  .panel-hdr{background:#131f2e;padding:14px 20px;border-bottom:1px solid #243447;display:flex;align-items:center;justify-content:space-between;}
  table.inc{width:100%;border-collapse:collapse;}
  table.inc th{background:#131f2e;color:#7a8fa3;font-size:.72rem;text-transform:uppercase;padding:11px 14px;border-bottom:1px solid #243447;font-weight:600;letter-spacing:.05em;white-space:nowrap;}
  table.inc td{padding:9px 14px;border-bottom:1px solid #1e2e40;font-size:.83rem;vertical-align:middle;}
  table.inc tr:hover td{background:#1e2e40;}
  @keyframes flash{0%{background:rgba(220,53,69,.18);}100%{background:transparent;}}
  .new-row td{animation:flash 2.5s ease-out;}
  .payload{font-family:monospace;font-size:.78rem;color:#ff7070;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .atk-badge{background:#1b3a5e;color:#5aabff;padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600;font-family:monospace;}
  /* severity badges */
  .sev-CRITICAL{background:rgba(220,53,69,.15);color:#ff6b6b;border:1px solid rgba(220,53,69,.3);padding:2px 9px;border-radius:20px;font-size:.72rem;font-weight:700;}
  .sev-HIGH{background:rgba(253,126,20,.15);color:#ffaa40;border:1px solid rgba(253,126,20,.3);padding:2px 9px;border-radius:20px;font-size:.72rem;font-weight:700;}
  .sev-MEDIUM{background:rgba(255,193,7,.12);color:#ffd04a;border:1px solid rgba(255,193,7,.3);padding:2px 9px;border-radius:20px;font-size:.72rem;font-weight:700;}
  .sev-LOW{background:rgba(13,202,240,.1);color:#4dd0e1;border:1px solid rgba(13,202,240,.25);padding:2px 9px;border-radius:20px;font-size:.72rem;font-weight:700;}
  .sev-INFO{background:rgba(108,117,125,.12);color:#9ba8b4;border:1px solid rgba(108,117,125,.25);padding:2px 9px;border-radius:20px;font-size:.72rem;font-weight:700;}
  .dot-live{width:8px;height:8px;background:#28a745;border-radius:50%;display:inline-block;animation:pulse 1.5s infinite;}
  @keyframes pulse{0%,100%{opacity:1;}50%{opacity:.25;}}
  .empty{text-align:center;padding:60px;color:#3d5470;}
  .empty i{font-size:3rem;display:block;margin-bottom:12px;}
</style>
</head>
<body>
<div class="sidebar">
  <div class="sb-brand">
    <div class="name"><i class="bi bi-shield-exclamation me-2"></i>SOC TenderPro</div>
    <div class="sub">Центр безопасности</div>
  </div>
  <nav class="nav flex-column mt-2">
    <a class="nav-link active" href="/admin"><i class="bi bi-list-ul"></i>Инциденты</a>
    <a class="nav-link" href="http://localhost:5000/api/incidents" target="_blank"><i class="bi bi-cloud-download"></i>API экспорт</a>
    <a class="nav-link" href="http://localhost:5000/docs" target="_blank"><i class="bi bi-code-square"></i>API Docs</a>
    <a class="nav-link" href="http://localhost:5000/api/health" target="_blank"><i class="bi bi-heart-pulse"></i>Статус системы</a>
  </nav>
  <div class="mt-auto p-3">
    <div class="small text-secondary"><i class="bi bi-person-badge me-1"></i>security@tenderpro</div>
    <a href="/" target="_blank" class="btn btn-outline-secondary btn-sm w-100 mt-2">
      <i class="bi bi-globe me-1"></i>Открыть сайт
    </a>
  </div>
</div>

<div class="main">
  <div class="d-flex align-items-start justify-content-between mb-4">
    <div>
      <h4 class="fw-bold text-white mb-1">Журнал инцидентов SQL-инъекций</h4>
      <div class="small text-secondary">Защищённые эндпоинты: /login &nbsp;·&nbsp; /search</div>
    </div>
    <div class="d-flex align-items-center gap-3 mt-1">
      <span class="small text-secondary">Обновлено: <span id="last-upd" class="text-white">—</span></span>
      <span class="dot-live"></span><span class="small text-success ms-1">LIVE</span>
    </div>
  </div>

  <!-- Stats -->
  <div class="row g-3 mb-4">
    <div class="col-md-3"><div class="sc">
      <div class="lbl"><i class="bi bi-shield-x me-1"></i>Всего инцидентов</div>
      <div class="val text-danger" id="s-total">—</div>
    </div></div>
    <div class="col-md-3"><div class="sc">
      <div class="lbl"><i class="bi bi-clock-history me-1"></i>Последние 5 минут</div>
      <div class="val text-warning" id="s-recent">—</div>
    </div></div>
    <div class="col-md-3"><div class="sc">
      <div class="lbl"><i class="bi bi-geo-alt me-1"></i>Уникальных IP</div>
      <div class="val text-info" id="s-ips">—</div>
    </div></div>
    <div class="col-md-3"><div class="sc">
      <div class="lbl"><i class="bi bi-exclamation-octagon me-1"></i>Критических</div>
      <div class="val text-danger" id="s-crit">—</div>
    </div></div>
  </div>

  <!-- Table -->
  <div class="panel">
    <div class="panel-hdr">
      <div class="fw-semibold text-white"><i class="bi bi-table me-2 text-danger"></i>Зафиксированные атаки</div>
      <div class="d-flex gap-2">
        <button class="btn btn-outline-secondary btn-sm" onclick="load()">
          <i class="bi bi-arrow-clockwise me-1"></i>Обновить
        </button>
        <button class="btn btn-outline-danger btn-sm" onclick="clearAll()">
          <i class="bi bi-trash me-1"></i>Очистить
        </button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table class="inc">
        <thead>
          <tr>
            <th>ID инцидента</th>
            <th>Дата / Время</th>
            <th>IP атакующего</th>
            <th>Эндпоинт</th>
            <th>Поле</th>
            <th>Payload</th>
            <th>Тип атаки</th>
            <th>Критичность</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody id="tbody">
          <tr><td colspan="9" class="empty">
            <i class="bi bi-shield-check"></i>
            Инцидентов пока нет.<br>
            <a href="/" class="text-info" target="_blank">Откройте сайт</a> и введите SQL-инъекцию в форму входа.
          </td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
let prevLen = 0;

function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function scoreColor(v){
  if(v>0.8) return 'color:#ff6b6b;font-weight:700';
  if(v>0.5) return 'color:#ffaa40;font-weight:600';
  return 'color:#7a8fa3';
}

async function load(){
  try{
    const r = await fetch('/admin/api/incidents');
    const d = await r.json();

    document.getElementById('s-total').textContent  = d.stats.total;
    document.getElementById('s-recent').textContent = d.stats.recent_5min;
    document.getElementById('s-ips').textContent    = d.stats.unique_ips;
    document.getElementById('s-crit').textContent   = d.stats.critical;
    document.getElementById('last-upd').textContent = new Date().toLocaleTimeString('ru-RU');

    const tbody = document.getElementById('tbody');
    if(!d.incidents.length){
      tbody.innerHTML = `<tr><td colspan="9" class="empty">
        <i class="bi bi-shield-check"></i>
        Инцидентов пока нет.<br>
        <a href="/" class="text-info" target="_blank">Откройте сайт</a> и введите SQL-инъекцию в форму входа.
      </td></tr>`;
      prevLen = 0; return;
    }

    const newCount = d.incidents.length - prevLen;
    tbody.innerHTML = d.incidents.map((inc, i) => {
      const cls = (newCount > 0 && i < newCount) ? 'new-row' : '';
      return `<tr class="${cls}">
        <td><code style="color:#4a7fa5;font-size:.78rem">${esc(inc.id)}</code></td>
        <td style="color:#7a8fa3;font-size:.8rem;white-space:nowrap">${esc(inc.ts)}</td>
        <td><code style="color:#4dd0e1">${esc(inc.ip)}</code></td>
        <td><span class="atk-badge">${esc(inc.endpoint)}</span></td>
        <td style="color:#7a8fa3;font-size:.8rem">${esc(inc.field)}</td>
        <td class="payload" title="${esc(inc.payload)}">${esc(inc.payload)}</td>
        <td><span class="atk-badge">${esc(inc.attack_type)}</span></td>
        <td><span class="sev-${esc(inc.severity)}">${esc(inc.severity)}</span></td>
        <td style="${scoreColor(inc.score)}">${inc.score.toFixed(3)}</td>
      </tr>`;
    }).join('');

    prevLen = d.incidents.length;
  } catch(e){ console.error(e); }
}

async function clearAll(){
  if(!confirm('Удалить все инциденты из памяти и базы данных?')) return;
  await fetch('/admin/api/clear');
  prevLen = 0;
  load();
}

load();
setInterval(load, 4000);
</script>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _render_dashboard(user: str, tenders: list) -> str:
    rows = ""
    for t in tenders:
        label = "Активен" if t["status"] == "active" else "На рассмотрении"
        rows += (
            f'<tr>'
            f'<td class="ps-4"><code class="text-primary small">{t["id"]}</code></td>'
            f'<td>{t["title"]}</td>'
            f'<td class="text-muted small">{t["org"]}</td>'
            f'<td class="fw-semibold">{t["budget"]}</td>'
            f'<td class="small text-muted">{t["deadline"]}</td>'
            f'<td class="pe-4"><span class="badge-{t["status"]}">{label}</span></td>'
            f'</tr>'
        )
    if not rows:
        rows = '<tr><td colspan="6" class="text-center py-5 text-muted">По вашему запросу ничего не найдено</td></tr>'
    return DASHBOARD_HTML.replace("__USER__", user).replace("__ROWS__", rows)


# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES — CLIENT SIDE
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def login_page():
    return LOGIN_HTML.replace("__ERROR_BLOCK__", "")


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(default=""),
    password: str = Form(default=""),
):
    ip = request.client.host

    # Check username field
    r = check(username, "username", ip, "/login")
    if r["blocked"]:
        return HTMLResponse(ERROR_HTML.replace("__INCIDENT_ID__", r["incident_id"]))

    # Check password field
    if password:
        r = check(password, "password", ip, "/login")
        if r["blocked"]:
            return HTMLResponse(ERROR_HTML.replace("__INCIDENT_ID__", r["incident_id"]))

    # Demo: accept any non-empty credentials
    if username and password:
        return HTMLResponse(_render_dashboard(username, TENDERS))

    err = '<div class="alert alert-danger small py-2 mb-3"><i class="bi bi-x-circle me-1"></i>Неверный логин или пароль</div>'
    return HTMLResponse(LOGIN_HTML.replace("__ERROR_BLOCK__", err))


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(_render_dashboard("Гость", TENDERS))


@app.post("/search", response_class=HTMLResponse)
async def search_post(request: Request, query: str = Form(default="")):
    ip = request.client.host

    r = check(query, "search_query", ip, "/search")
    if r["blocked"]:
        return HTMLResponse(ERROR_HTML.replace("__INCIDENT_ID__", r["incident_id"]))

    q = query.strip().lower()
    filtered = (
        [t for t in TENDERS
         if q in t["title"].lower() or q in t["org"].lower() or q in t["id"].lower()]
        if q else TENDERS
    )
    return HTMLResponse(_render_dashboard("demo_user", filtered))


# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES — ADMIN SIDE
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    return HTMLResponse(ADMIN_HTML)


@app.get("/admin/api/incidents")
async def admin_incidents_api():
    now = datetime.now()
    inc_list = list(incidents)

    recent = 0
    for inc in inc_list:
        try:
            ts = datetime.strptime(inc["ts"], "%d.%m.%Y %H:%M:%S")
            if (now - ts).total_seconds() < 300:
                recent += 1
        except Exception:
            pass

    return JSONResponse({
        "incidents": inc_list,
        "stats": {
            "total":      len(inc_list),
            "recent_5min": recent,
            "unique_ips":  len({i["ip"] for i in inc_list}),
            "critical":    sum(1 for i in inc_list if i["severity"] == "CRITICAL"),
        },
    })


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/admin/api/clear")
async def admin_clear():
    """Clear all incidents from memory and DB (demo utility)."""
    incidents.clear()
    try:
        with _db_connect() as conn:
            conn.execute("DELETE FROM incidents")
            conn.commit()
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})
    return JSONResponse({"ok": True})


if __name__ == "__main__":
    _db_init()   # ← загружаем старые инциденты из БД при старте
    print("=" * 58)
    print("  TenderPro Demo — SQL Injection Protection")
    print("=" * 58)
    print("  Сайт закупок:  http://localhost:8080")
    print("  Панель SOC:    http://localhost:8080/admin")
    print(f"  База данных:   {DB_PATH.name}")
    print("=" * 58)
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
