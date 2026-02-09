"""
SQL Injection Protection API Server
====================================
REST API for integrating the SQL injection detector into applications.

Endpoints:
    POST /api/check     - Check single text for SQL injection
    POST /api/validate  - Validate entire form
    GET  /api/health    - Health check and model status
    GET  /api/stats     - Incident statistics
    GET  /api/incidents - Query logged incidents
    GET  /api/demo      - Interactive demo page

Usage:
    python api_server.py

    curl -X POST http://localhost:5000/api/check \
         -H "Content-Type: application/json" \
         -d '{"text": "admin'"'"'--"}'
"""

from flask import Flask, request, jsonify
from sql_injection_detector import SQLInjectionEnsemble
from incident_logger import IncidentLogger
import time
import os

app = Flask(__name__)

# Configuration
LOG_ALL_REQUESTS = os.environ.get('LOG_ALL_REQUESTS', 'false').lower() == 'true'
DB_PATH = os.environ.get('INCIDENTS_DB', 'incidents.db')

# Initialize detector and logger
print("Loading SQL Injection Detection Agent...")
detector = SQLInjectionEnsemble()
logger = IncidentLogger(db_path=DB_PATH)
print(f"Models loaded: RF={detector.rf_loaded}, CNN={detector.cnn_loaded}")
print(f"Incident logging: {DB_PATH}")


def get_client_ip():
    """Extract client IP from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'models': {
            'rf': detector.rf_loaded,
            'cnn': detector.cnn_loaded
        },
        'incidents_logged': logger.get_incident_count()
    })


@app.route('/api/check', methods=['POST'])
def check_single():
    """
    Check single text for SQL injection

    Request:
        {"text": "input to check"}

    Response:
        {
            "decision": "SAFE|INVALID|SUSPICIOUS|INJECTION",
            "action": "ALLOW|LOG|CHALLENGE|BLOCK",
            "blocked": true/false,
            "details": {...}
        }
    """
    data = request.get_json()

    if not data or 'text' not in data:
        return jsonify({'error': 'Missing "text" field'}), 400

    text = data['text']
    start = time.time()
    result = detector.detect(text)
    elapsed = (time.time() - start) * 1000

    # Log incidents (BLOCK/CHALLENGE always, others if LOG_ALL_REQUESTS)
    should_log = result['action'] in ('BLOCK', 'CHALLENGE') or LOG_ALL_REQUESTS

    incident_id = None
    if should_log:
        incident_id = logger.log_incident(
            input_text=text,
            result=result,
            source_ip=get_client_ip(),
            user_agent=request.headers.get('User-Agent'),
            endpoint=request.path,
            field_name=data.get('field_name'),
            metadata={'processing_time_ms': round(elapsed, 2)}
        )

    response = {
        'input': text,
        'decision': result['decision'],
        'action': result['action'],
        'blocked': result['action'] == 'BLOCK',
        'confidence': result['confidence_level'],
        'scores': {
            'ensemble': round(result['score'], 3),
            'rf': round(result['P_rf'], 3),
            'cnn': round(result['P_cnn'], 3),
            'semantic': result['semantic_score']
        },
        'reason': result['reason'],
        'processing_time_ms': round(elapsed, 2)
    }

    if incident_id:
        response['incident_id'] = incident_id

    return jsonify(response)


@app.route('/api/validate', methods=['POST'])
def validate_form():
    """
    Validate entire form for SQL injection

    Request:
        {"fields": {"username": "value", "password": "value", ...}}

    Response:
        {
            "safe": true/false,
            "blocked_fields": [...],
            "results": {...}
        }
    """
    data = request.get_json()

    if not data or 'fields' not in data:
        return jsonify({'error': 'Missing "fields" field'}), 400

    fields = data['fields']
    results = {}
    blocked_fields = []
    incident_ids = []

    start = time.time()
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent')

    for field_name, field_value in fields.items():
        if isinstance(field_value, str) and len(field_value) > 0:
            result = detector.detect(field_value)
            results[field_name] = {
                'decision': result['decision'],
                'action': result['action'],
                'score': round(result['score'], 3)
            }

            if result['action'] == 'BLOCK':
                blocked_fields.append(field_name)

            # Log blocked/challenged fields
            if result['action'] in ('BLOCK', 'CHALLENGE'):
                inc_id = logger.log_incident(
                    input_text=field_value,
                    result=result,
                    source_ip=client_ip,
                    user_agent=user_agent,
                    endpoint=request.path,
                    field_name=field_name
                )
                incident_ids.append(inc_id)

    elapsed = (time.time() - start) * 1000

    response = {
        'safe': len(blocked_fields) == 0,
        'blocked_fields': blocked_fields,
        'results': results,
        'processing_time_ms': round(elapsed, 2)
    }

    if incident_ids:
        response['incident_ids'] = incident_ids

    return jsonify(response)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Get incident statistics

    Response:
        {
            "total_incidents": 100,
            "blocked_count": 15,
            "block_rate": 15.0,
            "by_decision": {...},
            "top_attacking_ips": [...]
        }
    """
    stats = logger.get_statistics()
    return jsonify(stats)


@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    """
    Query incident history

    Query params:
        limit (int): Max results (default 50)
        offset (int): Skip N results
        decision (str): Filter by decision
        action (str): Filter by action
        severity (str): Filter by severity (INFO, LOW, MEDIUM, HIGH)

    Response:
        {"incidents": [...], "total": 100}
    """
    limit = min(int(request.args.get('limit', 50)), 500)
    offset = int(request.args.get('offset', 0))
    decision = request.args.get('decision')
    action = request.args.get('action')
    severity = request.args.get('severity')

    incidents = logger.get_incidents(
        limit=limit,
        offset=offset,
        decision=decision,
        action=action,
        severity=severity
    )

    return jsonify({
        'incidents': incidents,
        'count': len(incidents),
        'limit': limit,
        'offset': offset
    })


@app.route('/api/incident/<int:incident_id>/feedback', methods=['POST'])
def submit_feedback(incident_id):
    """
    Submit feedback for active learning

    Request:
        {"is_false_positive": true/false, "notes": "optional notes"}
    """
    data = request.get_json()

    if 'is_false_positive' not in data:
        return jsonify({'error': 'Missing is_false_positive field'}), 400

    logger.mark_false_positive(
        incident_id=incident_id,
        is_false_positive=data['is_false_positive'],
        reviewer_notes=data.get('notes')
    )

    return jsonify({'status': 'ok', 'incident_id': incident_id})


@app.route('/api/export', methods=['GET'])
def export_incidents():
    """
    Export incidents for SIEM integration

    Query params:
        format (str): json, csv, or cef (default: json)
        severity_min (str): Minimum severity (default: LOW)

    Response:
        Formatted incident data
    """
    fmt = request.args.get('format', 'json')
    severity_min = request.args.get('severity_min', 'LOW')

    export_data = logger.export_to_siem(format=fmt, severity_min=severity_min)

    content_types = {
        'json': 'application/json',
        'csv': 'text/csv',
        'cef': 'text/plain'
    }

    from flask import Response
    return Response(
        export_data,
        mimetype=content_types.get(fmt, 'application/json'),
        headers={'Content-Disposition': f'attachment; filename=incidents.{fmt}'}
    )


@app.route('/api/demo', methods=['GET'])
def demo():
    """Demo page with test form"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SQL Injection Detector - Demo</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 50px auto; padding: 20px; }
            input, button { padding: 10px; margin: 5px; font-size: 16px; }
            input { width: 400px; }
            .result { margin-top: 20px; padding: 20px; border-radius: 10px; }
            .safe { background: #d4edda; border: 2px solid #28a745; }
            .blocked { background: #f8d7da; border: 2px solid #dc3545; }
            .invalid { background: #e2e3e5; border: 2px solid #6c757d; }
            .suspicious { background: #fff3cd; border: 2px solid #ffc107; }
            .stats { background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0; }
            .stats h3 { margin-top: 0; }
        </style>
    </head>
    <body>
        <h1>SQL Injection Detection Agent</h1>
        <p>Enter any text to check for SQL injection:</p>

        <input type="text" id="input" placeholder="Enter text to check...">
        <button onclick="checkInput()">Check</button>

        <div id="result"></div>

        <h3>Quick Tests:</h3>
        <button onclick="test(`john_doe`)">Safe: john_doe</button>
        <button onclick="test(`O'Brien`)">Safe: O'Brien</button>
        <button onclick="test(`' OR '1'='1`)">SQLi: ' OR '1'='1</button>
        <button onclick="test(`admin'--`)">SQLi: admin'--</button>
        <button onclick="test(`'1'1'1=1'1'1'1`)">Invalid: garbage</button>

        <div class="stats" id="stats">
            <h3>Statistics</h3>
            <p>Loading...</p>
        </div>

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

                document.getElementById('result').innerHTML = `
                    <div class="result ${cssClass}">
                        <h2>${data.decision} - ${data.action}</h2>
                        <p><b>Input:</b> ${data.input}</p>
                        <p><b>Blocked:</b> ${data.blocked}</p>
                        <p><b>Scores:</b> Ensemble=${data.scores.ensemble}, RF=${data.scores.rf}, CNN=${data.scores.cnn}, Semantic=${data.scores.semantic}</p>
                        <p><b>Reason:</b> ${data.reason}</p>
                        <p><b>Time:</b> ${data.processing_time_ms}ms</p>
                        ${data.incident_id ? `<p><b>Incident ID:</b> ${data.incident_id}</p>` : ''}
                    </div>
                `;

                loadStats();
            }

            async function loadStats() {
                const response = await fetch('/api/stats');
                const stats = await response.json();

                document.getElementById('stats').innerHTML = `
                    <h3>Incident Statistics</h3>
                    <p><b>Total:</b> ${stats.total_incidents} |
                       <b>Blocked:</b> ${stats.blocked_count} |
                       <b>Block Rate:</b> ${stats.block_rate}%</p>
                    <p><b>By Decision:</b>
                       Safe: ${stats.by_decision.safe},
                       Invalid: ${stats.by_decision.invalid},
                       Suspicious: ${stats.by_decision.suspicious},
                       Injection: ${stats.by_decision.injection}</p>
                `;
            }

            loadStats();
        </script>
    </body>
    </html>
    '''


if __name__ == '__main__':
    print("\n" + "="*60)
    print("SQL Injection Protection API Server")
    print("="*60)
    print("\nEndpoints:")
    print("  GET  /api/health     - Health check")
    print("  POST /api/check      - Check single text")
    print("  POST /api/validate   - Validate form")
    print("  GET  /api/stats      - Incident statistics")
    print("  GET  /api/incidents  - Query incidents")
    print("  GET  /api/export     - Export for SIEM")
    print("  GET  /api/demo       - Interactive demo")
    print("\nStarting server on http://localhost:5000")
    print("Demo page: http://localhost:5000/api/demo")
    print("="*60 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=False)
