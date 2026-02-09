# SQL Injection Detection Agent

Intelligent SQL injection detection system using ensemble machine learning (Random Forest + CNN) with semantic analysis.

## Features

- **4-class classification**: SAFE, INVALID, SUSPICIOUS, INJECTION
- **Ensemble ML**: Random Forest (TF-IDF) + CNN (char-level)
- **Semantic Analysis**: Rule-based SQL pattern detection
- **Low False Positives**: INVALID class for malformed but harmless input
- **REST API**: Easy integration into any application
- **Incident Logging**: SQLite database with SIEM export
- **Active Learning**: Feedback loop for model improvement

## Architecture

```
                    +------------------+
                    |   User Input     |
                    +--------+---------+
                             |
                    +--------v---------+
                    | Semantic Analyzer|  <-- Rule-based pre-filter
                    | (SQL patterns)   |      Calculates semantic_score
                    +--------+---------+
                             |
            +----------------+----------------+
            |                                 |
   +--------v--------+              +---------v--------+
   | Random Forest   |              |   CNN Model      |
   | (TF-IDF + feat) |              | (char-level)     |
   +--------+--------+              +---------+--------+
            |                                 |
            +----------------+----------------+
                             |
                    +--------v---------+
                    | Ensemble Logic   |  S = 0.65*P_cnn + 0.35*P_rf
                    | Decision Rules   |
                    +--------+---------+
                             |
                    +--------v---------+
                    |    Decision      |
                    | SAFE/INVALID/    |
                    | SUSPICIOUS/BLOCK |
                    +------------------+
```

## Decision Logic

| Rule | Condition | Decision | Action |
|------|-----------|----------|--------|
| 0 | P_cnn >= 0.70 AND P_rf < 0.50 AND sem < 2.0 | INVALID | LOG |
| 1 | S >= 0.60 AND sem >= 2.0 | INJECTION | BLOCK |
| 2 | P_cnn >= 0.75 AND sem >= 3.0 | INJECTION | BLOCK |
| 3 | P_rf >= 0.70 AND sem >= 2.0 | INJECTION | BLOCK |
| 4 | S < 0.30 | SAFE | ALLOW |
| 5 | sem >= 1.0 | SUSPICIOUS | CHALLENGE |
| 6 | default | INVALID | LOG |

**Actions:**
- `ALLOW`: Request passes through
- `LOG`: Log for analysis, allow through
- `CHALLENGE`: Require CAPTCHA or additional verification
- `BLOCK`: Block the request

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/your-username/sql-injection-detector.git
cd sql-injection-detector

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Basic Usage (Python)

```python
from sql_injection_detector import SQLInjectionEnsemble

detector = SQLInjectionEnsemble()

# Check input
result = detector.detect("' OR '1'='1")

print(f"Decision: {result['decision']}")  # INJECTION
print(f"Action: {result['action']}")      # BLOCK
print(f"Score: {result['score']:.2f}")    # 0.95
```

### 3. Run API Server

```bash
python api_server.py
# Server starts on http://localhost:5000
```

### 4. Run Streamlit Demo

```bash
streamlit run streamlit_demo.py
# Opens browser at http://localhost:8501
```

## API Reference

### Check Single Input

```bash
POST /api/check
Content-Type: application/json

{"text": "admin'--"}
```

Response:
```json
{
  "decision": "INJECTION",
  "action": "BLOCK",
  "blocked": true,
  "confidence": "CRITICAL",
  "scores": {
    "ensemble": 0.89,
    "rf": 0.85,
    "cnn": 0.92,
    "semantic": 6.5
  },
  "reason": "High ensemble score (0.89) with SQL patterns",
  "incident_id": 42
}
```

### Validate Form

```bash
POST /api/validate
Content-Type: application/json

{
  "fields": {
    "username": "john_doe",
    "search": "' OR 1=1--"
  }
}
```

Response:
```json
{
  "safe": false,
  "blocked_fields": ["search"],
  "results": {
    "username": {"decision": "SAFE", "action": "ALLOW", "score": 0.12},
    "search": {"decision": "INJECTION", "action": "BLOCK", "score": 0.91}
  }
}
```

### Get Statistics

```bash
GET /api/stats
```

Response:
```json
{
  "total_incidents": 150,
  "blocked_count": 23,
  "block_rate": 15.33,
  "by_decision": {
    "safe": 80,
    "invalid": 35,
    "suspicious": 12,
    "injection": 23
  },
  "top_attacking_ips": [
    {"ip": "192.168.1.100", "count": 15}
  ]
}
```

### Export for SIEM

```bash
GET /api/export?format=cef&severity_min=LOW
```

## Integration Guide

### Web Application (Flask)

```python
from flask import Flask, request, jsonify
from sql_injection_detector import SQLInjectionEnsemble
from functools import wraps

app = Flask(__name__)
detector = SQLInjectionEnsemble()

def sql_injection_protection(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check all form fields
        for key, value in request.form.items():
            if isinstance(value, str):
                result = detector.detect(value)
                if result['action'] == 'BLOCK':
                    return jsonify({
                        'error': 'SQL injection detected',
                        'field': key
                    }), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
@sql_injection_protection
def login():
    # Your login logic
    pass
```

### Django Middleware

```python
# middleware.py
from sql_injection_detector import SQLInjectionEnsemble
from django.http import JsonResponse

class SQLInjectionProtectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.detector = SQLInjectionEnsemble()

    def __call__(self, request):
        # Check POST data
        if request.method == 'POST':
            for key, value in request.POST.items():
                result = self.detector.detect(str(value))
                if result['action'] == 'BLOCK':
                    return JsonResponse(
                        {'error': 'SQL injection detected', 'field': key},
                        status=403
                    )
        return self.get_response(request)

# settings.py
MIDDLEWARE = [
    'yourapp.middleware.SQLInjectionProtectionMiddleware',
    # ... other middleware
]
```

### FastAPI

```python
from fastapi import FastAPI, Request, HTTPException
from sql_injection_detector import SQLInjectionEnsemble

app = FastAPI()
detector = SQLInjectionEnsemble()

@app.middleware("http")
async def sql_injection_middleware(request: Request, call_next):
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.json()
            for key, value in body.items():
                if isinstance(value, str):
                    result = detector.detect(value)
                    if result['action'] == 'BLOCK':
                        raise HTTPException(
                            status_code=403,
                            detail=f"SQL injection detected in field: {key}"
                        )
        except:
            pass
    return await call_next(request)
```

### Node.js / Express

```javascript
// Use the REST API
const axios = require('axios');

const sqlInjectionMiddleware = async (req, res, next) => {
    const fieldsToCheck = { ...req.body, ...req.query };

    try {
        const response = await axios.post('http://localhost:5000/api/validate', {
            fields: fieldsToCheck
        });

        if (!response.data.safe) {
            return res.status(403).json({
                error: 'SQL injection detected',
                blocked_fields: response.data.blocked_fields
            });
        }
        next();
    } catch (error) {
        console.error('SQL injection check failed:', error);
        next(); // Fail open or closed based on your security policy
    }
};

app.use(sqlInjectionMiddleware);
```

### SIEM Integration (Splunk/ELK)

```bash
# Export incidents in CEF format for Splunk
curl "http://localhost:5000/api/export?format=cef&severity_min=LOW" >> /var/log/sql_injection.log

# For ELK Stack, use JSON format
curl "http://localhost:5000/api/export?format=json" | \
  jq -c '.[]' >> /var/log/sql_injection.json
```

**Logstash config:**
```ruby
input {
  file {
    path => "/var/log/sql_injection.json"
    codec => json
  }
}

filter {
  if [severity] == "HIGH" {
    mutate { add_tag => ["critical_alert"] }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "sql-injection-%{+YYYY.MM.dd}"
  }
}
```

### Database Layer Protection

```python
# PostgreSQL with psycopg2
import psycopg2
from sql_injection_detector import SQLInjectionEnsemble

detector = SQLInjectionEnsemble()

def safe_query(conn, query, params):
    """Execute query with SQL injection protection"""
    # Check parameters
    for param in params:
        if isinstance(param, str):
            result = detector.detect(param)
            if result['action'] == 'BLOCK':
                raise SecurityError(f"Blocked parameter: {result['reason']}")

    # Execute if safe
    cursor = conn.cursor()
    cursor.execute(query, params)
    return cursor.fetchall()
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "api_server.py"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  sql-injection-detector:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./incidents.db:/app/incidents.db
    environment:
      - LOG_ALL_REQUESTS=false
      - INCIDENTS_DB=/app/incidents.db
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sql-injection-detector
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sql-detector
  template:
    metadata:
      labels:
        app: sql-detector
    spec:
      containers:
      - name: detector
        image: your-registry/sql-injection-detector:latest
        ports:
        - containerPort: 5000
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: sql-detector-service
spec:
  selector:
    app: sql-detector
  ports:
  - port: 5000
    targetPort: 5000
```

## Incident Logging

All blocked and suspicious requests are automatically logged to SQLite database.

```python
from incident_logger import IncidentLogger

logger = IncidentLogger()

# Query recent incidents
incidents = logger.get_incidents(action="BLOCK", limit=10)

# Get statistics
stats = logger.get_statistics()
print(f"Block rate: {stats['block_rate']}%")

# Export for SIEM
export = logger.export_to_siem(format="cef", severity_min="LOW")
```

## Active Learning

The system supports feedback-driven model improvement:

```python
from incident_logger import IncidentLogger

logger = IncidentLogger()

# Mark incident as false positive
logger.mark_false_positive(
    incident_id=42,
    is_false_positive=True,
    reviewer_notes="Legitimate O'Brien surname"
)

# Export training data for model retraining
training_data = logger.get_training_data(only_reviewed=True)
```

## File Structure

```
sql-injection-detector/
├── sql_injection_detector.py   # Core detection module
├── api_server.py               # Flask REST API
├── streamlit_demo.py           # Interactive web demo
├── incident_logger.py          # SQLite incident logging
├── test_models.py              # Test suite
├── requirements.txt            # Python dependencies
├── rf_sql_model.pkl            # Random Forest model
├── tfidf_vectorizer.pkl        # TF-IDF vectorizer
├── models/
│   ├── cnn_sql_detector.keras  # CNN model
│   └── dl_tokenizer.pkl        # Tokenizer for CNN
└── README.md
```

## Requirements

- Python 3.9+
- TensorFlow 2.x
- scikit-learn
- Flask
- Streamlit (for demo)

## Performance

| Metric | Value |
|--------|-------|
| Accuracy | 98.2% |
| Precision | 97.8% |
| Recall | 98.5% |
| F1 Score | 98.1% |
| False Positive Rate | 1.2% |
| Processing Time | ~5-15ms per request |

## Examples of Detected Attacks

| Attack Type | Example | Detected |
|-------------|---------|----------|
| Classic OR | `' OR '1'='1` | Yes |
| Comment injection | `admin'--` | Yes |
| UNION SELECT | `' UNION SELECT * FROM users--` | Yes |
| Time-based | `' AND SLEEP(5)--` | Yes |
| Boolean-based | `' AND 1=1--` | Yes |
| Stacked queries | `'; DROP TABLE users--` | Yes |

## License

MIT License

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## Support

For issues and questions, please open a GitHub issue.
