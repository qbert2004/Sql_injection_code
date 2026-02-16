# SQL Injection Detection Agent

Multi-layer SQL injection detection system using an ensemble of machine learning models (Random Forest + VDCNN) combined with semantic SQL validation.

## Features

- **4-class classification**: SAFE, INVALID, SUSPICIOUS, INJECTION
- **Ensemble ML**: Random Forest (TF-IDF + features) + VDCNN (char-level deep CNN)
- **6-layer pipeline**: Normalization -> Lexical Pre-filter -> ML Ensemble -> Semantic Validation -> Severity Classification -> Explainability
- **Low False Positives**: INVALID class for malformed but harmless input
- **Architectural invariant**: ML alone cannot classify as INJECTION without semantic confirmation
- **REST API**: FastAPI server for easy integration
- **Incident Logging**: SQLite database with SIEM export (CEF format)
- **Active Learning**: Feedback loop for model improvement

## Model Performance

### VDCNN-9 (Primary Deep Learning Model)

| Metric | Value |
|--------|-------|
| **Test Accuracy** | 99.90% |
| **Precision** | 99.93% |
| **Recall** | 99.85% |
| **F1 Score** | 99.89% |
| **ROC-AUC** | 99.97% |
| **FPR** | 0.055% |
| **Parameters** | 7,003,089 |
| **Architecture** | Conneau et al. 2017 (depth=9) |
| **Training** | CUDA + AMP, 35 epochs, 6.1 min |

### Random Forest (Secondary Model)

| Metric | Value |
|--------|-------|
| **Test Accuracy** | 99.18% |
| **Precision** | 99.96% |
| **Recall** | 98.26% |
| **F1 Score** | 99.10% |
| **ROC-AUC** | 99.97% |
| **FPR** | 0.031% |

### Ensemble System (End-to-End)

| Metric | Value |
|--------|-------|
| **Attack Detection Rate** | 99.3% (134/135 payloads) |
| **False Positive Rate** | 1.5% (1/68 safe inputs) |
| **Average Latency** | ~51ms per request (CPU) |
| **Pytest Suite** | 148/148 passed |

## Architecture

```
Input -> Normalization -> Lexical Pre-filter -> ML Ensemble (RF + VDCNN)
      -> SQL Semantic Validation -> Decision Engine -> Severity/Action Mapping
      -> Explainability Output
```

```
                    +------------------+
                    |   User Input     |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  Normalization   |  URL decode, null-byte strip,
                    |  (Layer 0)       |  comment removal, lowercase
                    +--------+---------+
                             |
                    +--------v---------+
                    | Lexical Filter   |  Fast-path: skip ML if no
                    | (Layer 1)        |  SQL indicators detected
                    +--------+---------+
                             |
            +----------------+----------------+
            |                                 |
   +--------v--------+              +---------v--------+
   | Random Forest   |              |   VDCNN-9        |
   | (TF-IDF + feat) |              | (char-level CNN) |
   | w_rf = 0.35     |              | w_cnn = 0.65     |
   +--------+--------+              +---------+--------+
            |                                 |
            +----------------+----------------+
                             |
                    +--------v---------+
                    | Semantic Analyzer|  SQL pattern validation
                    | (Layer 3)        |  structural_validity check
                    +--------+---------+
                             |
                    +--------v---------+
                    | Decision Engine  |  S = 0.65*P_cnn + 0.35*P_rf
                    | (Layer 4)        |  + semantic gate
                    +--------+---------+
                             |
                    +--------v---------+
                    |    Output        |
                    | Decision/Action/ |
                    | Severity/Explain |
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

**Core invariant**: ML scores alone never classify as INJECTION. Semantic score >= threshold is always required.

**Actions:**
- `ALLOW`: Request passes through
- `LOG`: Log for analysis, allow through
- `CHALLENGE`: Require CAPTCHA or additional verification
- `BLOCK`: Block the request (all INJECTION decisions)

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
print(f"Score: {result['score']:.2f}")    # 1.00
print(f"Severity: {result['severity']}")  # MEDIUM
print(f"Attack: {result['attack_type']}") # BOOLEAN_BASED
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

### 5. Train Models

```bash
# Train VDCNN (requires CUDA GPU)
python training/train_cnn.py --epochs 50

# Train BiLSTM
python training/train_bilstm.py

# Train Random Forest
python training/train_rf.py
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

### Export for SIEM

```bash
GET /api/export?format=cef&severity_min=LOW
```

## File Structure

```
sql-injection-detector/
├── sql_injection_detector.py   # Core detection module (6-layer pipeline)
├── api_server.py               # FastAPI REST API server
├── config.py                   # Centralized configuration
├── incident_logger.py          # SQLite incident logging + SIEM export
├── logger.py                   # Structured logging (structlog)
├── streamlit_demo.py           # Interactive web demo
├── rf_sql_model.pkl            # Random Forest model
├── tfidf_vectorizer.pkl        # TF-IDF vectorizer
├── models/
│   ├── char_cnn_model.py       # VDCNN architecture (Conneau et al. 2017)
│   ├── char_bilstm_model.py    # BiLSTM architecture
│   ├── char_tokenizer.py       # ASCII character tokenizer
│   ├── char_cnn_detector.pt    # Trained VDCNN-9 checkpoint
│   ├── char_bilstm_detector.pt # Trained BiLSTM checkpoint
│   └── char_tokenizer.json     # Tokenizer config
├── training/
│   ├── train_cnn.py            # VDCNN training script (CUDA + AMP)
│   ├── train_bilstm.py         # BiLSTM training script
│   ├── train_rf.py             # Random Forest training script
│   └── generate_dataset.py     # Dataset generation
├── data/
│   ├── dataset.csv             # Training dataset
│   └── massive_test_100k.csv   # 100k benchmark dataset
├── tests/
│   ├── test_detector.py        # Main pytest suite (148 tests)
│   ├── stress_test.py          # Concurrent load testing
│   └── benchmark_cnn_cuda.py   # CUDA inference benchmark
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Pytest configuration
└── README.md
```

## Requirements

- Python 3.10+
- PyTorch 2.x (with CUDA for training)
- scikit-learn
- FastAPI + Uvicorn
- Streamlit (for demo)

## Examples of Detected Attacks

| Attack Type | Example | Detected | Severity |
|-------------|---------|----------|----------|
| Classic OR | `' OR '1'='1` | BLOCK | MEDIUM |
| Comment injection | `admin'--` | BLOCK | LOW |
| UNION SELECT | `' UNION SELECT * FROM users--` | BLOCK | HIGH |
| Time-based | `' AND SLEEP(5)--` | BLOCK | MEDIUM |
| Boolean-based | `' AND 1=1--` | BLOCK | MEDIUM |
| Stacked queries | `'; DROP TABLE users--` | BLOCK | CRITICAL |
| OS command | `; EXEC xp_cmdshell('dir')--` | BLOCK | CRITICAL |
| Obfuscated | `'/**/OR/**/1=1--` | BLOCK | LOW |
| URL encoded | `%27%20OR%201=1--` | BLOCK | MEDIUM |
| Parenthesis bypass | `') or ('1'='1` | BLOCK | MEDIUM |

## Testing

```bash
# Run full test suite
pytest tests/ -v

# Run global integration test
python global_test.py

# Run comprehensive stress test
python ultimate_test.py

# Run stress/load test
python stress_test.py
```

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
