# SQL Injection Protector AI Agent — Production Architecture (10/10)

## Current State Assessment

| Layer | Current Implementation | Maturity |
|-------|----------------------|----------|
| Pre-filter | `SQLSemanticAnalyzer` with URL-decode + comment stripping | 6/10 |
| ML Classic | Random Forest + TF-IDF (alpha=0.35) | 5/10 |
| ML Deep | CNN char-level (alpha=0.65), BiLSTM trained but unused | 5/10 |
| Decision Engine | 8-rule priority cascade with semantic gating | 7/10 |
| Classification | 4-class (SAFE/INVALID/SUSPICIOUS/INJECTION) | 7/10 |
| Severity | Mapped from action, not from attack type | 3/10 |
| Explainability | Rule name + scores in result dict | 4/10 |
| Logging/SIEM | SQLite + CEF/CSV/JSON export | 7/10 |
| API | Flask (not FastAPI), no auth, no rate limiting | 4/10 |
| Tests | 500+ payloads across 4 scripts, not pytest-compatible | 6/10 |
| Training pipeline | Missing entirely | 0/10 |
| Config management | Hardcoded `EnsembleConfig`, dead `.env` | 2/10 |

**Overall: ~5/10 — solid MVP, not production-grade.**

---

## 1. Architecture Upgrade — Final Layered Design

### Target Architecture

```
Input (raw string)
   │
   ▼
┌──────────────────────────────────────────┐
│  LAYER 0: INPUT NORMALIZATION            │
│  Unicode NFKC → URL decode (recursive)   │
│  → HTML entity decode → null-byte strip  │
│  → homoglyph normalization → lowercase   │
│  → comment removal → whitespace collapse │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  LAYER 1: LEXICAL / HEURISTIC PRE-FILTER │
│  Fast regex + keyword scan               │
│  Output: is_sql_like (bool),             │
│          lexical_score (0-20),           │
│          matched_patterns (list)         │
└──────────────┬───────────────────────────┘
               │
        ┌──────┴──────┐
        │             │
   lexical_score=0   lexical_score>0
        │             │
        ▼             ▼
   FAST PATH     ┌────────────────────────────────┐
   → SAFE        │  LAYER 2: ML ENSEMBLE           │
                 │  ┌──────────┐ ┌───────────────┐ │
                 │  │ RF+TF-IDF│ │ Char-CNN      │ │
                 │  │ (P_rf)   │ │ (P_cnn)       │ │
                 │  └────┬─────┘ └──────┬────────┘ │
                 │       │              │           │
                 │       ▼              ▼           │
                 │  ┌────────────────────────────┐  │
                 │  │ Weighted Fusion             │  │
                 │  │ S = α·P_cnn + β·P_rf       │  │
                 │  │ + model agreement bonus     │  │
                 │  └────────────┬───────────────┘  │
                 └───────────────┼──────────────────┘
                                 │
                                 ▼
               ┌──────────────────────────────────────┐
               │  LAYER 3: SQL SEMANTIC VALIDATION     │
               │  Parse SQL structure, not just keywords│
               │  Validate: does this input contain     │
               │  syntactically meaningful SQL logic?   │
               │  Output: semantic_score, attack_type,  │
               │          structural_validity (bool)    │
               └──────────────┬───────────────────────┘
                              │
                              ▼
               ┌──────────────────────────────────────┐
               │  LAYER 4: DECISION ENGINE             │
               │  Combines: ML score, semantic score,  │
               │  lexical features, model agreement    │
               │  Constraint: ML alone CANNOT classify │
               │  as INJECTION without semantic >= 2   │
               └──────────────┬───────────────────────┘
                              │
                              ▼
               ┌──────────────────────────────────────┐
               │  LAYER 5: SEVERITY & ACTION MAPPING   │
               │  Attack-type-aware severity            │
               │  (not just decision-based)            │
               └──────────────┬───────────────────────┘
                              │
                              ▼
               ┌──────────────────────────────────────┐
               │  LAYER 6: EXPLAINABILITY MODULE       │
               │  Human-readable decision trace        │
               │  SIEM-ready structured output         │
               │  Feature attribution per model        │
               └──────────────────────────────────────┘
```

### Why Each Layer Exists

| Layer | Purpose | Must Never Do |
|-------|---------|---------------|
| **L0: Normalization** | Defeat encoding-based evasion (double URL-encode, Unicode homoglyphs, null bytes). Every downstream layer sees a canonical form. | Must never alter semantic meaning of legitimate input. Must never silently drop characters that change meaning. |
| **L1: Lexical Pre-Filter** | Fast-path rejection of clearly safe input (plain text, numbers, simple names). Avoids expensive ML inference for 95%+ of traffic. | Must never classify anything as INJECTION. It only produces SAFE or NEEDS_ANALYSIS. A pre-filter that blocks is a false-positive factory. |
| **L2: ML Ensemble** | Detect patterns invisible to regex: obfuscated payloads, novel attack vectors, adversarial variations. Generalize beyond known signatures. | Must never be the sole authority on INJECTION. ML confidence without semantic confirmation is unreliable (random strings trigger CNNs). |
| **L3: Semantic Validation** | Verify that the input contains structurally meaningful SQL logic. This is the false-positive kill switch. | Must never approve input based on "looks safe." Its job is to confirm or deny SQL structure. Must never be skipped or overridden by ML alone. |
| **L4: Decision Engine** | Fuse signals with explicit priority rules. Resolve conflicts between ML and semantic layers. | Must never use a single threshold. Must never ignore model disagreement. Must never classify without considering all three signal sources. |
| **L5: Severity Mapping** | Map attack type to operational severity. A `DROP TABLE` is not the same as a boolean probe. | Must never assign severity based only on confidence score. Must use attack type. |
| **L6: Explainability** | Provide auditable, structured decision traces for SOC analysts, compliance officers, and academic reviewers. | Must never produce opaque "score: 0.87" without explaining what drove the score. |

### Critical Architectural Invariant

```
INJECTION decision requires:
  (ML_ensemble_score >= tau_high AND semantic_score >= tau_semantic_min)
  OR
  (semantic_score >= tau_semantic_override)

ML alone → never INJECTION.
Semantic alone (high score) → can override ML (catches regex-invisible stacked queries).
```

This invariant is already partially implemented in your current `_ensemble_decision()` rules but must be formalized as an inviolable constraint.

---

## 2. ML Improvements

### 2.1 Current Model Assessment

| Model | Strengths | Weaknesses |
|-------|-----------|------------|
| **RF + TF-IDF** | Good on known patterns; interpretable; fast inference | Bag-of-words loses token order; weak on obfuscation; TF-IDF vocabulary is fixed at training time |
| **Char-CNN** | Captures local character patterns; somewhat robust to obfuscation | High false-positive rate on random/garbage input (any unusual char sequence triggers it); no global context |
| **BiLSTM** | Trained but unused; captures sequential dependencies | Not integrated into ensemble; slower inference than CNN |

### 2.2 Recommended Model Stack

```
TIER 1 — Fast Models (< 5ms inference)
├── RF + TF-IDF (keep, retrain with better features)
└── Char-level CNN (keep, retrain with INVALID class in training data)

TIER 2 — Contextual Model (< 50ms inference)
└── BiLSTM with attention (integrate the existing model, add attention layer)

TIER 3 — Optional Heavy Model (< 200ms, async)
└── Fine-tuned DistilBERT or CodeBERT on SQL/injection corpus
    (only for ambiguous cases where Tier 1+2 disagree)
```

### 2.3 Specific Model Recommendations

**a) RF + TF-IDF — Upgrade Features**

Current TF-IDF uses word-level tokenization. Add:
- Character n-gram TF-IDF (2-5 grams) as a separate feature set
- Structural features: parenthesis depth, quote balance, semicolon count, comment marker count
- Token entropy: Shannon entropy of character distribution (random strings have high entropy, SQL has structured entropy)
- SQL keyword density: ratio of SQL keywords to total tokens

```
Feature vector = [
  TF-IDF_word(input),          # existing
  TF-IDF_char_ngram(input),    # new: captures obfuscation patterns
  structural_features(input),   # new: 8-10 numeric features
  token_entropy(input),         # new: distinguishes SQL from random
  keyword_density(input),       # new: ratio feature
]
```

**b) Char-CNN — Architecture Fix**

Current problem: CNN fires on any "unusual" character sequence, including garbage input like `!!!@@@###`. This is because the CNN was trained on a binary dataset (safe vs. injection) and learned "anything not normal English = injection."

Fix: Retrain with a 3-class dataset:
- Class 0: SAFE (normal user input)
- Class 1: INVALID (random characters, encoding artifacts, malformed data)
- Class 2: INJECTION (actual SQL injection payloads)

Architecture suggestion (keep it small for latency):
```
Input: char sequence, maxlen=300
→ Embedding(charset_size=128, dim=32)
→ Conv1D(64, kernel=3) + ReLU + MaxPool
→ Conv1D(128, kernel=5) + ReLU + MaxPool
→ Conv1D(128, kernel=7) + ReLU + GlobalMaxPool
→ Dense(64, ReLU) + Dropout(0.3)
→ Dense(3, softmax)  ← 3-class output
```

The multi-kernel sizes (3, 5, 7) capture different pattern scales: single SQL operators (3), short keywords (5), and compound patterns like `UNION SELECT` (7).

**c) BiLSTM — Integration**

The existing BiLSTM model should be integrated into the ensemble. BiLSTM captures sequential dependencies that CNN misses (e.g., `' OR 1=1--` where the quote-OR-tautology-comment sequence matters).

Add an attention mechanism to make it explainable:
```
Input: tokenized sequence
→ Embedding(dim=64)
→ BiLSTM(128) → attention weights
→ Dense(64, ReLU)
→ Dense(3, softmax)  ← 3-class output

Attention weights → which tokens drove the decision (explainability)
```

**d) Optional: Fine-tuned DistilBERT**

For the highest accuracy tier, fine-tune `distilbert-base-uncased` or `microsoft/codebert-base` on SQL injection data. This captures deep contextual semantics that character-level models miss.

Use only for ambiguous cases (ensemble disagreement) due to latency cost (~100-200ms).

### 2.4 Ensemble Fusion Logic

```python
# Tier 1: Fast consensus
P_rf   = rf_model.predict_proba(x)
P_cnn  = cnn_model.predict_proba(x)  # now 3-class

# Tier 2: Sequential context
P_lstm = bilstm_model.predict_proba(x)  # 3-class

# Agreement bonus
agreement = 1.0 if all models agree on argmax else 0.0

# Weighted fusion
S_injection = (
    w_rf   * P_rf[INJECTION]   +    # w_rf   = 0.25
    w_cnn  * P_cnn[INJECTION]  +    # w_cnn  = 0.35
    w_lstm * P_lstm[INJECTION]      # w_lstm = 0.40
) * (1 + 0.1 * agreement)

S_invalid = (
    w_rf   * P_rf[INVALID]   +
    w_cnn  * P_cnn[INVALID]  +
    w_lstm * P_lstm[INVALID]
)

S_safe = 1.0 - S_injection - S_invalid
```

BiLSTM gets the highest weight (0.40) because sequential context is most discriminative for SQL injection. CNN gets 0.35 for pattern detection. RF gets 0.25 as a regularizer (bag-of-words acts as an independent signal that reduces correlated errors).

### 2.5 ML Confidence Constrained by Semantics

**Hard rule: ML score is necessary but not sufficient.**

```python
def constrained_decision(S_injection, semantic_score):
    if S_injection >= 0.60 and semantic_score >= 2.0:
        return INJECTION  # both agree
    if S_injection >= 0.60 and semantic_score < 2.0:
        return INVALID    # ML says yes, semantics says no → garbage input
    if S_injection < 0.40 and semantic_score >= 6.0:
        return INJECTION  # semantic override for regex-invisible attacks
    if S_injection < 0.30:
        return SAFE
    return SUSPICIOUS     # ambiguous zone
```

### 2.6 Handling Obfuscation, Encoding, Noise

| Technique | Defense |
|-----------|---------|
| URL encoding (`%27`, `%20`) | Recursive URL decode in L0 (already implemented) |
| Double encoding (`%2527`) | Recursive decode with max depth=3 |
| Unicode homoglyphs (`ＳＥＬＥＣＴα`) | NFKC normalization + homoglyph mapping table |
| Comment insertion (`UN/**/ION`) | Comment stripping in L0 (already implemented) |
| Case alternation (`SeLeCt`) | Lowercase in L0 (already implemented) |
| No-space bypass (`UNION(SELECT)`) | Regex patterns in semantic analyzer (partially implemented) |
| Null bytes (`SE%00LECT`) | Null byte stripping in L0 |
| Concatenation (`CONC`+`AT`) | Char-CNN handles this naturally; add concat-aware regex |
| Hex encoding (`0x41444D494E`) | Hex literal detection in semantic analyzer |
| Scientific notation (`1e309`) | Numeric overflow detection |

---

## 3. SQL Semantic Validation (Critical Section)

### 3.1 Definition: What Constitutes SQL Logic

An input contains SQL logic if and only if it contains **at least one** of the following structural elements in a syntactically meaningful arrangement:

| Category | Structural Element | Example | Score |
|----------|--------------------|---------|-------|
| **SQL Statement** | Complete or partial SQL statement keyword followed by valid SQL clause structure | `SELECT * FROM users` | +5 |
| **Logic Manipulation** | Boolean operator combined with comparison that forms a tautology or contradiction | `' OR 1=1`, `' AND ''='` | +4 |
| **Query Termination** | Input that terminates an existing query context and begins a new one | `'; DROP TABLE--` | +5 |
| **Data Extraction** | UNION-based column alignment attempt | `' UNION SELECT null,null--` | +5 |
| **Subquery** | Nested SELECT in parentheses | `(SELECT password FROM users)` | +4 |
| **SQL Function Call** | Database function invoked with parentheses and arguments | `SLEEP(5)`, `BENCHMARK(1e7,SHA1('x'))` | +4 |
| **Comment Termination** | SQL comment marker used to truncate a query | `admin'--`, `1; --` | +2 |
| **Stacked Query** | Semicolon followed by a new SQL statement | `1; DROP TABLE users` | +5 |
| **Conditional Logic** | IF/CASE/WHEN used to branch query behavior | `IF(1=1,'a','b')` | +3 |

### 3.2 What Must NEVER Be Classified as SQL Injection

| Input Type | Why It Is Not SQLi | Example |
|------------|-------------------|---------|
| **Lone quotes** | A single quote without surrounding SQL logic is just a character | `O'Brien`, `it's`, `5'11"` |
| **Random characters** | No SQL structural meaning | `!!!@@@###$$$` |
| **SQL keywords in natural language** | Words like "select", "drop", "table", "union" appear in English | `Please select an option from the drop-down table` |
| **Partial SQL fragments without logic** | A keyword alone is not an attack | `SELECT`, `FROM`, `WHERE` (alone) |
| **Numeric comparisons in normal context** | `1=1` alone is not SQLi without query context (quote prefix, OR/AND) | `score=100`, `page=1` |
| **Encoded strings that decode to safe content** | `%48%65%6C%6C%6F` = "Hello" | Safe after decoding |
| **Programming code snippets** | Code that contains SQL keywords but is not injected into a query context | `cursor.execute("SELECT * FROM users")` |
| **Error messages containing SQL** | Error text quoting SQL syntax | `Error: near "SELECT": syntax error` |

### 3.3 Semantic Score Computation — Correct Algorithm

```python
def compute_semantic_score(normalized_input: str) -> SemanticResult:
    score = 0
    attack_type = None
    structural_validity = False
    evidence = []

    # Step 1: Detect SQL statement structure (keyword + clause)
    # NOT just keyword presence — keyword + structural context
    if has_statement_structure(input):
        score += 5
        structural_validity = True
        evidence.append("Complete SQL statement structure detected")

    # Step 2: Detect tautology patterns
    # Require: quote_or_boundary + boolean_op + always_true_comparison
    tautology = detect_tautology(input)
    if tautology:
        score += 4
        structural_validity = True
        attack_type = "BOOLEAN_BASED"
        evidence.append(f"Tautology: {tautology.pattern}")

    # Step 3: Detect UNION-based extraction
    # Require: UNION + SELECT + at least one column expression
    if detect_union_select(input):
        score += 5
        structural_validity = True
        attack_type = "UNION_BASED"
        evidence.append("UNION SELECT with column alignment")

    # Step 4: Detect stacked queries
    # Require: semicolon + new SQL statement keyword
    if detect_stacked_query(input):
        score += 5
        structural_validity = True
        attack_type = "STACKED_QUERY"
        evidence.append("Stacked query detected")

    # Step 5: Detect time-based blind
    # Require: SLEEP/BENCHMARK/WAITFOR/pg_sleep + numeric argument
    if detect_time_function(input):
        score += 4
        structural_validity = True
        attack_type = "TIME_BASED"
        evidence.append("Time-based blind injection function")

    # Step 6: Detect error-based extraction
    # Require: EXTRACTVALUE/UPDATEXML/CONVERT/CAST in injection context
    if detect_error_function(input):
        score += 4
        structural_validity = True
        attack_type = "ERROR_BASED"
        evidence.append("Error-based extraction function")

    # Step 7: Detect comment-based truncation
    # Require: payload + comment marker (-- or /* or #)
    # Only scores if OTHER SQL elements are also present
    if detect_comment_truncation(input) and score > 0:
        score += 2
        evidence.append("Comment-based query truncation")

    # Step 8: Detect SQL operator context
    # Only count operators that appear in SQL-like context
    # NOT standalone || in shell or && in JS
    if detect_sql_operator_context(input):
        score += 2
        evidence.append("SQL operators in injection context")

    return SemanticResult(
        score=score,
        attack_type=attack_type,
        structural_validity=structural_validity,
        evidence=evidence
    )
```

### 3.4 How to Avoid False Positives from Quotes and Noise

**The Quote Problem:** Your current analyzer gives +2 for any tautology match, but `O'Brien` contains a quote that could partial-match patterns.

**Solution: Context-Aware Quote Analysis**

```python
def is_quote_in_sql_context(input: str, quote_pos: int) -> bool:
    """A quote is in SQL context only if followed by SQL logic."""
    after_quote = input[quote_pos + 1:].strip()

    # Quote followed by SQL boolean operator + comparison → SQL context
    if re.match(r'\s*(OR|AND)\s+.+[=<>]', after_quote, re.I):
        return True

    # Quote followed by comment marker → SQL context
    if re.match(r'\s*(--|#|/\*)', after_quote):
        return True

    # Quote followed by semicolon + SQL keyword → SQL context
    if re.match(r'\s*;\s*(SELECT|DROP|INSERT|UPDATE|DELETE)', after_quote, re.I):
        return True

    # Quote in a name-like context (preceded by letter, followed by letter) → NOT SQL
    before = input[:quote_pos]
    if before and before[-1].isalpha() and after_quote and after_quote[0].isalpha():
        return False  # O'Brien, it's, don't

    return False
```

**The Keyword-in-English Problem:** "Please select from the drop-down" should not score.

**Solution: Keyword Proximity Scoring**

SQL keywords only score when they appear near other SQL elements:
```python
def keyword_in_sql_context(keyword: str, input: str) -> bool:
    """A SQL keyword is meaningful only with surrounding SQL structure."""
    pos = input.lower().find(keyword.lower())
    window = input[max(0, pos-20):pos+len(keyword)+20]

    # Keyword near other SQL keywords → SQL context
    other_keywords = ['select', 'from', 'where', 'union', 'insert', 'update',
                      'delete', 'drop', 'or', 'and']
    nearby_sql = sum(1 for k in other_keywords
                     if k != keyword.lower() and k in window.lower())
    if nearby_sql >= 1:
        return True

    # Keyword near SQL operators (=, <>, ', ;, --)
    if re.search(r'[=<>;\'\"()]', window):
        return True

    return False
```

---

## 4. Classification Logic — 3-Class System

### 4.1 Class Definitions

| Class | Definition | ML Behavior | Semantic Behavior |
|-------|-----------|-------------|-------------------|
| **SAFE** | Input contains no SQL structural elements. It is normal user data (names, text, numbers, search queries). | All models output P(injection) < 0.30 | semantic_score = 0 |
| **INVALID** | Input is malformed, random, or contains unusual characters but has no SQL semantic meaning. ML models may produce high scores due to unusual character distributions, but semantic analysis confirms no SQL structure. | One or more models may output P(injection) > 0.50 | semantic_score < 2 |
| **INJECTION** | Input contains structurally meaningful SQL logic intended to manipulate a query. Both ML models and semantic analysis agree (or semantic score is overwhelming). | Ensemble score >= 0.40 (with semantic confirmation) OR any score (with semantic >= 6) | semantic_score >= 2 AND structural_validity = True |

### 4.2 Typical Examples Per Class

**SAFE:**
```
"John Smith"                          → name, no SQL
"search for blue shoes"               → search query
"2024-01-15"                          → date
"user@example.com"                    → email
"The quick brown fox"                 → prose
"Order #12345"                        → order reference
"Please select an option"             → English sentence with SQL keyword
"price > 100"                         → comparison without SQL context
```

**INVALID:**
```
"!!!@@@###$$$%%%"                     → random symbols
"asdkjfhaskjdfh"                     → random characters
"%80%81%82%83"                        → invalid encoding
"<script>alert(1)</script>"           → XSS (not SQLi)
"../../../../etc/passwd"              → path traversal (not SQLi)
"{{7*7}}"                             → SSTI (not SQLi)
""                                    → empty input
"NULL"                                → the word null
```

**INJECTION:**
```
"' OR 1=1--"                          → boolean-based auth bypass
"' UNION SELECT username,password FROM users--" → data extraction
"'; DROP TABLE users--"               → destructive stacked query
"' AND SLEEP(5)--"                    → time-based blind
"' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--" → error-based
"admin'--"                            → comment truncation bypass
"1; EXEC xp_cmdshell('whoami')"      → OS command via MSSQL
"' OR '1'='1' /*"                     → inline comment tautology
```

### 4.3 Recommended Action Per Class

| Class | Action | HTTP Response | Log Level |
|-------|--------|---------------|-----------|
| SAFE | `ALLOW` | Pass through | DEBUG (optional) |
| INVALID | `LOG` | Pass through (sanitized) | INFO |
| INJECTION | `BLOCK` | 403 Forbidden | CRITICAL |

Note: SUSPICIOUS (your current 4th class) maps to `CHALLENGE` — this is valid for cases where semantic_score is 1-2 and ML score is 0.40-0.60. Keep it as an operational class but it is not a primary classification target.

---

## 5. Severity Model

### 5.1 Attack-Type-Based Severity

The current system maps severity from action (BLOCK→HIGH, CHALLENGE→MEDIUM). This is wrong. Severity must come from attack type, because a blocked boolean probe and a blocked `DROP TABLE` have vastly different risk profiles.

| Severity | Attack Types | Risk Description | CVSS Analog |
|----------|-------------|-----------------|-------------|
| **CRITICAL** | Stacked queries with DDL/DML (`DROP`, `DELETE`, `TRUNCATE`, `ALTER`), OS command execution (`xp_cmdshell`, `LOAD_FILE`, `INTO OUTFILE`) | Data destruction or system compromise | 9.0-10.0 |
| **HIGH** | UNION-based extraction, Error-based extraction, Out-of-band (`UTL_HTTP`, `LOAD_FILE`) | Data exfiltration | 7.0-8.9 |
| **MEDIUM** | Time-based blind, Boolean-based blind, Conditional injection (`IF`, `CASE`) | Information disclosure (slow) | 4.0-6.9 |
| **LOW** | Authentication bypass (`' OR 1=1--`), Comment truncation without further payload | Logic manipulation | 2.0-3.9 |

### 5.2 Severity Detection Rules

```python
def classify_severity(attack_type: str, semantic_evidence: list) -> str:
    # CRITICAL: destructive or OS-level
    if attack_type == "STACKED_QUERY":
        destructive = ['drop', 'delete', 'truncate', 'alter', 'xp_cmdshell',
                       'exec', 'load_file', 'into outfile', 'into dumpfile']
        if any(d in normalized_input for d in destructive):
            return "CRITICAL"
        return "HIGH"

    # HIGH: data extraction
    if attack_type in ("UNION_BASED", "ERROR_BASED", "OUT_OF_BAND"):
        return "HIGH"

    # MEDIUM: blind techniques
    if attack_type in ("TIME_BASED", "BOOLEAN_BASED_BLIND", "CONDITIONAL"):
        return "MEDIUM"

    # LOW: simple bypass
    if attack_type in ("BOOLEAN_BASED", "COMMENT_TRUNCATION"):
        return "LOW"

    return "MEDIUM"  # unknown attack type defaults to MEDIUM
```

### 5.3 Severity → Action Mapping

| Severity | Action | Operational Response |
|----------|--------|---------------------|
| **CRITICAL** | `BLOCK` + `ALERT` | Block request. Send real-time alert to SOC. Log with full request context. Trigger incident response workflow. |
| **HIGH** | `BLOCK` + `LOG_URGENT` | Block request. Log as urgent. Include in hourly SOC digest. |
| **MEDIUM** | `BLOCK` + `LOG` | Block request. Standard logging. Review in daily report. |
| **LOW** | `CHALLENGE` or `BLOCK` | Configurable: challenge (CAPTCHA/re-auth) or soft block. Standard logging. |

---

## 6. Explainability & SOC Readiness

### 6.1 Decision Explanation Format

Every detection result must produce a structured explanation object:

```json
{
  "decision": "INJECTION",
  "confidence": 0.87,
  "severity": "HIGH",
  "action": "BLOCK",

  "explanation": {
    "summary": "UNION-based SQL injection detected with high confidence across all detection layers.",

    "layer_results": {
      "normalization": {
        "transformations_applied": ["url_decode", "lowercase", "comment_strip"],
        "original_length": 52,
        "normalized_length": 38
      },
      "lexical_prefilter": {
        "is_sql_like": true,
        "lexical_score": 8,
        "matched_keywords": ["union", "select", "from"],
        "matched_patterns": ["union_select", "comment_termination"]
      },
      "ml_ensemble": {
        "rf_score": 0.91,
        "cnn_score": 0.85,
        "bilstm_score": 0.88,
        "ensemble_score": 0.87,
        "model_agreement": true,
        "rf_top_features": ["tfidf_union: 0.42", "tfidf_select: 0.38", "keyword_density: 0.65"],
        "bilstm_attention_tokens": ["'", "union", "select", "password", "--"]
      },
      "semantic_validation": {
        "semantic_score": 9,
        "structural_validity": true,
        "attack_type": "UNION_BASED",
        "evidence": [
          "UNION SELECT with column alignment detected",
          "Comment-based query truncation at end of input",
          "Query targets sensitive column: 'password'"
        ]
      }
    },

    "decision_rule": "Rule 1: S >= 0.60 AND semantic_score >= 2.0 → INJECTION",
    "decision_factors": [
      "Ensemble score 0.87 exceeds high-confidence threshold 0.60",
      "Semantic score 9 exceeds minimum semantic threshold 2.0",
      "All three models agree on INJECTION class",
      "Attack type UNION_BASED maps to severity HIGH"
    ]
  },

  "siem_fields": {
    "event_id": "sqli-2024-001-a8f3",
    "timestamp": "2024-01-15T14:23:45.123Z",
    "event_category": "intrusion_detection",
    "event_type": "sql_injection",
    "event_severity": "high",
    "source_ip": "192.168.1.100",
    "source_port": 54321,
    "destination_endpoint": "/api/login",
    "http_method": "POST",
    "field_name": "username",
    "input_hash": "a8f3b2c1d4e5f6a7",
    "attack_type": "union_based",
    "mitre_technique": "T1190",
    "cve_reference": null,
    "detection_time_ms": 12.5,
    "models_used": ["rf_v2.1", "cnn_v1.3", "bilstm_v1.0"],
    "false_positive_probability": 0.02
  }
}
```

### 6.2 SIEM/SOC Required Fields

| Field | Source | Standard |
|-------|--------|----------|
| `event_id` | Generated UUID | Internal |
| `timestamp` | ISO 8601 UTC | RFC 3339 |
| `event_category` | Fixed: `intrusion_detection` | ECS (Elastic Common Schema) |
| `event_type` | `sql_injection` | ECS |
| `event_severity` | `low` / `medium` / `high` / `critical` | ECS |
| `source_ip` | Request header | ECS `source.ip` |
| `destination_endpoint` | Request URL path | ECS `url.path` |
| `http_method` | Request method | ECS `http.request.method` |
| `attack_type` | Semantic analyzer output | Custom |
| `mitre_technique` | `T1190` (Exploit Public-Facing Application) | MITRE ATT&CK |
| `detection_time_ms` | Measured | Custom |
| `ensemble_score` | ML ensemble output | Custom |
| `semantic_score` | Semantic analyzer output | Custom |
| `models_used` | Model version strings | Custom |
| `input_hash` | SHA-256 truncated | Custom |

### 6.3 CEF (Common Event Format) Output

Already partially implemented in `incident_logger.py`. Recommended format:

```
CEF:0|SQLIProtector|EnsembleDetector|2.0|SQLI_UNION|UNION-based SQL Injection|8|
  src=192.168.1.100
  dst=/api/login
  act=BLOCK
  msg=UNION SELECT detected with 3-model agreement
  cs1=0.87 cs1Label=EnsembleScore
  cs2=9 cs2Label=SemanticScore
  cs3=UNION_BASED cs3Label=AttackType
  cn1=12 cn1Label=DetectionTimeMs
```

### 6.4 Explanation for Auditors and Academic Review

For academic/audit contexts, provide a methodology explanation alongside each detection:

```
DETECTION METHODOLOGY:
1. Input underwent 6-stage normalization (URL decode, NFKC, null strip,
   homoglyph map, lowercase, comment strip).
2. Lexical pre-filter identified 3 SQL keywords in structural context.
3. Three independent ML models (RF, CNN, BiLSTM) produced injection
   probabilities of 0.91, 0.85, 0.88 respectively (weighted ensemble: 0.87).
4. SQL semantic validator confirmed structural validity: UNION keyword
   followed by SELECT with column list, terminated by comment marker.
5. Attack classified as UNION_BASED with severity HIGH per attack
   taxonomy (data exfiltration capability).
6. Decision rule applied: Rule 1 (high-confidence with semantic confirmation).
7. False positive probability estimated at 0.02 based on validation set
   performance for this attack class.
```

---

## 7. Dataset & Training Strategy

### 7.1 Dataset Composition

The current `SQL_Dataset_Extended.csv` is a single file. A production training pipeline needs:

| Dataset | Source | Purpose | Size Target |
|---------|--------|---------|-------------|
| **Safe inputs** | Common Crawl excerpts, form submission logs (anonymized), name databases, search query logs | Negative class: normal user input | 50,000+ |
| **SQL injections** | SQLMap tamper payloads, PayloadsAllTheThings, OWASP testing guide, HackTricks, real WAF logs (anonymized) | Positive class: actual attacks | 30,000+ |
| **Invalid/Malformed** | Random string generator, encoding fuzzer, XSS payloads, path traversal, SSTI payloads, binary data | Third class: not safe, not SQLi | 20,000+ |
| **Adversarial** | Quote-heavy safe inputs (`O'Brien`, `it's`), English text with SQL keywords (`select from the dropdown`), programming code snippets | Hard negatives for FP reduction | 10,000+ |

**Total: 110,000+ samples minimum, 3-class labeled.**

### 7.2 Avoiding Dataset Bias

| Bias | Problem | Mitigation |
|------|---------|------------|
| **Quote bias** | Dataset has quotes only in SQLi samples → model learns quote = injection | Include 5,000+ safe inputs with legitimate quotes (names, contractions, measurements) |
| **Keyword bias** | "SELECT" only appears in attacks → "please select an option" becomes FP | Include 3,000+ safe inputs containing SQL keywords in natural language context |
| **Length bias** | Injections tend to be longer → long normal input gets flagged | Balance length distribution across classes; include long safe inputs (paragraphs, addresses) |
| **Character set bias** | Special characters only in attacks → password input `P@ssw0rd!` gets flagged | Include safe inputs with special characters (passwords, URLs, file paths, math expressions) |
| **Encoding bias** | URL-encoded strings only in attacks → legitimate encoded form data gets flagged | Include safe URL-encoded form submissions |
| **Language bias** | Only English safe samples → non-English input treated as suspicious | Include safe inputs in multiple languages, especially those with characters similar to SQL syntax |

### 7.3 Validation Strategy

```
Dataset split:
├── Train:      70% (stratified by class AND by attack type)
├── Validation: 15% (same stratification)
└── Test:       15% (same stratification)

Additional held-out sets:
├── FP Stress Test:  500 adversarial safe inputs (quotes, keywords, special chars)
├── FN Stress Test:  500 obfuscated/novel injections not in training data
├── Robustness Test: 200 encoding variations of known injections
└── Real-World Test: WAF logs from production (if available)
```

**Cross-validation:** 5-fold stratified CV on training set for hyperparameter tuning.

**Temporal validation:** If timestamps available, train on older data, test on newer data to simulate real-world deployment.

### 7.4 Metrics Beyond Accuracy

| Metric | Target | Why It Matters |
|--------|--------|----------------|
| **Accuracy** | > 97% | Overall correctness |
| **False Positive Rate (FPR)** | < 0.5% | FP = blocking legitimate users. In production with 1M req/day, 0.5% = 5,000 false blocks. Must be minimized. |
| **False Negative Rate (FNR)** | < 2% | FN = missed attacks. More tolerable than FP (defense in depth), but still critical. |
| **Precision (INJECTION class)** | > 99% | When the system says INJECTION, it must be right. |
| **Recall (INJECTION class)** | > 98% | The system must catch almost all injections. |
| **F1 (INJECTION class)** | > 98.5% | Harmonic mean of precision and recall. |
| **INVALID accuracy** | > 90% | Correctly classifying garbage as INVALID, not INJECTION. |
| **Latency P99** | < 50ms | 99th percentile detection time for real-time WAF use. |
| **Robustness score** | > 95% | Detection rate on obfuscated variants of known injections. |
| **Class-conditional calibration** | ECE < 0.05 | Model confidence should match actual probability of being correct. |

---

## 8. Final Evaluation

### 8.1 Production-Ready Checklist (10/10)

| # | Criterion | Current | Required |
|---|-----------|---------|----------|
| 1 | Multi-stage normalization defeats encoding evasion | Partial (URL + comments) | Unicode NFKC + recursive URL + HTML entity + null byte + homoglyph |
| 2 | Lexical pre-filter provides fast path for safe input | Yes | Yes (formalize the fast-path SAFE exit) |
| 3 | ML ensemble uses 3+ independent model architectures | 2 active (RF, CNN), 1 unused (BiLSTM) | 3 active: RF, CNN, BiLSTM all voting |
| 4 | All ML models trained on 3-class data (SAFE/INVALID/INJECTION) | No (binary training data) | Yes — retrain all models with INVALID class |
| 5 | Semantic validation is mandatory for INJECTION classification | Yes (partially) | Yes — formalize as architectural invariant |
| 6 | Context-aware quote/keyword analysis prevents false positives | No | Yes — implement proximity-based scoring |
| 7 | Severity based on attack type, not confidence score | No (severity from action) | Yes — attack-type-aware severity taxonomy |
| 8 | Explainability produces per-layer decision trace | Partial (rule name + scores) | Full structured explanation with feature attribution |
| 9 | SIEM export with ECS-compatible fields | Partial (CEF) | Full ECS + MITRE ATT&CK mapping |
| 10 | FPR < 0.5% on adversarial test set | Unknown | Measured and documented |
| 11 | FNR < 2% on obfuscated injection set | Unknown | Measured and documented |
| 12 | P99 latency < 50ms | Unknown | Benchmarked |
| 13 | Input size validation and rate limiting | No | Yes |
| 14 | Proper logging framework (not print()) | No | structlog or Python logging |
| 15 | pytest-compatible test suite with CI | No | Yes — pytest + GitHub Actions |
| 16 | Training pipeline documented and reproducible | No | Yes — script + dataset versioning |
| 17 | Configuration externalized (not hardcoded) | No | Yes — YAML/env config |
| 18 | FastAPI (not Flask) with OpenAPI docs | No (Flask) | Yes — migrate to FastAPI |
| 19 | Graceful degradation with health reporting | Partial | Full — model status in health endpoint |
| 20 | Active learning feedback loop operational | Schema exists | End-to-end: feedback → retrain trigger |

**The system is 10/10 when all 20 criteria are met with documented evidence.**

### 8.2 Why This System Is Production-Ready (When Complete)

This system is production-ready because it enforces a fundamental architectural invariant: no input is classified as SQL injection without both statistical evidence (ML ensemble agreement) and structural evidence (semantic validation). This dual-confirmation design eliminates the two failure modes that plague production WAFs: false positives from unusual-but-safe input (handled by the semantic gate), and false negatives from obfuscated attacks (handled by the ML ensemble's generalization capability). The multi-model ensemble provides fault tolerance — no single model failure causes system failure. Attack-type-aware severity mapping ensures operational teams can prioritize responses correctly. The sub-50ms latency target makes it viable as inline middleware without degrading user experience. The structured explainability output integrates directly into SOC workflows via ECS-compatible SIEM fields, and every decision is auditable and reproducible.

### 8.3 Why This System Is Academically Strong (When Complete)

This system is academically strong because it addresses three open problems in ML-based security detection. First, it solves the false-positive problem that undermines trust in ML-based WAFs by introducing a semantic validation layer that constrains ML predictions — formalizing the principle that statistical pattern matching is necessary but not sufficient for security classification. Second, it introduces the INVALID class as a third classification target, acknowledging that the real-world input space is not binary (safe/malicious) but includes a large region of malformed, nonsensical, or non-SQL-related anomalous input that existing binary classifiers mishandle. Third, it provides full decision explainability with per-layer attribution, addressing the "black box" criticism of ML security tools and enabling formal verification of detection logic. The ensemble fusion strategy (weighted voting with agreement bonus and semantic gating) is a contribution to the applied ML literature on constrained classification, where domain knowledge is used to bound the hypothesis space of statistical models.

---

## Appendix A: Current Bugs and Issues to Fix

These issues were identified during codebase review and must be fixed:

| # | Issue | File | Fix |
|---|-------|------|-----|
| 1 | Flask not in requirements.txt | `requirements.txt` | Add `flask>=3.0` or migrate to FastAPI |
| 2 | TensorFlow not in requirements.txt | `requirements.txt` | Add `tensorflow>=2.15` |
| 3 | `requirements.txt` is UTF-16 encoded with space padding | `requirements.txt` | Re-encode as UTF-8 |
| 4 | `detect_sql_injection()` creates a new detector per call | `sql_injection_detector.py:572` | Use module-level singleton |
| 5 | `tau_model_divergence` defined but never used | `sql_injection_detector.py:57` | Implement divergence-based rules or remove |
| 6 | BiLSTM model exists but is not integrated | `models/bilstm_sql_detector.keras` | Integrate into ensemble |
| 7 | `daily_stats` table never populated | `incident_logger.py` | Implement or remove dead schema |
| 8 | XSS vulnerability in demo page | `api_server.py:367` | HTML-escape `${data.input}` |
| 9 | `print()` used instead of logging | Multiple files | Replace with `structlog` |
| 10 | `.env` file references non-existent model path | `.env` | Fix path or remove |
| 11 | `test_models.py` has inconsistent `extract_features` | `test_models.py:86` | Sync with `sql_injection_detector.py` |
| 12 | No input size validation | `api_server.py`, `sql_injection_detector.py` | Add max input length (e.g., 10,000 chars) |
| 13 | No API authentication or rate limiting | `api_server.py` | Add API key auth + rate limiter |

## Appendix B: Implementation Priority Order

```
PHASE 1 — Fix Critical Bugs (1-2 days)
  → Items 1-4, 8, 12 from Appendix A
  → Fix requirements.txt
  → Add input validation

PHASE 2 — Integrate BiLSTM + 3-Class Retraining (1 week)
  → Build training pipeline script
  → Create 3-class dataset (add INVALID samples)
  → Retrain RF, CNN, BiLSTM on 3-class data
  → Update ensemble weights for 3-model voting

PHASE 3 — Semantic Analyzer Upgrade (3-5 days)
  → Implement context-aware quote analysis
  → Implement keyword proximity scoring
  → Add attack type classification
  → Add structural validity check

PHASE 4 — Severity + Explainability (3-5 days)
  → Implement attack-type-aware severity
  → Build structured explanation output
  → Add ECS fields to SIEM export
  → Add MITRE ATT&CK mapping

PHASE 5 — API + Infrastructure (3-5 days)
  → Migrate Flask → FastAPI
  → Add authentication + rate limiting
  → Add proper logging (structlog)
  → Externalize configuration
  → Dockerize

PHASE 6 — Testing + Validation (1 week)
  → Migrate tests to pytest
  → Add CI pipeline (GitHub Actions)
  → Measure FPR, FNR, latency benchmarks
  → Document metrics
```
