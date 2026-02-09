"""
SQL Injection Detector - Production Module with Ensemble + INVALID Detection
=============================================================================
Combines Random Forest (classic ML) and CNN (deep learning) for robust detection.
Includes semantic analysis to distinguish SQL injections from malformed input.

Usage:
    from sql_injection_detector import SQLInjectionEnsemble

    detector = SQLInjectionEnsemble()
    result = detector.detect("' OR '1'='1")

    print(f"Decision: {result['decision']}")
    print(f"Action: {result['action']}")
    print(f"Confidence: {result['confidence_level']}")
"""

import re
import urllib.parse
import numpy as np
import joblib
import pickle
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

MODULE_DIR = Path(__file__).parent


class Decision(Enum):
    SAFE = "SAFE"
    INVALID = "INVALID"          # Malformed input (no SQL semantics)
    SUSPICIOUS = "SUSPICIOUS"
    INJECTION = "INJECTION"


class Action(Enum):
    ALLOW = "ALLOW"
    LOG = "LOG"                  # Log for analysis but don't block
    CHALLENGE = "CHALLENGE"      # CAPTCHA or additional verification
    BLOCK = "BLOCK"


@dataclass
class EnsembleConfig:
    """Configuration for ensemble decision rule."""
    alpha: float = 0.65          # CNN weight (higher = more trust in CNN)
    beta: float = 0.35           # RF weight
    tau_high: float = 0.60       # High confidence injection threshold
    tau_low: float = 0.40        # Low confidence injection threshold
    tau_safe: float = 0.30       # Safe threshold
    tau_cnn_override: float = 0.75  # CNN single-model override
    tau_rf_strong: float = 0.70     # RF strong signal threshold
    # New: thresholds for INVALID detection
    tau_semantic_min: float = 2.0   # Minimum semantic score to consider as SQLi
    tau_model_divergence: float = 0.40  # |P_cnn - P_rf| threshold for divergence


class SQLSemanticAnalyzer:
    """
    Rule-based pre-filter to calculate SQL semantic score.

    Key insight: Real SQL injection has SQL SEMANTICS, not just special characters.
    Malformed input has syntax patterns but NO SQL meaning.

    Score components:
        - SQL keywords (SELECT, UNION, OR, AND, DROP, etc.)
        - SQL functions (SLEEP, BENCHMARK, LOAD_FILE)
        - SQL operators and patterns
        - Comment patterns (--, /*, #)
        - Quote-escape patterns
    """

    # High-risk SQL keywords (direct query manipulation)
    HIGH_RISK_KEYWORDS = [
        'select', 'union', 'insert', 'update', 'delete', 'drop',
        'truncate', 'exec', 'execute', 'xp_', 'sp_'
    ]

    # Medium-risk keywords (logic manipulation)
    MEDIUM_RISK_KEYWORDS = [
        'or', 'and', 'where', 'from', 'having', 'group', 'order',
        'like', 'between', 'in', 'is', 'null', 'not', 'exists'
    ]

    # SQL functions (time-based, file access, etc.)
    # Note: Must include () or be word-bounded to avoid false positives
    SQL_FUNCTIONS = [
        'sleep(', 'benchmark(', 'waitfor', 'delay', 'pg_sleep(',
        'load_file(', 'into outfile', 'into dumpfile',
        'concat(', 'char(', 'ascii(', 'substring(', 'substr(', 'mid(',
        'version(', 'database(', 'user(', 'current_user(', 'schema('
    ]

    # SQL comment patterns
    COMMENT_PATTERNS = ['--', '/*', '*/', '#']

    @classmethod
    def calculate_semantic_score(cls, text: str) -> Dict[str, Any]:
        """
        Calculate SQL semantic score for input text.

        Returns:
            Dict with:
                - score: Total semantic score (0 = no SQL semantics)
                - breakdown: Detailed scoring breakdown
                - has_sql_semantics: Boolean flag
        """
        text_lower = text.lower()
        text_clean = urllib.parse.unquote(text_lower)

        # Remove inline comments to catch obfuscation like UN/**/ION
        text_normalized = re.sub(r'/\*.*?\*/', '', text_clean)

        score = 0.0
        breakdown = {
            'high_risk_keywords': [],
            'medium_risk_keywords': [],
            'sql_functions': [],
            'comment_patterns': [],
            'injection_patterns': []
        }

        # === HIGH-RISK SQL KEYWORDS (+3 each) ===
        # Use text_normalized to catch obfuscation like UN/**/ION
        for kw in cls.HIGH_RISK_KEYWORDS:
            if re.search(rf'\b{kw}\b', text_normalized, re.I):
                score += 3
                breakdown['high_risk_keywords'].append(kw)

        # === MEDIUM-RISK KEYWORDS (+1 each, max +3) ===
        medium_count = 0
        for kw in cls.MEDIUM_RISK_KEYWORDS:
            if re.search(rf'\b{kw}\b', text_normalized, re.I):
                medium_count += 1
                breakdown['medium_risk_keywords'].append(kw)
        score += min(medium_count, 3)

        # === SQL FUNCTIONS (+4 each) ===
        for fn in cls.SQL_FUNCTIONS:
            if fn in text_normalized:
                score += 4
                breakdown['sql_functions'].append(fn)

        # === ALTERNATIVE LOGIC OPERATORS (+3) ===
        # || is string concat in Oracle/PostgreSQL, can be used for injection
        if re.search(r"'\s*\|\|\s*'", text_clean):
            score += 3
            breakdown['injection_patterns'].append("concat-operator")
        # && is AND alternative
        if re.search(r"'\s*&&\s*'", text_clean):
            score += 3
            breakdown['injection_patterns'].append("and-operator")

        # === COMMENT PATTERNS (+2 each) ===
        # Note: Only count if pattern appears in SQL-like context
        if '--' in text_clean:
            score += 2
            breakdown['comment_patterns'].append('--')
        if '/*' in text_clean or '*/' in text_clean:
            score += 2
            breakdown['comment_patterns'].append('/*...*/')
        # MySQL # comment only if after quote or alphanumeric (not standalone)
        if re.search(r"['\w]\s*#", text_clean):
            score += 2
            breakdown['comment_patterns'].append('#')

        # === INJECTION-SPECIFIC PATTERNS ===
        # NOTE: Patterns must be CONTEXTUAL to avoid false positives on garbage input

        # Pattern: ' OR '1'='1 / ' AND '1'='1 (classic injection with logic)
        # Requires: quote + logic operator + quote pattern
        if re.search(r"'\s*(or|and)\s+['\d]", text_clean, re.I):
            score += 3
            breakdown['injection_patterns'].append("quote-logic-quote")

        # Pattern: '=' only in SQL context (after OR/AND or before --)
        # More restrictive: requires SQL keyword nearby
        if re.search(r"(or|and)\s+'\w*'\s*=\s*'\w*'", text_clean, re.I):
            score += 2
            breakdown['injection_patterns'].append("quote-equals-quote")

        # Pattern: Standalone tautology 1=1, 2=2 (must be word-bounded, not inside garbage)
        # Only match if: start of string, after space/operator, or after SQL keyword
        if re.search(r"(^|or|and|where|\s)(\d)\s*=\s*\2(\s|$|;|--)", text_clean, re.I):
            score += 3
            breakdown['injection_patterns'].append("tautology-numeric")

        # Pattern: 'x'='x' tautology - must have SQL context (OR/AND nearby)
        if re.search(r"(or|and)\s+'(\w+)'\s*=\s*'\2'", text_clean, re.I):
            score += 3
            breakdown['injection_patterns'].append("tautology-string")

        # Pattern: UNION SELECT (normal and obfuscated)
        if re.search(r'\bunion\b.*\bselect\b', text_clean, re.I):
            score += 4
            breakdown['injection_patterns'].append("union-select")
        # Obfuscated: UN/**/ION/**/SE/**/LECT -> unionselect (no boundaries)
        elif re.search(r'union\s*select', text_normalized, re.I):
            score += 4
            breakdown['injection_patterns'].append("union-select-obfuscated")

        # Pattern: quote followed by SQL keyword (must be start of injection)
        # More restrictive: requires the keyword to be meaningful (OR/AND with space after)
        if re.search(r"'\s*;\s*(select|insert|update|delete|drop)", text_clean, re.I):
            score += 3
            breakdown['injection_patterns'].append("stacked-query")

        if re.search(r"'\s*(or|and)\s+\d", text_clean, re.I):
            score += 2
            breakdown['injection_patterns'].append("quote-keyword")

        # Pattern: No-space obfuscation 'OR'1'='1 or 'AND'1'='1
        # Catches: 'OR'x'='x, 'AND'1'='1 without spaces
        if re.search(r"'(or|and)'[^']*'='", text_clean, re.I):
            score += 4
            breakdown['injection_patterns'].append("no-space-obfuscation")

        return {
            'score': score,
            'breakdown': breakdown,
            'has_sql_semantics': score >= 2
        }


class SQLInjectionEnsemble:
    """
    Ensemble SQL Injection Detector combining Random Forest and CNN.

    Architecture:
        - Random Forest: Good for clean SQL patterns, fast inference
        - CNN: Better for obfuscated attacks, character-level patterns
        - Semantic Analyzer: Rule-based pre-filter to detect SQL semantics

    Decision Rule (Updated with INVALID class):
        1. Calculate SQL semantic score (rule-based)
        2. Get model predictions (P_rf, P_cnn)
        3. Apply decision logic:

        RULE 0: INVALID DETECTION
            IF P_cnn >= 0.70 AND P_rf < 0.50 AND semantic_score < 2:
                → INVALID (malformed input, not SQLi)

        RULE 1: HIGH CONFIDENCE INJECTION
            IF S >= 0.60 AND semantic_score >= 2:
                → INJECTION

        RULE 2: CNN OVERRIDE (obfuscation)
            IF P_cnn >= 0.75 AND semantic_score >= 3:
                → INJECTION

        RULE 3: RF STRONG SIGNAL
            IF P_rf >= 0.70 AND semantic_score >= 2:
                → INJECTION

        RULE 4: SAFE
            IF S < 0.30:
                → SAFE

        RULE 5: SUSPICIOUS
            IF semantic_score >= 1:
                → SUSPICIOUS

        RULE 6: DEFAULT INVALID
            → INVALID (high model signal but no SQL semantics)
    """

    def __init__(self, config: Optional[EnsembleConfig] = None):
        self.config = config or EnsembleConfig()
        self.semantic_analyzer = SQLSemanticAnalyzer()

        # Model paths
        self.rf_model = None
        self.rf_vectorizer = None
        self.cnn_model = None
        self.cnn_tokenizer = None

        self.rf_loaded = False
        self.cnn_loaded = False

        self._load_models()

    def _load_models(self):
        """Load both RF and CNN models."""
        # Load Random Forest
        try:
            self.rf_model = joblib.load(MODULE_DIR / 'rf_sql_model.pkl')
            self.rf_vectorizer = joblib.load(MODULE_DIR / 'tfidf_vectorizer.pkl')
            self.rf_loaded = True
        except Exception as e:
            print(f"Warning: RF model not loaded: {e}")

        # Load CNN
        try:
            import tensorflow as tf
            self.cnn_model = tf.keras.models.load_model(MODULE_DIR / 'models' / 'cnn_sql_detector.keras')
            with open(MODULE_DIR / 'models' / 'dl_tokenizer.pkl', 'rb') as f:
                self.cnn_tokenizer = pickle.load(f)
            self.cnn_loaded = True
        except Exception as e:
            print(f"Warning: CNN model not loaded: {e}")

    @staticmethod
    def preprocess(text: str) -> str:
        """Preprocess text for analysis."""
        text = str(text).lower()
        text = urllib.parse.unquote(text)
        text = re.sub(r'/\*.*?\*/', ' ', text)
        text = re.sub(r'--.*$', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    @staticmethod
    def extract_features(text: str) -> Dict[str, int]:
        """Extract features for RF model."""
        clean = SQLInjectionEnsemble.preprocess(text)
        return {
            'length': len(clean),
            'num_digits': sum(c.isdigit() for c in clean),
            'num_special': sum(not c.isalnum() and not c.isspace() for c in clean),
            'num_quotes': clean.count("'") + clean.count('"'),
            'num_keywords': len(re.findall(
                r'\b(select|union|or|and|drop|sleep|where|from|insert|update|delete|having|group)\b',
                clean
            ))
        }

    def _predict_rf(self, text: str) -> float:
        """Get RF probability."""
        if not self.rf_loaded:
            return 0.0

        from scipy.sparse import hstack

        clean_text = self.preprocess(text)
        features = self.extract_features(text)

        tfidf = self.rf_vectorizer.transform([clean_text])
        extra = np.array([[
            features['length'],
            features['num_digits'],
            features['num_special'],
            features['num_quotes'],
            features['num_keywords']
        ]])

        X = hstack([tfidf, extra])
        return float(self.rf_model.predict_proba(X)[0][1])

    def _predict_cnn(self, text: str) -> float:
        """Get CNN probability."""
        if not self.cnn_loaded:
            return 0.0

        from tensorflow.keras.preprocessing.sequence import pad_sequences

        clean_text = self.preprocess(text)
        seq = self.cnn_tokenizer.texts_to_sequences([clean_text])
        padded = pad_sequences(seq, maxlen=200, padding='post', truncating='post')

        return float(self.cnn_model.predict(padded, verbose=0)[0][0])

    def _ensemble_decision(self, P_rf: float, P_cnn: float, semantic: Dict) -> Dict[str, Any]:
        """
        Apply ensemble decision rule with INVALID detection.

        Key innovation: Uses semantic score to distinguish:
            - SQL Injection: High model scores + SQL semantics
            - Malformed Input: High CNN score + Low RF + No SQL semantics

        Returns dict with decision, confidence, reason, action.
        """
        cfg = self.config
        sem_score = semantic['score']
        has_semantics = semantic['has_sql_semantics']

        # Weighted ensemble score
        S = cfg.alpha * P_cnn + cfg.beta * P_rf

        # Model divergence (CNN thinks SQLi, RF doesn't)
        divergence = abs(P_cnn - P_rf)

        # === RULE 0: INVALID INPUT DETECTION ===
        # High CNN + Low RF + No SQL semantics = Malformed/garbage input
        if P_cnn >= 0.70 and P_rf < 0.50 and sem_score < cfg.tau_semantic_min:
            return {
                'decision': Decision.INVALID,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'Malformed input: P_cnn={P_cnn:.2f} but P_rf={P_rf:.2f}, sem_score={sem_score:.1f} (no SQL semantics)',
                'action': Action.LOG
            }

        # === RULE 1: High confidence injection (both models agree + semantics) ===
        if S >= cfg.tau_high and has_semantics:
            return {
                'decision': Decision.INJECTION,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'Ensemble score {S:.2f} >= {cfg.tau_high}, sem_score={sem_score:.1f} (SQL semantics confirmed)',
                'action': Action.BLOCK
            }

        # === RULE 2: CNN Override (obfuscation) - REQUIRES strong semantics ===
        if P_cnn >= cfg.tau_cnn_override and sem_score >= 3:
            return {
                'decision': Decision.INJECTION,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'CNN override: P_cnn={P_cnn:.2f}, sem_score={sem_score:.1f} (obfuscated SQLi)',
                'action': Action.BLOCK
            }

        # === RULE 3: RF Strong signal with semantics ===
        if P_rf >= cfg.tau_rf_strong and has_semantics:
            return {
                'decision': Decision.INJECTION,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'RF strong signal: P_rf={P_rf:.2f}, sem_score={sem_score:.1f}',
                'action': Action.BLOCK
            }

        # === RULE 3.5: Very high semantic score (advanced injection patterns) ===
        # Catches sophisticated attacks that may fool ML but have clear SQL semantics
        if sem_score >= 6:
            return {
                'decision': Decision.INJECTION,
                'confidence_level': 'MEDIUM',
                'score': S,
                'reason': f'High semantic score {sem_score:.1f} indicates SQL injection patterns',
                'action': Action.BLOCK
            }

        # === RULE 4: Conflict zone with semantics ===
        if S >= cfg.tau_low and has_semantics:
            if P_cnn >= 0.50 or P_rf >= cfg.tau_rf_strong:
                confidence = 'MEDIUM' if S < cfg.tau_high else 'HIGH'
                return {
                    'decision': Decision.INJECTION,
                    'confidence_level': confidence,
                    'score': S,
                    'reason': f'Conflict zone with SQL semantics (P_rf={P_rf:.2f}, P_cnn={P_cnn:.2f}, sem={sem_score:.1f})',
                    'action': Action.CHALLENGE if confidence == 'MEDIUM' else Action.BLOCK
                }

        # === RULE 5: High confidence safe ===
        if S < cfg.tau_safe:
            return {
                'decision': Decision.SAFE,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'Ensemble score {S:.2f} < {cfg.tau_safe} (both models agree safe)',
                'action': Action.ALLOW
            }

        # === RULE 6: Suspicious (has some SQL semantics but low confidence) ===
        if sem_score >= 1:
            return {
                'decision': Decision.SUSPICIOUS,
                'confidence_level': 'LOW',
                'score': S,
                'reason': f'Gray zone with weak SQL semantics: S={S:.2f}, sem={sem_score:.1f}',
                'action': Action.CHALLENGE
            }

        # === RULE 7: Default to INVALID (model signal but no semantics) ===
        return {
            'decision': Decision.INVALID,
            'confidence_level': 'MEDIUM',
            'score': S,
            'reason': f'No SQL semantics detected: S={S:.2f}, sem_score={sem_score:.1f}',
            'action': Action.LOG
        }

    def detect(self, text: str) -> Dict[str, Any]:
        """
        Detect SQL injection using ensemble of RF and CNN with semantic analysis.

        Args:
            text: Input text to analyze

        Returns:
            Dict with:
                - decision: SAFE, INVALID, SUSPICIOUS, or INJECTION
                - action: ALLOW, LOG, CHALLENGE, or BLOCK
                - confidence_level: HIGH, MEDIUM, or LOW
                - score: Weighted ensemble score
                - P_rf: Random Forest probability
                - P_cnn: CNN probability
                - semantic_score: SQL semantic score
                - semantic_breakdown: Detailed semantic analysis
                - reason: Human-readable explanation
                - features: Extracted features
        """
        # Step 1: Semantic analysis (rule-based pre-filter)
        semantic = self.semantic_analyzer.calculate_semantic_score(text)

        # Step 2: Get individual model predictions
        P_rf = self._predict_rf(text)
        P_cnn = self._predict_cnn(text) if self.cnn_loaded else P_rf

        # Step 3: Apply ensemble decision rule
        result = self._ensemble_decision(P_rf, P_cnn, semantic)

        # Add all analysis data
        result['P_rf'] = P_rf
        result['P_cnn'] = P_cnn
        result['semantic_score'] = semantic['score']
        result['semantic_breakdown'] = semantic['breakdown']
        result['features'] = self.extract_features(text)
        result['models_loaded'] = {
            'rf': self.rf_loaded,
            'cnn': self.cnn_loaded
        }

        # Convert enums to strings for JSON serialization
        result['decision'] = result['decision'].value
        result['action'] = result['action'].value

        return result

    def detect_batch(self, texts: List[str]) -> List[Dict[str, Any]]:
        """Detect SQL injection in multiple texts."""
        return [self.detect(text) for text in texts]

    def is_safe(self, text: str) -> bool:
        """Quick check if input is safe."""
        decision = self.detect(text)['decision']
        return decision in ['SAFE', 'INVALID']

    def should_block(self, text: str) -> bool:
        """Check if input should be blocked."""
        return self.detect(text)['action'] == 'BLOCK'


# === Legacy API for backward compatibility ===

class SQLInjectionDetector:
    """Legacy detector using only Random Forest (backward compatible)."""

    def __init__(self, threshold: float = 0.5):
        self._ensemble = SQLInjectionEnsemble()
        self.threshold = threshold
        self.model_loaded = self._ensemble.rf_loaded

    def detect(self, text: str) -> Dict[str, Any]:
        P_rf = self._ensemble._predict_rf(text)
        is_injection = P_rf >= self.threshold

        return {
            'is_injection': is_injection,
            'confidence': P_rf if is_injection else (1 - P_rf),
            'label': 'SQL_INJECTION' if is_injection else 'SAFE',
            'probability': P_rf,
            'features': self._ensemble.extract_features(text)
        }

    def is_safe(self, text: str) -> bool:
        return not self.detect(text)['is_injection']


# === Convenience functions ===

def detect_sql_injection(text: str) -> Dict[str, Any]:
    """Quick detection using ensemble (recommended)."""
    detector = SQLInjectionEnsemble()
    return detector.detect(text)


def create_middleware():
    """Create middleware function for web frameworks."""
    detector = SQLInjectionEnsemble()

    def check_request(params: Dict[str, str]) -> Dict[str, Any]:
        """Check all parameters for SQL injection."""
        blocked = False
        results = []

        for key, value in params.items():
            if isinstance(value, str) and len(value) > 0:
                result = detector.detect(value)
                if result['action'] == 'BLOCK':
                    blocked = True
                results.append({
                    'parameter': key,
                    'decision': result['decision'],
                    'action': result['action'],
                    'score': result['score'],
                    'semantic_score': result['semantic_score']
                })

        return {
            'blocked': blocked,
            'results': results
        }

    return check_request


# === Demo ===

if __name__ == '__main__':
    print("="*90)
    print("SQL Injection Ensemble Detector - Demo (with INVALID class)")
    print("="*90)

    detector = SQLInjectionEnsemble()
    print(f"\nModels loaded: RF={detector.rf_loaded}, CNN={detector.cnn_loaded}")
    print(f"Config: alpha={detector.config.alpha} (CNN), beta={detector.config.beta} (RF)")

    test_cases = [
        # Real SQL Injections
        "' OR '1'='1",
        "SELECT * FROM users",
        "admin'--",
        "'; DROP TABLE users; --",
        "' UNION SELECT password FROM users--",
        "%27%20OR%20%271%27%3D%271",  # URL encoded

        # Safe inputs
        "John O'Brien",
        "hello@email.com",
        "McDonald's restaurant",

        # INVALID / Malformed (should NOT be blocked)
        "'fqule' = Robert O'nill",
        "1 + 1 = 2",
        "x' y' z' random garbage",
        "!@#$%^&*()_+",
        "'''''",
    ]

    print(f"\n{'Input':<40} {'Decision':<12} {'Action':<10} {'Score':<6} {'P_rf':<6} {'P_cnn':<6} {'Sem':<5}")
    print("-"*100)

    for test in test_cases:
        r = detector.detect(test)
        display = test[:38] + '..' if len(test) > 40 else test
        print(f"{display:<40} {r['decision']:<12} {r['action']:<10} {r['score']:.2f}   {r['P_rf']:.2f}   {r['P_cnn']:.2f}   {r['semantic_score']:.1f}")

    print("\n" + "="*90)
    print("Legend:")
    print("  SAFE      - Legitimate input, allow")
    print("  INVALID   - Malformed input (no SQL semantics), log but don't block")
    print("  SUSPICIOUS- Unclear, requires human review or CAPTCHA")
    print("  INJECTION - SQL injection detected, block immediately")
    print("="*90)
