"""
SQL Injection Detection Demo Dashboard
=====================================
Ensemble Detection System with INVALID class for malformed input detection.
"""

import streamlit as st
import time

# Import our ensemble detector
from sql_injection_detector import SQLInjectionEnsemble, EnsembleConfig

# Page config
st.set_page_config(
    page_title="SQL Injection Detector",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.2rem;
        text-align: center;
        color: #666;
        margin-bottom: 2rem;
    }
    .safe-box {
        background-color: #d4edda;
        border: 2px solid #28a745;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .danger-box {
        background-color: #f8d7da;
        border: 2px solid #dc3545;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .warning-box {
        background-color: #fff3cd;
        border: 2px solid #ffc107;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .invalid-box {
        background-color: #e2e3e5;
        border: 2px solid #6c757d;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 15px;
        text-align: center;
    }
    .ensemble-score {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource(ttl=60)  # Refresh cache every 60 seconds
def load_ensemble():
    """Load ensemble detector"""
    return SQLInjectionEnsemble()


def get_decision_box(decision, action, confidence):
    """Get styled box based on decision"""
    if decision == "SAFE":
        return f"""
        <div class="safe-box">
            <h2>✅ SAFE</h2>
            <h3>Action: {action}</h3>
            <p>Confidence: {confidence}</p>
        </div>
        """
    elif decision == "INVALID":
        return f"""
        <div class="invalid-box">
            <h2>⚠️ INVALID / MALFORMED</h2>
            <h3>Action: {action}</h3>
            <p>No SQL semantics detected</p>
        </div>
        """
    elif decision == "SUSPICIOUS":
        return f"""
        <div class="warning-box">
            <h2>🔍 SUSPICIOUS</h2>
            <h3>Action: {action}</h3>
            <p>Confidence: {confidence}</p>
        </div>
        """
    else:  # INJECTION
        return f"""
        <div class="danger-box">
            <h2>🚨 SQL INJECTION</h2>
            <h3>Action: {action}</h3>
            <p>Confidence: {confidence}</p>
        </div>
        """


def main():
    # Header
    st.markdown('<p class="main-header">🛡️ SQL Injection Ensemble Detector</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">RF + CNN + Semantic Analysis | With INVALID Class</p>', unsafe_allow_html=True)

    # Load ensemble
    with st.spinner("Loading ensemble models..."):
        detector = load_ensemble()

    # Sidebar
    with st.sidebar:
        st.header("ℹ️ Decision Classes")
        st.markdown("""
        | Class | Action | Description |
        |-------|--------|-------------|
        | **SAFE** | ALLOW | Legitimate input |
        | **INVALID** | LOG | Malformed (no SQL semantics) |
        | **SUSPICIOUS** | CHALLENGE | Requires verification |
        | **INJECTION** | BLOCK | SQL attack detected |
        """)

        st.header("🧠 Architecture")
        st.markdown("""
        1. **Semantic Analyzer** (rule-based)
           - SQL keywords detection
           - Injection pattern matching
           - Returns `semantic_score`

        2. **ML Models**
           - Random Forest (TF-IDF)
           - CNN (char-level)

        3. **Ensemble Logic**
           - `S = 0.65×P_cnn + 0.35×P_rf`
           - Semantic score gates decisions
        """)

        st.header("📊 Model Status")
        if detector.rf_loaded:
            st.success("✅ Random Forest: Loaded")
        else:
            st.error("❌ Random Forest: Not loaded")

        if detector.cnn_loaded:
            st.success("✅ CNN: Loaded")
        else:
            st.error("❌ CNN: Not loaded")

        st.header("🧪 Test Examples")
        st.markdown("**Safe:**")
        st.code("John O'Brien")
        st.code("hello@email.com")

        st.markdown("**Invalid/Malformed:**")
        st.code("'1'1'1'1'11'1'1")
        st.code("'fqule' = Robert O'nill")

        st.markdown("**SQL Injection:**")
        st.code("' OR '1'='1")
        st.code("admin'--")

    # Main content
    col1, col2 = st.columns([2, 1])

    with col1:
        st.header("🔍 Enter Query to Analyze")

        user_input = st.text_area(
            "Enter SQL query or user input:",
            height=100,
            placeholder="Type a query here... e.g., ' OR '1'='1"
        )

        # Analyze button
        analyze_clicked = st.button("🔍 Analyze Query", type="primary", use_container_width=True)

    with col2:
        st.header("⚙️ Thresholds")
        cfg = detector.config
        st.metric("CNN Weight (α)", f"{cfg.alpha:.2f}")
        st.metric("RF Weight (β)", f"{cfg.beta:.2f}")
        st.metric("Semantic Min", f"{getattr(cfg, 'tau_semantic_min', 2.0):.1f}")

    # Results
    if analyze_clicked and user_input:
        st.markdown("---")
        st.header("📊 Analysis Results")

        # Analyze
        with st.spinner("Running ensemble detection..."):
            start_time = time.time()
            result = detector.detect(user_input)
            elapsed = time.time() - start_time

        # Main decision display
        st.markdown("### 🎯 Ensemble Decision")

        decision_col, score_col = st.columns([2, 1])

        with decision_col:
            st.markdown(
                get_decision_box(result['decision'], result['action'], result['confidence_level']),
                unsafe_allow_html=True
            )

        with score_col:
            st.markdown(f"""
            <div class="metric-card">
                <p>Ensemble Score</p>
                <p class="ensemble-score">{result['score']:.2f}</p>
                <p>Semantic: {result['semantic_score']:.1f}</p>
                <p>Time: {elapsed*1000:.1f}ms</p>
            </div>
            """, unsafe_allow_html=True)

        # Model probabilities
        st.markdown("### 📈 Model Probabilities")

        prob_col1, prob_col2, prob_col3 = st.columns(3)

        with prob_col1:
            st.metric("🌲 Random Forest", f"{result['P_rf']:.2%}")
            st.progress(result['P_rf'])

        with prob_col2:
            st.metric("🧠 CNN", f"{result['P_cnn']:.2%}")
            st.progress(result['P_cnn'])

        with prob_col3:
            sem_normalized = min(result['semantic_score'] / 10, 1.0)
            st.metric("📝 Semantic Score", f"{result['semantic_score']:.1f}")
            st.progress(sem_normalized)

        # Reason explanation
        st.markdown("### 💡 Decision Explanation")
        st.info(f"**Reason:** {result['reason']}")

        # Semantic breakdown
        if result['semantic_score'] > 0:
            with st.expander("🔬 Semantic Analysis Details"):
                breakdown = result['semantic_breakdown']
                if breakdown['high_risk_keywords']:
                    st.warning(f"**High-risk keywords:** {', '.join(breakdown['high_risk_keywords'])}")
                if breakdown['medium_risk_keywords']:
                    st.info(f"**Medium-risk keywords:** {', '.join(breakdown['medium_risk_keywords'])}")
                if breakdown['sql_functions']:
                    st.error(f"**SQL functions:** {', '.join(breakdown['sql_functions'])}")
                if breakdown['comment_patterns']:
                    st.warning(f"**Comment patterns:** {', '.join(breakdown['comment_patterns'])}")
                if breakdown['injection_patterns']:
                    st.error(f"**Injection patterns:** {', '.join(breakdown['injection_patterns'])}")
        else:
            st.markdown("*No SQL semantic patterns detected in input*")

        # Feature analysis
        st.markdown("### 🔬 Input Features")
        features = result['features']

        feat_cols = st.columns(5)
        feat_cols[0].metric("Length", features['length'])
        feat_cols[1].metric("Digits", features['num_digits'])
        feat_cols[2].metric("Special", features['num_special'])
        feat_cols[3].metric("Quotes", features['num_quotes'])
        feat_cols[4].metric("Keywords", features['num_keywords'])

        # Decision rule visualization
        with st.expander("📐 Decision Rule Details"):
            cfg = detector.config
            S = result['score']
            P_rf = result['P_rf']
            P_cnn = result['P_cnn']
            sem = result['semantic_score']

            st.markdown(f"""
            **Calculation:**
            ```
            S = α × P_cnn + β × P_rf
            S = {cfg.alpha} × {P_cnn:.4f} + {cfg.beta} × {P_rf:.4f}
            S = {S:.4f}
            ```

            **Rule Evaluation:**

            | Rule | Condition | Result |
            |------|-----------|--------|
            | 0 | P_cnn≥0.70 ∧ P_rf<0.50 ∧ sem<2 → INVALID | {'✅' if P_cnn >= 0.70 and P_rf < 0.50 and sem < 2 else '❌'} |
            | 1 | S≥0.60 ∧ sem≥2 → INJECTION | {'✅' if S >= 0.60 and sem >= 2 else '❌'} |
            | 2 | P_cnn≥0.75 ∧ sem≥3 → INJECTION (obfuscation) | {'✅' if P_cnn >= 0.75 and sem >= 3 else '❌'} |
            | 3 | P_rf≥0.70 ∧ sem≥2 → INJECTION | {'✅' if P_rf >= 0.70 and sem >= 2 else '❌'} |
            | 4 | S<0.30 → SAFE | {'✅' if S < 0.30 else '❌'} |
            | 5 | sem≥1 → SUSPICIOUS | {'✅' if sem >= 1 else '❌'} |
            | 6 | default → INVALID | - |

            **Final: {result['decision']}** | **Action: {result['action']}**
            """)

    # Quick test section
    st.markdown("---")
    st.header("⚡ Quick Tests")

    test_cases = [
        ("' OR '1'='1", "SQLi - Classic"),
        ("SELECT * FROM users", "SQLi - Direct SQL"),
        ("admin'--", "SQLi - Comment"),
        ("John O'Brien", "Safe - Name"),
        ("'fqule' = Robert O'nill", "Invalid - Malformed"),
        ("'1'1'1'1'11'1'1", "Invalid - Garbage"),
        ("1 + 1 = 2", "Invalid - Math"),
    ]

    cols = st.columns(4)
    for i, (query, description) in enumerate(test_cases):
        col = cols[i % 4]
        with col:
            if st.button(f"{description[:15]}", key=f"test_{i}", use_container_width=True):
                result = detector.detect(query)
                icons = {"SAFE": "✅", "INVALID": "⚠️", "SUSPICIOUS": "🔍", "INJECTION": "🚨"}
                st.markdown(f"""
                **Query:** `{query}`

                {icons.get(result['decision'], '❓')} **{result['decision']}** ({result['action']})

                Score: {result['score']:.2f} | Sem: {result['semantic_score']:.1f}
                """)

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; font-size: 0.9rem;">
        SQL Injection Ensemble Detection System v2.0<br>
        Random Forest + CNN + Semantic Analysis | INVALID Class for Malformed Input<br>
        Reduces False Positives while Maintaining Security
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
