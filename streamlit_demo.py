"""
SQL Injection Detection Demo Dashboard v3.0
=============================================
Ensemble Detection System with attack typing, severity classification,
and full explainability.
"""

import streamlit as st
import time

from sql_injection_detector import SQLInjectionEnsemble, EnsembleConfig

# Page config
st.set_page_config(
    page_title="SQL Injection Detector v3.0",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header { font-size: 2.5rem; font-weight: bold; text-align: center; color: #1f77b4; margin-bottom: 1rem; }
    .sub-header { font-size: 1.2rem; text-align: center; color: #666; margin-bottom: 2rem; }
    .safe-box { background-color: #d4edda; border: 2px solid #28a745; border-radius: 10px; padding: 20px; text-align: center; }
    .danger-box { background-color: #f8d7da; border: 2px solid #dc3545; border-radius: 10px; padding: 20px; text-align: center; }
    .warning-box { background-color: #fff3cd; border: 2px solid #ffc107; border-radius: 10px; padding: 20px; text-align: center; }
    .invalid-box { background-color: #e2e3e5; border: 2px solid #6c757d; border-radius: 10px; padding: 20px; text-align: center; }
    .metric-card { background-color: #f8f9fa; border-radius: 10px; padding: 15px; text-align: center; }
    .ensemble-score { font-size: 3rem; font-weight: bold; text-align: center; }
</style>
""", unsafe_allow_html=True)


@st.cache_resource(ttl=60)
def load_ensemble():
    """Load ensemble detector."""
    return SQLInjectionEnsemble()


def get_decision_box(decision, action, confidence, severity, attack_type):
    """Get styled box based on decision."""
    if decision == "SAFE":
        return f"""
        <div class="safe-box">
            <h2>SAFE</h2>
            <h3>Action: {action}</h3>
            <p>Severity: {severity}</p>
        </div>
        """
    elif decision == "INVALID":
        return f"""
        <div class="invalid-box">
            <h2>INVALID / MALFORMED</h2>
            <h3>Action: {action}</h3>
            <p>No SQL semantics detected</p>
        </div>
        """
    elif decision == "SUSPICIOUS":
        return f"""
        <div class="warning-box">
            <h2>SUSPICIOUS</h2>
            <h3>Action: {action}</h3>
            <p>Confidence: {confidence}</p>
        </div>
        """
    else:
        return f"""
        <div class="danger-box">
            <h2>SQL INJECTION</h2>
            <h3>Action: {action} | Severity: {severity}</h3>
            <p>Attack Type: {attack_type} | Confidence: {confidence}</p>
        </div>
        """


def main():
    st.markdown('<p class="main-header">SQL Injection Ensemble Detector v3.0</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">RF + CNN + BiLSTM + Semantic Validation | Attack Typing | Severity | Explainability</p>', unsafe_allow_html=True)

    with st.spinner("Loading ensemble models..."):
        detector = load_ensemble()

    # Sidebar
    with st.sidebar:
        st.header("Decision Classes")
        st.markdown("""
        | Class | Action | Description |
        |-------|--------|-------------|
        | **SAFE** | ALLOW | Legitimate input |
        | **INVALID** | LOG | Malformed (no SQL) |
        | **SUSPICIOUS** | CHALLENGE | Needs verification |
        | **INJECTION** | BLOCK/ALERT | SQL attack detected |
        """)

        st.header("Architecture (v3.0)")
        st.markdown("""
        1. **L0: Normalization** — Unicode NFKC, URL decode, null strip
        2. **L1: Lexical Pre-filter** — Fast-path SAFE exit
        3. **L2: ML Ensemble** — RF + CNN + BiLSTM
        4. **L3: Semantic Validation** — Attack typing
        5. **L4: Decision Engine** — Semantic-gated
        6. **L5: Severity** — Attack-type-aware
        7. **L6: Explainability** — SIEM-ready
        """)

        st.header("Model Status")
        if detector.rf_loaded:
            st.success("Random Forest: Loaded")
        else:
            st.error("Random Forest: Not loaded")
        if detector.cnn_loaded:
            st.success("CNN: Loaded")
        else:
            st.error("CNN: Not loaded")
        if detector.bilstm_loaded:
            st.success("BiLSTM: Loaded")
        else:
            st.warning("BiLSTM: Not loaded (2-model fallback)")

    # Main content
    col1, col2 = st.columns([2, 1])

    with col1:
        st.header("Enter Query to Analyze")
        user_input = st.text_area("Input:", height=100, placeholder="Type here...")
        analyze_clicked = st.button("Analyze", type="primary", use_container_width=True)

    with col2:
        st.header("Thresholds")
        cfg = detector.config
        st.metric("w_rf / w_cnn / w_bilstm", f"{cfg.w_rf}/{cfg.w_cnn}/{cfg.w_bilstm}")
        st.metric("Semantic Min", f"{cfg.tau_semantic_min}")
        st.metric("Semantic Override", f"{cfg.tau_semantic_override}")

    # Results
    if analyze_clicked and user_input:
        st.markdown("---")
        st.header("Analysis Results")

        with st.spinner("Running ensemble..."):
            start_time = time.time()
            result = detector.detect(user_input)
            elapsed = time.time() - start_time

        # Decision display
        decision_col, score_col = st.columns([2, 1])

        with decision_col:
            st.markdown(
                get_decision_box(
                    result['decision'], result['action'],
                    result['confidence_level'], result.get('severity', 'INFO'),
                    result.get('attack_type', 'NONE')
                ),
                unsafe_allow_html=True
            )

        with score_col:
            st.markdown(f"""
            <div class="metric-card">
                <p>Ensemble Score</p>
                <p class="ensemble-score">{result['score']:.2f}</p>
                <p>Semantic: {result['semantic_score']:.1f} | Time: {elapsed*1000:.1f}ms</p>
                <p>Rule: {result.get('rule', 'N/A')}</p>
            </div>
            """, unsafe_allow_html=True)

        # Model probabilities
        st.markdown("### Model Probabilities")
        cols = st.columns(4)
        with cols[0]:
            st.metric("RF", f"{result['P_rf']:.2%}")
            st.progress(min(result['P_rf'], 1.0))
        with cols[1]:
            st.metric("CNN", f"{result['P_cnn']:.2%}")
            st.progress(min(result['P_cnn'], 1.0))
        with cols[2]:
            bilstm = result.get('P_bilstm', 0.0)
            st.metric("BiLSTM", f"{bilstm:.2%}")
            st.progress(min(bilstm, 1.0))
        with cols[3]:
            sem_norm = min(result['semantic_score'] / 10, 1.0)
            st.metric("Semantic", f"{result['semantic_score']:.1f}")
            st.progress(sem_norm)

        # Decision explanation
        st.markdown("### Decision Explanation")
        st.info(f"**Reason:** {result['reason']}")

        if result.get('explanation'):
            exp = result['explanation']
            if exp.get('decision_factors'):
                for f in exp['decision_factors']:
                    st.write(f"- {f}")

        # Semantic breakdown
        if result['semantic_score'] > 0:
            with st.expander("Semantic Analysis Details"):
                bd = result['semantic_breakdown']
                if bd.get('high_risk_keywords'):
                    st.warning(f"**High-risk:** {', '.join(bd['high_risk_keywords'])}")
                if bd.get('medium_risk_keywords'):
                    st.info(f"**Medium-risk:** {', '.join(bd['medium_risk_keywords'])}")
                if bd.get('sql_functions'):
                    st.error(f"**SQL functions:** {', '.join(bd['sql_functions'])}")
                if bd.get('injection_patterns'):
                    st.error(f"**Patterns:** {', '.join(bd['injection_patterns'])}")

        # Features
        st.markdown("### Input Features")
        features = result['features']
        fcols = st.columns(5)
        fcols[0].metric("Length", features['length'])
        fcols[1].metric("Digits", features['num_digits'])
        fcols[2].metric("Special", features['num_special'])
        fcols[3].metric("Quotes", features['num_quotes'])
        fcols[4].metric("Keywords", features['num_keywords'])

    # Quick tests
    st.markdown("---")
    st.header("Quick Tests")

    test_cases = [
        ("' OR '1'='1", "SQLi: OR"),
        ("' UNION SELECT password FROM users--", "SQLi: UNION"),
        ("'; DROP TABLE users--", "SQLi: DROP"),
        ("' AND SLEEP(5)--", "SQLi: SLEEP"),
        ("John O'Brien", "Safe: Name"),
        ("Please select an option", "Safe: Text"),
        ("'1'1'1'1'11'1'1", "Invalid"),
    ]

    cols = st.columns(4)
    for i, (query, desc) in enumerate(test_cases):
        col = cols[i % 4]
        with col:
            if st.button(desc[:20], key=f"test_{i}", use_container_width=True):
                r = detector.detect(query)
                icons = {"SAFE": "OK", "INVALID": "?", "SUSPICIOUS": "~", "INJECTION": "X"}
                st.markdown(f"""
                `{query[:30]}`

                **{r['decision']}** | {r['action']} | {r.get('severity','INFO')}

                Type: {r.get('attack_type','NONE')} | S={r['score']:.2f} | Sem={r['semantic_score']:.1f}
                """)

    st.markdown("---")
    st.caption("SQL Injection Ensemble Detection System v3.0 — RF + CNN + BiLSTM + Semantic Analysis")


if __name__ == "__main__":
    main()
