"""
SQL Injection Detection Models - Comprehensive Testing
"""

import pandas as pd
import numpy as np
import re
import urllib.parse
import joblib
import pickle
import warnings
warnings.filterwarnings('ignore')

# Test cases: various SQL injection patterns
TEST_CASES = [
    # === OBVIOUS SQL INJECTIONS ===
    ("' OR '1'='1", 1, "Classic OR injection"),
    ("' OR 1=1 --", 1, "OR with comment"),
    ("'; DROP TABLE users; --", 1, "DROP TABLE attack"),
    ("1' UNION SELECT * FROM users --", 1, "UNION SELECT"),
    ("admin'--", 1, "Admin bypass"),
    ("' OR ''='", 1, "Empty string OR"),
    ("1; DELETE FROM users", 1, "DELETE injection"),
    ("' AND 1=0 UNION SELECT username, password FROM users --", 1, "UNION with column names"),

    # === ADVANCED INJECTIONS ===
    ("1' AND SLEEP(5) --", 1, "Time-based blind"),
    ("' OR BENCHMARK(10000000,SHA1('test')) --", 1, "Benchmark DoS"),
    ("'; EXEC xp_cmdshell('dir'); --", 1, "Command execution"),
    ("' UNION SELECT NULL,NULL,NULL --", 1, "NULL UNION"),
    ("1' ORDER BY 10 --", 1, "ORDER BY probe"),
    ("' HAVING 1=1 --", 1, "HAVING injection"),
    ("' GROUP BY columnname HAVING 1=1 --", 1, "GROUP BY injection"),

    # === ENCODED/OBFUSCATED ===
    ("%27%20OR%20%271%27%3D%271", 1, "URL encoded OR 1=1"),
    ("' OR 'x'='x", 1, "String comparison"),
    ("'/**/OR/**/1=1/**/--", 1, "Comment obfuscation"),
    ("' oR 1=1 --", 1, "Mixed case"),
    ("'||'1'='1", 1, "Concatenation Oracle"),

    # === REAL-WORLD PATTERNS ===
    ("SELECT * FROM users WHERE id=1", 1, "Direct SELECT"),
    ("INSERT INTO logs VALUES('test')", 1, "INSERT statement"),
    ("UPDATE users SET password='hacked'", 1, "UPDATE statement"),
    ("1' AND (SELECT COUNT(*) FROM users) > 0 --", 1, "Subquery injection"),

    # === NORMAL/SAFE QUERIES ===
    ("john.doe@email.com", 0, "Normal email"),
    ("Hello World", 0, "Simple text"),
    ("12345", 0, "Number"),
    ("My name is John", 0, "Normal sentence"),
    ("Product search query", 0, "Search text"),
    ("user123", 0, "Username"),
    ("New York City", 0, "City name"),
    ("2024-01-15", 0, "Date"),
    ("https://example.com/page", 0, "URL"),
    ("The quick brown fox", 0, "Normal text"),

    # === EDGE CASES (tricky normal inputs) ===
    ("It's a beautiful day", 0, "Apostrophe in text"),
    ("O'Brien", 0, "Irish name"),
    ("SELECT is a keyword", 0, "Keyword in normal text"),
    ("My password is 'secret'", 0, "Quotes in text"),
    ("1 + 1 = 2", 0, "Math expression"),
    ("WHERE are you going?", 0, "WHERE as word"),
    ("I dropped my phone", 0, "DROP as word"),
]

def preprocess(text):
    """Preprocess text for ML models"""
    text = str(text).lower()
    text = urllib.parse.unquote(text)
    text = re.sub(r'/\*.*?\*/', ' ', text)
    text = re.sub(r'--.*$', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def extract_features(text):
    """Extract additional features"""
    clean = preprocess(text)
    return {
        'length': len(clean),
        'num_digits': sum(c.isdigit() for c in clean),
        'num_special': sum(not c.isalnum() for c in clean),
        'num_quotes': clean.count("'") + clean.count('"'),
        'num_keywords': len(re.findall(r'\b(select|union|or|and|drop|sleep|where|from)\b', clean))
    }

def test_ml_models():
    """Test classic ML models"""
    print("="*80)
    print("TESTING CLASSIC ML MODELS")
    print("="*80)

    # Load models
    try:
        rf = joblib.load('rf_sql_model.pkl')
        vectorizer = joblib.load('tfidf_vectorizer.pkl')
        print("Models loaded successfully!\n")
    except Exception as e:
        print(f"Error loading models: {e}")
        return None

    results = []

    for query, expected, description in TEST_CASES:
        # Preprocess
        clean_text = preprocess(query)

        # TF-IDF features
        X_text = vectorizer.transform([clean_text])

        # Extra features
        feats = extract_features(query)
        X_extra = np.array([[feats['length'], feats['num_digits'],
                            feats['num_special'], feats['num_quotes'],
                            feats['num_keywords']]])

        # Combine features
        from scipy.sparse import hstack
        X = hstack([X_text, X_extra])

        # Predict
        pred = rf.predict(X)[0]
        prob = rf.predict_proba(X)[0][1]

        correct = pred == expected
        results.append({
            'query': query[:50] + '...' if len(query) > 50 else query,
            'expected': expected,
            'predicted': pred,
            'probability': prob,
            'correct': correct,
            'description': description
        })

    return results

def test_dl_models():
    """Test Deep Learning models"""
    print("\n" + "="*80)
    print("TESTING DEEP LEARNING MODELS")
    print("="*80)

    try:
        import tensorflow as tf
        from tensorflow.keras.preprocessing.sequence import pad_sequences

        # Load models
        cnn_model = tf.keras.models.load_model('models/cnn_sql_detector.keras')
        bilstm_model = tf.keras.models.load_model('models/bilstm_sql_detector.keras')

        with open('models/dl_tokenizer.pkl', 'rb') as f:
            tokenizer = pickle.load(f)

        print("DL Models loaded successfully!\n")
    except Exception as e:
        print(f"Error loading DL models: {e}")
        return None, None

    MAX_LEN = 200
    cnn_results = []
    bilstm_results = []

    for query, expected, description in TEST_CASES:
        clean_text = preprocess(query)

        # Tokenize and pad
        seq = tokenizer.texts_to_sequences([clean_text])
        X = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')

        # CNN prediction
        cnn_prob = cnn_model.predict(X, verbose=0)[0][0]
        cnn_pred = 1 if cnn_prob > 0.5 else 0

        cnn_results.append({
            'query': query[:50] + '...' if len(query) > 50 else query,
            'expected': expected,
            'predicted': cnn_pred,
            'probability': cnn_prob,
            'correct': cnn_pred == expected,
            'description': description
        })

        # Bi-LSTM prediction
        bilstm_prob = bilstm_model.predict(X, verbose=0)[0][0]
        bilstm_pred = 1 if bilstm_prob > 0.5 else 0

        bilstm_results.append({
            'query': query[:50] + '...' if len(query) > 50 else query,
            'expected': expected,
            'predicted': bilstm_pred,
            'probability': bilstm_prob,
            'correct': bilstm_pred == expected,
            'description': description
        })

    return cnn_results, bilstm_results

def print_results(results, model_name):
    """Print test results in a formatted way"""
    print(f"\n{'='*80}")
    print(f"{model_name} RESULTS")
    print(f"{'='*80}")

    # Separate correct and incorrect
    correct = [r for r in results if r['correct']]
    incorrect = [r for r in results if not r['correct']]

    accuracy = len(correct) / len(results) * 100

    # Count by type
    injections = [r for r in results if r['expected'] == 1]
    normal = [r for r in results if r['expected'] == 0]

    injection_correct = len([r for r in injections if r['correct']])
    normal_correct = len([r for r in normal if r['correct']])

    print(f"\nOverall Accuracy: {accuracy:.1f}% ({len(correct)}/{len(results)})")
    print(f"SQL Injection Detection: {injection_correct}/{len(injections)} ({injection_correct/len(injections)*100:.1f}%)")
    print(f"Normal Query Detection: {normal_correct}/{len(normal)} ({normal_correct/len(normal)*100:.1f}%)")

    if incorrect:
        print(f"\n{'='*80}")
        print("FAILED CASES:")
        print(f"{'='*80}")
        for r in incorrect:
            status = "MISSED INJECTION" if r['expected'] == 1 else "FALSE POSITIVE"
            print(f"\n[{status}] {r['description']}")
            print(f"  Query: {r['query']}")
            print(f"  Expected: {r['expected']}, Predicted: {r['predicted']}, Prob: {r['probability']:.4f}")

    return {
        'accuracy': accuracy,
        'injection_rate': injection_correct/len(injections)*100,
        'normal_rate': normal_correct/len(normal)*100,
        'failed_cases': incorrect
    }

def main():
    print("\n" + "#"*80)
    print("#" + " "*30 + "MODEL TESTING" + " "*35 + "#")
    print("#"*80)

    # Test ML models
    ml_results = test_ml_models()
    if ml_results:
        rf_stats = print_results(ml_results, "RANDOM FOREST")

    # Test DL models
    cnn_results, bilstm_results = test_dl_models()

    if cnn_results:
        cnn_stats = print_results(cnn_results, "CNN")

    if bilstm_results:
        bilstm_stats = print_results(bilstm_results, "BI-LSTM")

    # Summary
    print("\n" + "#"*80)
    print("#" + " "*30 + "SUMMARY" + " "*41 + "#")
    print("#"*80)

    print("\n| Model         | Overall | Injection Detection | Normal Detection |")
    print("|---------------|---------|---------------------|------------------|")
    if ml_results:
        print(f"| Random Forest | {rf_stats['accuracy']:5.1f}%  | {rf_stats['injection_rate']:17.1f}%  | {rf_stats['normal_rate']:14.1f}%  |")
    if cnn_results:
        print(f"| CNN           | {cnn_stats['accuracy']:5.1f}%  | {cnn_stats['injection_rate']:17.1f}%  | {cnn_stats['normal_rate']:14.1f}%  |")
    if bilstm_results:
        print(f"| Bi-LSTM       | {bilstm_stats['accuracy']:5.1f}%  | {bilstm_stats['injection_rate']:17.1f}%  | {bilstm_stats['normal_rate']:14.1f}%  |")

    # Recommendation
    print("\n" + "="*80)
    print("RECOMMENDATION")
    print("="*80)

    all_good = True

    if ml_results and rf_stats['injection_rate'] < 95:
        print("- Random Forest needs retraining: missing too many SQL injections")
        all_good = False

    if cnn_results and cnn_stats['injection_rate'] < 95:
        print("- CNN needs retraining: missing too many SQL injections")
        all_good = False

    if bilstm_results and bilstm_stats['injection_rate'] < 95:
        print("- Bi-LSTM needs retraining: missing too many SQL injections")
        all_good = False

    if all_good:
        print("All models are performing well! No retraining needed.")

    return ml_results, cnn_results, bilstm_results

if __name__ == "__main__":
    main()
