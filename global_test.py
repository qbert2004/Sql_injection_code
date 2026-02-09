"""
Global Test - 50 queries to stress test the SQL Injection Agent
"""
from sql_injection_detector import SQLInjectionEnsemble

detector = SQLInjectionEnsemble()

# 50 test cases across different categories
test_cases = [
    # === SAFE INPUTS (should be SAFE/ALLOW) ===
    ('admin', 'Safe: simple username'),
    ('john_doe', 'Safe: underscore username'),
    ('user123', 'Safe: alphanumeric'),
    ('hello@email.com', 'Safe: email'),
    ("John O'Brien", 'Safe: Irish name'),
    ("McDonald's", 'Safe: brand with apostrophe'),
    ("It's a test", 'Safe: contraction'),
    ('password123', 'Safe: password'),
    ('2024-01-15', 'Safe: date format'),
    ('192.168.1.1', 'Safe: IP address'),
    ('+1-555-123-4567', 'Safe: phone number'),
    ('C:/Users/Admin', 'Edge: path with users'),

    # === INVALID/MALFORMED (should be INVALID/LOG, not BLOCK) ===
    ("'1'1'1'1'11'1'1", 'Invalid: quote garbage'),
    ("'''''''", 'Invalid: only quotes'),
    ('====', 'Invalid: only equals'),
    ("'abc'=", 'Invalid: incomplete comparison'),
    ("'''=='''", 'Invalid: quote-equals mess'),
    ('???...', 'Invalid: punctuation spam'),
    ('asdf;lkj;', 'Invalid: keyboard mash'),
    ("'fqule' = Robert O'nill", 'Invalid: malformed quote'),
    ('1+1=2', 'Invalid: math equation'),
    ("x' AND y' OR z'", 'Edge: AND/OR with quotes'),
    ("'''''a'''''", 'Invalid: embedded char'),

    # === SQL INJECTIONS (should be INJECTION/BLOCK) ===
    ("' OR '1'='1", 'SQLi: classic OR'),
    ("' OR 1=1--", 'SQLi: OR with comment'),
    ("admin'--", 'SQLi: comment injection'),
    ("' OR 'a'='a", 'SQLi: string tautology'),
    ("1' OR '1'='1' --", 'SQLi: full classic'),
    ("'; DROP TABLE users--", 'SQLi: stacked query'),
    ("' UNION SELECT * FROM users--", 'SQLi: UNION'),
    ("' UNION SELECT username,password FROM users--", 'SQLi: UNION specific'),
    ("' AND 1=1--", 'SQLi: AND tautology'),
    ("' AND SLEEP(5)--", 'SQLi: time-based'),
    ("' AND BENCHMARK(10000000,SHA1('test'))--", 'SQLi: benchmark'),
    ("admin' AND 1=1#", 'SQLi: MySQL comment'),
    ("' OR 1=1/*", 'SQLi: block comment'),
    ("||(SELECT user FROM dual)||", 'SQLi: Oracle concat'),
    ("; EXEC xp_cmdshell('dir')--", 'SQLi: MSSQL cmdshell'),

    # === OBFUSCATED INJECTIONS (tricky - should still BLOCK) ===
    ("' oR '1'='1", 'SQLi obf: mixed case'),
    ("'/**/OR/**/1=1--", 'SQLi obf: comment bypass'),
    ('%27%20OR%201=1--', 'SQLi obf: URL encoded'),
    ("' OR 1=1-- -", 'SQLi obf: double dash space'),
    ("'OR'1'='1", 'SQLi obf: no spaces'),

    # === EDGE CASES (gray area - not strict expectations) ===
    ('SELECT', 'Edge: SQL keyword alone'),
    ('OR', 'Edge: logic keyword alone'),
    ('1=1', 'Edge: tautology alone'),
    ("'test", 'Edge: single quote only'),
    ("test'", 'Edge: trailing quote'),
    ('--comment', 'Edge: comment alone'),
    ('users; --', 'Edge: word with comment'),
]

print('='*100)
print('SQL INJECTION AGENT - GLOBAL TEST (50 queries)')
print('='*100)
print()

results = {'SAFE': [], 'INVALID': [], 'SUSPICIOUS': [], 'INJECTION': []}
errors = []

for i, (query, description) in enumerate(test_cases, 1):
    try:
        r = detector.detect(query)
        decision = r['decision']
        action = r['action']
        score = r['score']
        sem = r['semantic_score']

        results[decision].append((query, description, action, score, sem))

        # Check for potential errors
        expected_block = 'SQLi' in description
        expected_safe = description.startswith('Safe:')
        expected_invalid = description.startswith('Invalid:')

        is_error = False
        error_type = ''

        if expected_safe and decision not in ['SAFE']:
            is_error = True
            error_type = f'FALSE POSITIVE: Safe input classified as {decision}'
        elif expected_invalid and action == 'BLOCK':
            is_error = True
            error_type = f'FALSE POSITIVE: Invalid input BLOCKED'
        elif expected_block and action != 'BLOCK':
            is_error = True
            error_type = f'FALSE NEGATIVE: SQLi not blocked (got {action})'

        status = 'ERROR' if is_error else 'OK'
        status_symbol = '!!!' if is_error else '   '

        print(f'{status_symbol} [{i:2d}] {description:<40} | {decision:<10} {action:<10} S={score:.2f} sem={sem:.1f}')

        if is_error:
            errors.append((query, description, decision, action, error_type))

    except Exception as e:
        print(f'!!! [{i:2d}] {description:<40} | EXCEPTION: {e}')
        errors.append((query, description, 'EXCEPTION', str(e), str(e)))

print()
print('='*100)
print('SUMMARY')
print('='*100)
print(f'Total tests: {len(test_cases)}')
print(f'  SAFE:       {len(results["SAFE"])}')
print(f'  INVALID:    {len(results["INVALID"])}')
print(f'  SUSPICIOUS: {len(results["SUSPICIOUS"])}')
print(f'  INJECTION:  {len(results["INJECTION"])}')
print()
print(f'ERRORS FOUND: {len(errors)}')

if errors:
    print()
    print('='*100)
    print('ERRORS DETAIL')
    print('='*100)
    for query, desc, decision, action, error_type in errors:
        print(f'  Query: {repr(query)[:60]}')
        print(f'  Desc:  {desc}')
        print(f'  Got:   {decision}/{action}')
        print(f'  Error: {error_type}')
        print()
else:
    print()
    print('*** ALL TESTS PASSED ***')
