"""
Stress Test - 150+ queries for production readiness
Categories:
1. Real-world safe inputs
2. OWASP Top SQLi payloads
3. Obfuscation techniques
4. Encoding bypasses
5. Edge cases and tricky inputs
6. False positive traps
"""
from sql_injection_detector import SQLInjectionEnsemble
import time

detector = SQLInjectionEnsemble()

test_cases = [
    # ============================================================
    # CATEGORY 1: REAL-WORLD SAFE INPUTS (must be SAFE/ALLOW)
    # ============================================================
    # Names
    ("John", "Safe: simple name"),
    ("Mary Jane", "Safe: two words"),
    ("O'Connor", "Safe: Irish name"),
    ("D'Angelo", "Safe: Italian name"),
    ("Jean-Pierre", "Safe: hyphenated"),
    ("Müller", "Safe: umlaut"),
    ("Иванов", "Safe: Cyrillic"),
    ("田中", "Safe: Japanese"),
    ("McDonald's Restaurant", "Safe: brand"),

    # Emails & URLs
    ("user@example.com", "Safe: email"),
    ("test.user+tag@sub.domain.co.uk", "Safe: complex email"),
    ("https://example.com/path?q=test", "Safe: URL"),
    ("ftp://files.server.com/data", "Safe: FTP URL"),

    # Numbers & IDs
    ("12345", "Safe: numeric ID"),
    ("ABC-123-XYZ", "Safe: product code"),
    ("550e8400-e29b-41d4-a716-446655440000", "Safe: UUID"),
    ("+1 (555) 123-4567", "Safe: phone"),
    ("192.168.1.1", "Safe: IP v4"),
    ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "Safe: IP v6"),

    # Dates & Times
    ("2024-01-15", "Safe: ISO date"),
    ("15/01/2024", "Safe: EU date"),
    ("01-15-2024", "Safe: US date"),
    ("14:30:00", "Safe: time"),
    ("2024-01-15T14:30:00Z", "Safe: ISO datetime"),

    # Text content
    ("Hello, how are you?", "Safe: greeting"),
    ("The quick brown fox jumps over the lazy dog", "Safe: pangram"),
    ("Price: $99.99", "Safe: price"),
    ("50% discount!", "Safe: percentage"),
    ("C++ programming", "Safe: programming lang"),
    ("node.js", "Safe: tech name"),
    ("It's working!", "Safe: contraction"),
    ("Don't worry", "Safe: contraction 2"),
    ("Rock & Roll", "Safe: ampersand"),
    ("1 + 1 = 2", "Safe: math"),
    ("a < b && b > c", "Safe: code operators"),

    # Paths & Files
    ("/home/user/documents", "Safe: unix path"),
    ("C:\\Windows\\System32", "Safe: windows path"),
    ("file.txt", "Safe: filename"),
    ("image.jpg", "Safe: image file"),
    ("report_2024.pdf", "Safe: pdf file"),

    # ============================================================
    # CATEGORY 2: OWASP TOP SQL INJECTION PAYLOADS (must BLOCK)
    # ============================================================
    # Classic injections
    ("' OR '1'='1", "SQLi: classic OR tautology"),
    ("' OR '1'='1'--", "SQLi: OR with comment"),
    ("' OR '1'='1'/*", "SQLi: OR with block comment"),
    ("' OR ''='", "SQLi: empty string tautology"),
    ("' OR 1=1--", "SQLi: numeric tautology"),
    ("' OR 1=1#", "SQLi: MySQL comment"),
    ("admin'--", "SQLi: comment bypass login"),
    ("admin' #", "SQLi: MySQL comment login"),
    ("' OR 'x'='x", "SQLi: string tautology"),

    # AND-based
    ("' AND '1'='1", "SQLi: AND tautology"),
    ("' AND 1=1--", "SQLi: AND numeric"),
    ("1' AND '1'='1", "SQLi: AND prefix"),

    # UNION-based
    ("' UNION SELECT NULL--", "SQLi: UNION NULL"),
    ("' UNION SELECT 1,2,3--", "SQLi: UNION columns"),
    ("' UNION SELECT username,password FROM users--", "SQLi: UNION data"),
    ("' UNION ALL SELECT NULL--", "SQLi: UNION ALL"),
    ("' UNION SELECT @@version--", "SQLi: UNION version"),
    ("1' UNION SELECT * FROM information_schema.tables--", "SQLi: UNION schema"),

    # Stacked queries
    ("'; DROP TABLE users--", "SQLi: DROP TABLE"),
    ("'; DELETE FROM users--", "SQLi: DELETE"),
    ("'; UPDATE users SET password='hacked'--", "SQLi: UPDATE"),
    ("'; INSERT INTO users VALUES('hacker','pass')--", "SQLi: INSERT"),
    ("'; TRUNCATE TABLE logs--", "SQLi: TRUNCATE"),

    # Time-based blind
    ("' AND SLEEP(5)--", "SQLi: MySQL SLEEP"),
    ("' AND BENCHMARK(10000000,SHA1('x'))--", "SQLi: BENCHMARK"),
    ("'; WAITFOR DELAY '0:0:5'--", "SQLi: MSSQL WAITFOR"),
    ("' AND pg_sleep(5)--", "SQLi: PostgreSQL sleep"),
    ("' AND DBMS_LOCK.SLEEP(5)--", "SQLi: Oracle sleep"),

    # Boolean-based blind
    ("' AND 1=1 AND 'a'='a", "SQLi: boolean true"),
    ("' AND 1=2 AND 'a'='a", "SQLi: boolean false"),
    ("' AND SUBSTRING(username,1,1)='a'--", "SQLi: substring"),
    ("' AND ASCII(SUBSTRING(password,1,1))>64--", "SQLi: ASCII blind"),

    # Error-based
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "SQLi: extractvalue"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--", "SQLi: updatexml"),
    ("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "SQLi: error group by"),

    # Second-order / stored
    ("admin'-- stored for later", "SQLi: second order attempt"),

    # ============================================================
    # CATEGORY 3: OBFUSCATION TECHNIQUES (must still BLOCK)
    # ============================================================
    # Case variation
    ("' oR '1'='1", "SQLi obf: lowercase or"),
    ("' OR '1'='1", "SQLi obf: uppercase OR"),
    ("' oR '1'='1", "SQLi obf: mixed case"),
    ("' UnIoN SeLeCt NULL--", "SQLi obf: mixed UNION"),

    # Whitespace manipulation
    ("'OR'1'='1", "SQLi obf: no spaces"),
    ("'  OR  '1'='1", "SQLi obf: extra spaces"),
    ("'\tOR\t'1'='1", "SQLi obf: tabs"),
    ("'\nOR\n'1'='1", "SQLi obf: newlines"),
    ("'\r\nOR\r\n'1'='1", "SQLi obf: CRLF"),

    # Comment insertion
    ("'/**/OR/**/1=1--", "SQLi obf: inline comments"),
    ("'/*foo*/OR/*bar*/1=1--", "SQLi obf: comments with text"),
    ("UN/**/ION/**/SE/**/LECT", "SQLi obf: split keywords"),

    # Encoding
    ("%27%20OR%201=1--", "SQLi obf: URL encoded"),
    ("%27%20UNION%20SELECT%20NULL--", "SQLi obf: URL UNION"),
    ("&#39; OR 1=1--", "SQLi obf: HTML entity"),
    ("\\' OR 1=1--", "SQLi obf: backslash escape"),

    # Alternative syntax
    ("' || '1'='1", "SQLi obf: concat operator"),
    ("' && '1'='1", "SQLi obf: AND operator"),
    ("-1' OR 1=1--", "SQLi obf: negative prefix"),
    ("1' OR 1=1 LIMIT 1--", "SQLi obf: with LIMIT"),

    # ============================================================
    # CATEGORY 4: INVALID/MALFORMED (must be INVALID/LOG, not BLOCK)
    # ============================================================
    ("''''''''", "Invalid: many quotes"),
    ("'a'b'c'd'e'", "Invalid: alternating quotes"),
    ("===", "Invalid: equals only"),
    (";;;", "Invalid: semicolons only"),
    ("---", "Invalid: dashes only"),
    ("'''='''", "Invalid: quote equals"),
    ("'test'='test", "Invalid: incomplete"),
    ("OR OR OR", "Invalid: repeated keywords"),
    ("SELECT SELECT", "Invalid: double keyword"),
    ("1'2'3'4'5", "Invalid: number-quote pattern"),
    ("@#$%^&*()", "Invalid: special chars only"),
    ("........", "Invalid: dots only"),
    ("'fqule' = Robert O'nill", "Invalid: malformed comparison"),
    ("x' y' z'", "Invalid: multiple trailing quotes"),
    ("'' '' '' ''", "Invalid: spaced empty quotes"),
    ("a=b=c=d", "Invalid: chained equals"),
    ("!@#$%'test'!@#$%", "Invalid: special wrapper"),
    ("null null null", "Invalid: null text"),
    ("undefined", "Invalid: js undefined"),
    ("NaN", "Invalid: NaN"),
    ("[object Object]", "Invalid: JS object string"),
    ("<script>alert(1)</script>", "Invalid: XSS not SQLi"),

    # ============================================================
    # CATEGORY 5: EDGE CASES / TRICKY (behavior may vary)
    # ============================================================
    ("SELECT", "Edge: keyword alone"),
    ("UNION", "Edge: UNION alone"),
    ("DROP", "Edge: DROP alone"),
    ("OR", "Edge: OR alone"),
    ("AND", "Edge: AND alone"),
    ("--", "Edge: comment alone"),
    ("/**/", "Edge: empty comment"),
    ("1=1", "Edge: tautology alone"),
    ("'", "Edge: single quote"),
    ("''", "Edge: two quotes"),
    ("' '", "Edge: quote space quote"),
    (";", "Edge: semicolon alone"),
    ("' --", "Edge: quote comment"),
    ("test'", "Edge: trailing quote"),
    ("'test", "Edge: leading quote"),
    ("test'test", "Edge: middle quote"),
    ("users", "Edge: table name word"),
    ("password", "Edge: column name word"),
    ("admin", "Edge: common username"),
    ("root", "Edge: root user"),
    ("database", "Edge: keyword as text"),
    ("table", "Edge: keyword as text 2"),
    ("select * from", "Edge: partial query"),
    ("WHERE id=1", "Edge: WHERE clause text"),

    # ============================================================
    # CATEGORY 6: FALSE POSITIVE TRAPS (must NOT block)
    # ============================================================
    ("It's 1 or 2 choices", "FP trap: natural OR"),
    ("You and I", "FP trap: natural AND"),
    ("Select your option", "FP trap: Select word"),
    ("Drop me a line", "FP trap: Drop word"),
    ("Update your profile", "FP trap: Update word"),
    ("Delete old files", "FP trap: Delete word"),
    ("Join our union", "FP trap: union word"),
    ("Insert coin to play", "FP trap: Insert word"),
    ("I'll be there", "FP trap: contraction"),
    ("Rock'n'Roll", "FP trap: apostrophes"),
    ("fish'n'chips", "FP trap: food name"),
    ("5 o'clock", "FP trap: time expression"),
    ("master's degree", "FP trap: possessive"),
    ("children's toys", "FP trap: possessive 2"),
    ("users guide", "FP trap: users word"),
    ("Select Committee", "FP trap: formal name"),
    ("European Union", "FP trap: org name"),
    ("National Guard", "FP trap: org name 2"),
]

print("=" * 110)
print("SQL INJECTION AGENT - PRODUCTION STRESS TEST")
print(f"Total test cases: {len(test_cases)}")
print("=" * 110)
print()

results = {'SAFE': 0, 'INVALID': 0, 'SUSPICIOUS': 0, 'INJECTION': 0}
errors = []
timings = []

for i, (query, description) in enumerate(test_cases, 1):
    try:
        start = time.time()
        r = detector.detect(query)
        elapsed = (time.time() - start) * 1000
        timings.append(elapsed)

        decision = r['decision']
        action = r['action']
        score = r['score']
        sem = r['semantic_score']

        results[decision] += 1

        # Determine expected behavior
        is_safe_input = description.startswith("Safe:") or description.startswith("FP trap:")
        is_invalid_input = description.startswith("Invalid:")
        is_sqli = description.startswith("SQLi")
        is_edge = description.startswith("Edge:")

        # Check for errors
        is_error = False
        error_type = ""

        if is_safe_input and action == 'BLOCK':
            is_error = True
            error_type = "FALSE POSITIVE: Safe input BLOCKED"
        elif is_invalid_input and action == 'BLOCK':
            is_error = True
            error_type = "FALSE POSITIVE: Invalid input BLOCKED"
        elif is_sqli and action != 'BLOCK':
            is_error = True
            error_type = f"FALSE NEGATIVE: SQLi not blocked ({action})"

        symbol = "!!!" if is_error else "   "

        # Show all results with color coding
        if is_error or is_edge:
            print(f"{symbol} [{i:3d}] {description:<45} | {decision:<10} {action:<10} S={score:.2f} sem={sem:.1f} {elapsed:.0f}ms")

        if is_error:
            errors.append({
                'query': query,
                'description': description,
                'decision': decision,
                'action': action,
                'score': score,
                'semantic': sem,
                'error_type': error_type
            })

    except Exception as e:
        print(f"!!! [{i:3d}] {description:<45} | EXCEPTION: {e}")
        errors.append({
            'query': query,
            'description': description,
            'error_type': f"EXCEPTION: {e}"
        })

print()
print("=" * 110)
print("RESULTS SUMMARY")
print("=" * 110)
print(f"Total tests:    {len(test_cases)}")
print(f"  SAFE:         {results['SAFE']}")
print(f"  INVALID:      {results['INVALID']}")
print(f"  SUSPICIOUS:   {results['SUSPICIOUS']}")
print(f"  INJECTION:    {results['INJECTION']}")
print()
print(f"Performance:")
print(f"  Avg time:     {sum(timings)/len(timings):.1f}ms")
print(f"  Min time:     {min(timings):.1f}ms")
print(f"  Max time:     {max(timings):.1f}ms")
print()
print(f"ERRORS:         {len(errors)}")

if errors:
    print()
    print("=" * 110)
    print("ERROR DETAILS")
    print("=" * 110)

    # Group by error type
    fp_errors = [e for e in errors if "FALSE POSITIVE" in e.get('error_type', '')]
    fn_errors = [e for e in errors if "FALSE NEGATIVE" in e.get('error_type', '')]

    if fp_errors:
        print(f"\n### FALSE POSITIVES ({len(fp_errors)}) - Should NOT have blocked:")
        for e in fp_errors:
            print(f"  Query:    {repr(e['query'])[:70]}")
            print(f"  Desc:     {e['description']}")
            print(f"  Got:      {e['decision']}/{e['action']} (S={e.get('score', 'N/A')}, sem={e.get('semantic', 'N/A')})")
            print()

    if fn_errors:
        print(f"\n### FALSE NEGATIVES ({len(fn_errors)}) - Should have BLOCKED:")
        for e in fn_errors:
            print(f"  Query:    {repr(e['query'])[:70]}")
            print(f"  Desc:     {e['description']}")
            print(f"  Got:      {e['decision']}/{e['action']} (S={e.get('score', 'N/A')}, sem={e.get('semantic', 'N/A')})")
            print()
else:
    print()
    print("=" * 110)
    print("*** ALL TESTS PASSED - READY FOR PRODUCTION ***")
    print("=" * 110)
