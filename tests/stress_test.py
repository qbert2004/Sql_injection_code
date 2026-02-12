"""
Stress Test — SQL Injection Detector Break Attempt
=====================================================
Tests designed to expose weaknesses in the detector:
  1. Advanced obfuscation attacks (should be BLOCKED)
  2. Bypass attempts (should be BLOCKED)
  3. False positive traps (should NOT be blocked)
  4. Edge cases (empty, huge, unicode, etc.)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sql_injection_detector import SQLInjectionEnsemble

detector = SQLInjectionEnsemble()

PASS = 0
FAIL = 0
RESULTS = []


def check(test_input, expected_blocked, category, description):
    """Check a single test case."""
    global PASS, FAIL
    try:
        result = detector.detect(test_input)
        is_blocked = result['action'] in ('BLOCK', 'ALERT')
        decision = result['decision']
        score = result['score']
        cnn = result['P_cnn']
        rf = result['P_rf']
        sem = result['semantic_score']
        rule = result['rule']

        if is_blocked == expected_blocked:
            status = "PASS"
            PASS += 1
        else:
            status = "FAIL"
            FAIL += 1

        display = test_input[:50] + '..' if len(test_input) > 52 else test_input
        RESULTS.append({
            'status': status,
            'category': category,
            'description': description,
            'input': display,
            'expected': 'BLOCK' if expected_blocked else 'ALLOW',
            'actual': result['action'],
            'decision': decision,
            'score': score,
            'cnn': cnn,
            'rf': rf,
            'sem': sem,
            'rule': rule,
        })
    except Exception as e:
        FAIL += 1
        RESULTS.append({
            'status': 'ERROR',
            'category': category,
            'description': description,
            'input': test_input[:50],
            'expected': 'BLOCK' if expected_blocked else 'ALLOW',
            'actual': f'ERROR: {e}',
            'decision': '-',
            'score': 0,
            'cnn': 0,
            'rf': 0,
            'sem': 0,
            'rule': '-',
        })


print("=" * 120)
print("STRESS TEST — Trying to break the SQL Injection Detector")
print("=" * 120)

# ═══════════════════════════════════════════════════════════════════
# CATEGORY 1: ADVANCED OBFUSCATION (should be BLOCKED)
# ═══════════════════════════════════════════════════════════════════
print("\n[1] Advanced Obfuscation Attacks...")

# Comment-based obfuscation
check("'/**/OR/**/1/**/=/**/1--", True, "OBFUSCATION", "Inline comments in every gap")
check("UN/**/ION/**/SEL/**/ECT/**/1,2,3--", True, "OBFUSCATION", "UNION SELECT split by comments")
check("' /*!50000OR*/ 1=1--", True, "OBFUSCATION", "MySQL version-specific comment")

# Case alternation
check("' oR '1'='1", True, "OBFUSCATION", "Mixed case OR")
check("' UnIoN SeLeCt NULL--", True, "OBFUSCATION", "Mixed case UNION SELECT")
check("'; DrOp TaBlE users--", True, "OBFUSCATION", "Mixed case DROP TABLE")

# Whitespace alternatives
check("'\tOR\t1=1--", True, "OBFUSCATION", "Tab-separated")
check("'\nOR\n1=1--", True, "OBFUSCATION", "Newline-separated")
check("'\r\nOR\r\n1=1--", True, "OBFUSCATION", "CRLF-separated")

# Double URL encoding
check("%2527%2520OR%25201%253D1--", True, "OBFUSCATION", "Double URL encoded")
check("%252527%252520OR%2525201%25253D1", True, "OBFUSCATION", "Triple URL encoded")

# Hex encoding
check("' OR 0x31=0x31--", True, "OBFUSCATION", "Hex comparison")
check("' UNION SELECT CHAR(117,115,101,114)--", True, "OBFUSCATION", "CHAR() function")

# Concatenation tricks
check("' OR 'a'||'b'='ab'--", True, "OBFUSCATION", "String concatenation bypass")
check("' OR CONCAT('1','')='1'--", True, "OBFUSCATION", "CONCAT function bypass")

# No-quote injection
check("1 OR 1=1", True, "OBFUSCATION", "No-quote numeric injection")
check("1; DROP TABLE users", True, "OBFUSCATION", "No-quote stacked query")

# ═══════════════════════════════════════════════════════════════════
# CATEGORY 2: BYPASS ATTEMPTS (should be BLOCKED)
# ═══════════════════════════════════════════════════════════════════
print("[2] Bypass Attempts...")

# Null byte injection
check("' OR '1'='1'\x00--", True, "BYPASS", "Null byte mid-query")
check("admin'\x00--", True, "BYPASS", "Null byte after admin")

# Double encoding
check("%27%20OR%201%3D1%2D%2D", True, "BYPASS", "URL encoded full payload")

# HPP style
check("' OR ''='", True, "BYPASS", "Empty string comparison")
check("' OR 1 LIKE 1--", True, "BYPASS", "LIKE-based tautology")
check("' OR 1 BETWEEN 0 AND 2--", True, "BYPASS", "BETWEEN-based tautology")

# WAF bypass classics
check("-1' UNION SELECT 1,2,3--", True, "BYPASS", "Negative prefix UNION")
check("1' AND 1=1 UNION SELECT 1,2,3--", True, "BYPASS", "AND + UNION combo")
check("') OR ('1'='1", True, "BYPASS", "Parenthesis-wrapped tautology")
check("')) OR (('1'='1", True, "BYPASS", "Double-paren tautology")

# Second-order style
check("'; EXEC master..xp_cmdshell 'dir'--", True, "BYPASS", "MSSQL xp_cmdshell")
check("'; EXEC sp_configure 'show advanced options',1--", True, "BYPASS", "MSSQL sp_configure")

# PostgreSQL specific
check("'; SELECT pg_sleep(5)--", True, "BYPASS", "PostgreSQL pg_sleep")
check("' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--", True, "BYPASS", "CASE WHEN blind")

# Oracle specific
check("' AND UTL_INADDR.get_host_address('test')='x'--", True, "BYPASS", "Oracle UTL_INADDR")

# ═══════════════════════════════════════════════════════════════════
# CATEGORY 3: FALSE POSITIVE TRAPS (should NOT be blocked)
# ═══════════════════════════════════════════════════════════════════
print("[3] False Positive Traps...")

# SQL-like but legitimate
check("The DROP in temperature was 10 degrees", False, "FALSE_POS", "DROP in weather")
check("Please SELECT your preferred option from the menu", False, "FALSE_POS", "SELECT in UI text")
check("I need to UPDATE my address", False, "FALSE_POS", "UPDATE in instruction")
check("DELETE the old messages from your inbox", False, "FALSE_POS", "DELETE in instruction")
check("The UNION of two sets is A or B", False, "FALSE_POS", "UNION in math")
check("INSERT your card into the reader", False, "FALSE_POS", "INSERT in instruction")

# Names with apostrophes
check("Shaquille O'Neal", False, "FALSE_POS", "Basketball player")
check("Conan O'Brien", False, "FALSE_POS", "TV host")
check("L'Oreal Paris", False, "FALSE_POS", "Brand name")
check("Rock 'n Roll is dead", False, "FALSE_POS", "Music genre")
check("My daughter's friend's mother's car", False, "FALSE_POS", "Multiple possessives")

# Technical but safe
check("SELECT * FROM users WHERE id = 1", False, "FALSE_POS", "Legit SQL in docs")
check("The query SELECT COUNT(*) returns the total", False, "FALSE_POS", "SQL in tutorial")
check("Use ORDER BY to sort results", False, "FALSE_POS", "SQL keyword in guide")
check("x = 1 OR x = 2", False, "FALSE_POS", "Programming logic")
check("if (a == 1 && b == 2) return true", False, "FALSE_POS", "Code snippet")

# Emails and URLs
check("user@select-union.com", False, "FALSE_POS", "Email with SQL words")
check("https://example.com/drop/table/design.html", False, "FALSE_POS", "URL with SQL-like paths")

# Numbers that look like tautologies
check("Room 101 or 102", False, "FALSE_POS", "Room numbers with OR")
check("Choose 1 or 2 items", False, "FALSE_POS", "Count with OR")
check("Score: 1-1 tie", False, "FALSE_POS", "Sports score")
check("Temperature: -1 to 1 degrees", False, "FALSE_POS", "Temperature range")

# Unicode / international
check("Привет мир", False, "FALSE_POS", "Russian greeting")
check("こんにちは", False, "FALSE_POS", "Japanese greeting")
check("SELECT 好的商品", False, "FALSE_POS", "Chinese with SELECT")

# Long legitimate text
check("This is a very long normal text that contains no SQL injection whatsoever. " * 10, False, "FALSE_POS", "Long safe text")

# ═══════════════════════════════════════════════════════════════════
# CATEGORY 4: EDGE CASES
# ═══════════════════════════════════════════════════════════════════
print("[4] Edge Cases...")

# Empty / minimal
check("", False, "EDGE", "Empty string")
check(" ", False, "EDGE", "Single space")
check("a", False, "EDGE", "Single char")
check("'", False, "EDGE", "Single quote only")
check("--", False, "EDGE", "Comment only")
check(";", False, "EDGE", "Semicolon only")
check("=", False, "EDGE", "Equals only")

# Very long input
check("A" * 50000, False, "EDGE", "50K char string")
check("' OR '1'='1" * 1000, True, "EDGE", "Repeated injection x1000")

# Special characters overload
check("!@#$%^&*()_+-=[]{}|;':\",./<>?" * 10, False, "EDGE", "Special chars flood")

# Null bytes
check("\x00\x00\x00", False, "EDGE", "Only null bytes")

# Mix of attacks
check("' OR 1=1; DROP TABLE users; SELECT * FROM admin--", True, "EDGE", "Multi-attack combo")

# Unicode SQL
check("\uff27' OR '1'='1", True, "EDGE", "Fullwidth + injection")
check("' OR \u20181\u2019=\u20181\u2019", True, "EDGE", "Smart quotes injection")


# ═══════════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 120)
print(f"RESULTS: {PASS} passed, {FAIL} failed out of {PASS + FAIL} total")
print("=" * 120)

# Print failures
failures = [r for r in RESULTS if r['status'] != 'PASS']
if failures:
    print(f"\n{'='*120}")
    print(f"FAILURES ({len(failures)}):")
    print(f"{'='*120}")
    for r in failures:
        print(f"\n  [{r['status']}] {r['category']}: {r['description']}")
        print(f"    Input:    {r['input']}")
        print(f"    Expected: {r['expected']}")
        print(f"    Actual:   {r['actual']} (decision={r['decision']})")
        print(f"    Scores:   S={r['score']:.3f}, CNN={r['cnn']:.3f}, RF={r['rf']:.3f}, Sem={r['sem']:.1f}")
        print(f"    Rule:     {r['rule']}")
else:
    print("\n  ALL TESTS PASSED!")

# Category summary
print(f"\n{'='*120}")
print("CATEGORY SUMMARY:")
print(f"{'='*120}")
categories = {}
for r in RESULTS:
    cat = r['category']
    if cat not in categories:
        categories[cat] = {'pass': 0, 'fail': 0}
    if r['status'] == 'PASS':
        categories[cat]['pass'] += 1
    else:
        categories[cat]['fail'] += 1

for cat, counts in categories.items():
    total = counts['pass'] + counts['fail']
    pct = counts['pass'] / total * 100 if total > 0 else 0
    status = "OK" if counts['fail'] == 0 else "ISSUES"
    print(f"  {cat:<15} {counts['pass']}/{total} passed ({pct:.0f}%) [{status}]")

print(f"\n{'='*120}")
print(f"OVERALL: {PASS}/{PASS+FAIL} ({PASS/(PASS+FAIL)*100:.1f}%)")
print(f"{'='*120}")
