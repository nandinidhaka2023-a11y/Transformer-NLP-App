from sql_analyzer.pipeline import analyze
from sql_analyzer.security import analyze_security
from sql_analyzer.sql_summary import summarize


SELECT_SIMPLE = "SELECT name, email FROM users WHERE age > 18 ORDER BY name;"
SELECT_MULTILINE = """SELECT name, email
FROM users
WHERE age > 18
ORDER BY name;"""

JOIN_SQL = """
SELECT u.name, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id
WHERE o.total > 100;
"""

GROUP_SQL = """
SELECT department, COUNT(*) AS headcount
FROM employees
GROUP BY department;
"""

INSERT_SQL = "INSERT INTO users (name, email) VALUES ('Ada', 'ada@example.com');"
UPDATE_SQL = "UPDATE users SET email = 'new@example.com' WHERE id = 5;"
DELETE_SQL = "DELETE FROM users WHERE id = 5;"

SUBQUERY_SQL = """
SELECT name FROM users
WHERE id IN (SELECT user_id FROM orders WHERE total > 500);
"""

SAFE_PARAM = '''
cursor.execute(
    "SELECT * FROM users WHERE name = ?",
    (user_input,)
)
'''

SQLI_CONCAT = '''
def login(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    execute(query)
'''

SQLI_FSTRING = '''
query = f"SELECT * FROM users WHERE name = '{user_input}'"
cursor.execute(query)
'''

SQLI_FORMAT = '''
query = "SELECT * FROM users WHERE id = {}".format(user_id)
cursor.execute(query)
'''


def _sec(source: str):
    return analyze(source)["security"]


def test_simple_select_summary():
    text = summarize(SELECT_SIMPLE).lower()
    assert "name" in text and "email" in text
    assert "users" in text
    assert "18" in text
    assert "sort" in text or "order" in text
    assert "delete" not in text
    assert "insert" not in text


def test_join_where_summary():
    text = summarize(JOIN_SQL).lower()
    assert "users" in text
    assert "orders" in text
    assert "join" in text
    assert "100" in text
    assert "name" in text


def test_group_by_count_summary():
    text = summarize(GROUP_SQL).lower()
    assert "employees" in text
    assert "department" in text
    assert "count" in text
    assert "group" in text


def test_insert_summary():
    text = summarize(INSERT_SQL).lower()
    assert "insert" in text
    assert "users" in text
    assert "name" in text
    assert "email" in text


def test_update_summary():
    text = summarize(UPDATE_SQL).lower()
    assert "update" in text
    assert "email" in text
    assert "users" in text
    assert "5" in text


def test_delete_summary():
    text = summarize(DELETE_SQL).lower()
    assert "delete" in text
    assert "users" in text
    assert "5" in text


def test_subquery_summary():
    text = summarize(SUBQUERY_SQL).lower()
    assert "users" in text
    assert "subquery" in text or "orders" in text
    assert "select" in text or "retrieves" in text


def test_safe_parameterized_sql_not_injection():
    report = _sec(SAFE_PARAM)
    assert report["level"] == "SAFE"
    assert report["vulnerability"] == "No vulnerabilities found"


def test_sqli_concatenation():
    report = _sec(SQLI_CONCAT)
    assert report["level"] == "HIGH"
    assert report["vulnerability"] == "SQL Injection"


def test_sqli_fstring():
    report = _sec(SQLI_FSTRING)
    assert report["level"] == "HIGH"
    assert report["vulnerability"] == "SQL Injection"


def test_sqli_format():
    report = _sec(SQLI_FORMAT)
    assert report["level"] == "HIGH"
    assert report["vulnerability"] == "SQL Injection"


def test_same_sql_different_formatting_same_security():
    a = _sec(SELECT_SIMPLE)
    b = _sec(SELECT_MULTILINE)
    assert a["level"] == b["level"] == "SAFE"
    assert a["vulnerability"] == b["vulnerability"]


def test_ordinary_select_is_not_sqli():
    report = analyze_security("SELECT * FROM users WHERE id = 1;")
    assert report.level == "SAFE"
    assert report.vulnerability != "SQL Injection"


def test_command_injection():
    report = analyze_security("import os\nos.system(user_input)")
    assert report.vulnerability == "Command Injection"
    assert report.level in {"HIGH", "CRITICAL"}


def test_path_traversal():
    report = analyze_security("open('../etc/passwd')")
    assert report.vulnerability == "Path Traversal / Unsafe File Access"


def test_code_injection_eval():
    report = analyze_security("eval(user_code)")
    assert report.vulnerability == "Code Injection"
    assert report.level == "CRITICAL"


def test_hardcoded_secret():
    report = analyze_security('password = "S3cret-Value-99"')
    assert report.vulnerability == "Hardcoded Secrets/Credentials"


def test_invalid_sql_does_not_hallucinate_delete():
    text = summarize("SELEC name FROM").lower()
    assert "delete" not in text
    assert "insert" not in text


def test_login_code_mentions_users_and_input():
    text = summarize(SQLI_CONCAT).lower()
    assert "login" in text
    assert "users" in text
