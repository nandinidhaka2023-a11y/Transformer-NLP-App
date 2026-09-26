"""Example SQL and code snippets for the Streamlit UI."""

EXAMPLES = {
    "Simple SELECT": """SELECT name, email
FROM users
WHERE age > 18
ORDER BY name;""",
    "JOIN + WHERE": """SELECT u.name, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id
WHERE o.total > 100;""",
    "GROUP BY + COUNT": """SELECT department, COUNT(*) AS headcount
FROM employees
GROUP BY department
HAVING COUNT(*) > 5
ORDER BY headcount DESC;""",
    "INSERT": """INSERT INTO users (name, email)
VALUES ('Ada', 'ada@example.com');""",
    "UPDATE": """UPDATE users
SET email = 'new@example.com'
WHERE id = 5;""",
    "DELETE": """DELETE FROM users
WHERE id = 5;""",
    "Subquery": """SELECT name
FROM users
WHERE id IN (
    SELECT user_id FROM orders WHERE total > 500
);""",
    "Safe parameterized SQL": '''cursor.execute(
    "SELECT * FROM users WHERE name = ?",
    (user_input,)
)''',
    "SQL injection (concatenation)": '''def login(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    execute(query)''',
    "SQL injection (f-string)": '''query = f"SELECT * FROM users WHERE name = '{user_input}'"
cursor.execute(query)''',
    "SQL injection (.format)": '''query = "SELECT * FROM users WHERE id = {}".format(user_id)
cursor.execute(query)''',
}
