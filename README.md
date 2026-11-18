# SQL Insight

## 🚀 Live Demo

[![Live Demo](https://img.shields.io/badge/🚀%20Live%20Demo-Streamlit-red?style=for-the-badge)](https://transformer-nlp-app-dqj7zkajjrsweex6auy4pn.streamlit.app/)

Prototype link with screenshots of the project : https://drive.google.com/drive/folders/1VHkDIba9P8oKhQpYVJr3CQaeQ2h7mHX_?usp=sharing

Hybrid SQL summarizer** and **static security analyzer (SQLGlot parsing + FLAN-T5 explanations) in a single Streamlit app.

Paste one SQL query or a Python snippet that builds SQL, then click **Analyze**. The app returns:

1. **SQL summary**: the query is parsed with SQLGlot and summarized in plain language
2. **Transformer NLP explanation**: a Hugging Face FLAN-T5 model generates an easy-to-read explanation of the query
3. **Security analysis**: a risk level, detected vulnerability, explanation and recommended fix, using AST-based static checks for SQL Injection, Command Injection, Path Traversal, `eval`/`exec` misuse and hardcoded credentials

SQL is parsed with [sqlglot](https://github.com/tobymao/sqlglot), and a Hugging Face FLAN-T5 Transformer model turns the parsed structure into a plain-language explanation. Security checks walk Python ASTs, so whitespace and line breaks do not change the classification.

## Features

- Human-readable summaries for common SQL operations
- Transformer NLP explanations generated with Hugging Face FLAN-T5
- SQL injection detection for concatenation, f-strings, and `str.format`
- Recognition of parameterized `cursor.execute(sql, params)` as safe (for this rule set)
- Extra static checks: command injection, path traversal, `eval`/`exec`, hardcoded secrets
- One input, one button, three result cards: SQL summary, Transformer NLP explanation, Security analysis
- Example queries built into the UI
## SQL analysis examples

**Input**

```sql
SELECT name, email FROM users WHERE age > 18 ORDER BY name;
```

**Summary (paraphrased)**

Retrieves name and email from the users table where age is greater than 18, and sorts the results alphabetically by name.

**Input**

```sql
UPDATE users SET email = 'new@example.com' WHERE id = 5;
```

**Summary (paraphrased)**

Updates email in the users table where id is 5.

**Input**

```sql
DELETE FROM users WHERE id = 5;
```

**Summary (paraphrased)**

Deletes records from the users table where id is 5.

Supported structures include `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, joins, `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY`, `DISTINCT`, `LIMIT`, aggregates (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`), subqueries, aliases, `CASE`, and `UNION` when the parser can represent them.

Incomplete SQL is reported as unparsed. The app does not invent operations that are not in the input.

## Security examples

**Unsafe concatenation**

```python
def login(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    execute(query)
```

- Summary: the `login` function constructs and executes a query against `users` using supplied input
- Security: **HIGH — SQL Injection**
- Fix: parameterized queries / prepared statements

**Safe parameterized query**

```python
cursor.execute(
    "SELECT * FROM users WHERE name = ?",
    (user_input,)
)
```

- Security: **SAFE** under the current static rules
- A SAFE label is not a guarantee that the code is fully secure

Ordinary SQL such as `SELECT * FROM users WHERE id = 1;` is **not** classified as SQL injection.

Risk labels: SAFE, LOW, MEDIUM, HIGH, CRITICAL.

## Installation

```bash
cd Transformer-NLP-App
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the app

```bash
streamlit run app.py
```

Then open the URL Streamlit prints (typically http://localhost:8501).

## Tests

```bash
python -m pytest tests/ -q
```

Coverage includes simple `SELECT`, `JOIN` + `WHERE`, `GROUP BY` + `COUNT`, `INSERT`, `UPDATE`, `DELETE`, subqueries, parameterized SQL, concatenation / f-string / `format` injection, equivalent formatting of the same SQL, and the other security categories.

## Screenshots

Add UI captures here after running the app locally:

- Editor + Analyze action
- SQL summary card
- Security analysis card with risk badge

## Project layout

```
app.py                 Streamlit UI
sql_analyzer/          Summary, security, examples, pipeline
tests/                 Pytest suite
requirements.txt
```
