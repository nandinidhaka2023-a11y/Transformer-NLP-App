"""Turn SQL (or Python that contains SQL) into a plain-language summary."""

from __future__ import annotations

from typing import List, Optional

from sqlglot import exp, parse
from sqlglot.errors import ErrorLevel, ParseError, TokenError

from sql_analyzer.sql_extract import (
    extract_sql_snippets,
    first_function_name,
    looks_like_sql,
    source_executes_sql,
)


def summarize(source: str) -> str:
    source = source.strip()
    if not source:
        return "No SQL was provided."

    snippets = extract_sql_snippets(source)
    is_code = _looks_like_code(source)

    if not snippets:
        if looks_like_sql(source):
            return (
                "This looks like SQL, but it could not be fully parsed. "
                "Please check the syntax and try again."
            )
        return (
            "No SQL statement was detected in the input. "
            "Paste a SQL query or code that builds a SQL query."
        )

    parts: List[str] = []
    for snippet in snippets:
        parts.append(_summarize_sql_text(snippet))

    core = " ".join(p for p in parts if p)
    if not core:
        core = "A SQL statement was found, but it could not be described reliably."

    if is_code:
        return _wrap_code_context(source, core)
    return core


def _looks_like_code(source: str) -> bool:
    try:
        import ast

        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.Assign, ast.Call),
        ):
            return True
    return False


def _wrap_code_context(source: str, sql_summary: str) -> str:
    fn = first_function_name(source)
    executes = source_executes_sql(source)
    lowered = sql_summary[0].lower() + sql_summary[1:] if sql_summary else sql_summary

    if fn and executes:
        return (
            f"The `{fn}` function constructs and executes a SQL query. {sql_summary} "
            "The query is built using the supplied user input."
            if "user" in source.lower() or "input" in source.lower()
            else f"The `{fn}` function constructs and executes a SQL query. {sql_summary}"
        )
    if fn:
        prefix = f"The `{fn}` function constructs a SQL query. "
        if "user" in source.lower() or "input" in source.lower():
            return prefix + lowered.rstrip(".") + " using the supplied user input."
        return prefix + sql_summary
    if executes:
        return "This code constructs and executes a SQL query. " + sql_summary
    return "This code constructs a SQL query. " + sql_summary


def _summarize_sql_text(sql: str) -> str:
    try:
        statements = parse(sql, error_level=ErrorLevel.RAISE)
    except (ParseError, TokenError, IndexError, Exception):
        try:
            statements = parse(_repair_sql(sql), error_level=ErrorLevel.IGNORE)
        except Exception:
            return _fallback_summary(sql)

    if not statements:
        return _fallback_summary(sql)

    summaries: List[str] = []
    for stmt in statements:
        if stmt is None:
            continue
        summaries.append(_summarize_statement(stmt))

    if not summaries:
        return _fallback_summary(sql)
    return " ".join(summaries)


def _summarize_statement(stmt: exp.Expression) -> str:
    if isinstance(stmt, exp.Select) or isinstance(stmt, exp.Union):
        return _summarize_select_like(stmt)
    if isinstance(stmt, exp.Insert):
        return _summarize_insert(stmt)
    if isinstance(stmt, exp.Update):
        return _summarize_update(stmt)
    if isinstance(stmt, exp.Delete):
        return _summarize_delete(stmt)
    if isinstance(stmt, exp.Create):
        return _summarize_create(stmt)
    if isinstance(stmt, exp.Drop):
        kind = (stmt.args.get("kind") or "object")
        name = _ident(stmt.this) or "an object"
        return f"This statement drops the {str(kind).lower()} {name}."
    if isinstance(stmt, exp.Alter):
        name = _ident(stmt.this) or "a table"
        return f"This statement alters {name}."
    kind = stmt.key if hasattr(stmt, "key") else stmt.__class__.__name__
    return f"This statement performs a {kind} operation."


def _summarize_select_like(stmt: exp.Expression) -> str:
    unions = list(stmt.find_all(exp.Union)) if not isinstance(stmt, exp.Union) else [stmt]
    if isinstance(stmt, exp.Union) or (unions and stmt.find(exp.Union)):
        union_node = stmt if isinstance(stmt, exp.Union) else stmt.find(exp.Union)
        distinct = True
        if union_node is not None and union_node.args.get("distinct") is False:
            distinct = False
        combiner = "UNION" if distinct else "UNION ALL"
        left = union_node.this if union_node is not None else None
        right = union_node.expression if union_node is not None else None
        left_s = _summarize_select(left) if isinstance(left, exp.Select) else "a query"
        right_s = _summarize_select(right) if isinstance(right, exp.Select) else "another query"
        return (
            f"This query combines results using {combiner}. "
            f"First: {left_s} Second: {right_s}"
        )
    return _summarize_select(stmt) if isinstance(stmt, exp.Select) else (
        f"This statement performs a {stmt.key} operation."
    )


def _summarize_select(select: exp.Select) -> str:
    distinct = bool(select.args.get("distinct"))
    columns = _select_column_phrase(select)
    tables = _table_names(select)
    table_phrase = _table_phrase(tables)

    joins = list(select.find_all(exp.Join))
    join_phrase = _join_phrase(joins)

    where = select.args.get("where")
    where_phrase = _where_phrase(where.this) if where is not None else ""

    group = select.args.get("group")
    group_phrase = ""
    if group is not None:
        group_cols = [_expr_name(e) for e in group.expressions]
        group_phrase = _join_words(group_cols)

    having = select.args.get("having")
    having_phrase = _condition_english(having.this) if having is not None else ""

    order = select.args.get("order")
    order_phrase = _order_phrase(order)

    limit = select.args.get("limit")
    limit_n = None
    if limit is not None:
        limit_n = _literal(limit.expression) if hasattr(limit, "expression") else _literal(limit.this)

    subquery = _has_subquery(select)

    verb = "retrieves distinct" if distinct else "retrieves"
    sentence = f"This query {verb} {columns}"
    if table_phrase:
        sentence += f" from {table_phrase}"
    if join_phrase:
        sentence += f" {join_phrase}"
    if where_phrase:
        sentence += f" where {where_phrase}"
    if group_phrase:
        sentence += f", grouped by {group_phrase}"
    if having_phrase:
        sentence += f", keeping groups where {having_phrase}"
    if order_phrase:
        sentence += f", and sorts the results {order_phrase}"
    if limit_n is not None:
        sentence += f", returning at most {limit_n} row{'s' if str(limit_n) != '1' else ''}"
    if subquery:
        sentence += ". It includes a subquery"
    sentence += "."
    return _clean(sentence)


def _summarize_insert(insert: exp.Insert) -> str:
    table = _ident(insert.this) or _first_table(insert) or "a table"
    schema = insert.this if isinstance(insert.this, exp.Schema) else insert.args.get("schema")
    cols: List[str] = []
    if isinstance(insert.this, exp.Schema):
        table = _ident(insert.this.this) or table
        cols = [_ident(c) for c in insert.this.expressions]
    elif schema is not None and isinstance(schema, exp.Schema):
        table = _ident(schema.this) or table
        cols = [_ident(c) for c in schema.expressions]

    select = insert.expression if isinstance(insert.expression, exp.Select) else None
    if select is not None:
        col_bit = f", setting { _join_words(cols) }" if cols else ""
        return _clean(
            f"This query inserts rows into the {table} table{col_bit} "
            f"using the results of a subquery. {_summarize_select(select)}"
        )

    col_bit = f", setting {_join_words(cols)}" if cols else ""
    return _clean(f"This query inserts a new record into the {table} table{col_bit}.")


def _summarize_update(update: exp.Update) -> str:
    table = _ident(update.this) or _first_table(update) or "a table"
    assignments = []
    for expr in update.expressions:
        if isinstance(expr, exp.EQ):
            assignments.append(_expr_name(expr.left))
        else:
            assignments.append(_expr_name(expr))
    set_phrase = _join_words([a for a in assignments if a])
    where = update.args.get("where")
    where_phrase = _where_phrase(where.this) if where is not None else ""
    sentence = f"This query updates {set_phrase} in the {table} table" if set_phrase else (
        f"This query updates rows in the {table} table"
    )
    if where_phrase:
        sentence += f" where {where_phrase}"
    sentence += "."
    return _clean(sentence)


def _summarize_delete(delete: exp.Delete) -> str:
    table = _ident(delete.this) or _first_table(delete) or "a table"
    where = delete.args.get("where")
    where_phrase = _where_phrase(where.this) if where is not None else ""
    sentence = f"This query deletes records from the {table} table"
    if where_phrase:
        sentence += f" where {where_phrase}"
    else:
        sentence += " (all rows, because no WHERE clause is present)"
    sentence += "."
    return _clean(sentence)


def _summarize_create(create: exp.Create) -> str:
    kind = str(create.args.get("kind") or "object").lower()
    name = _ident(create.this) or "an object"
    if kind == "table":
        return f"This statement creates a table named {name}."
    return f"This statement creates a {kind} named {name}."


def _select_column_phrase(select: exp.Select) -> str:
    expressions = select.expressions or []
    if not expressions:
        return "rows"
    names: List[str] = []
    for expr in expressions:
        names.append(_projection_english(expr))
    if len(names) == 1 and names[0] in {"all columns", "*"}:
        return "all columns"
    return _join_words(names)


def _projection_english(expr: exp.Expression) -> str:
    if isinstance(expr, exp.Star) or (isinstance(expr, exp.Column) and expr.name == "*"):
        return "all columns"
    alias = expr.args.get("alias") if isinstance(expr, exp.Alias) else None
    inner = expr.this if isinstance(expr, exp.Alias) else expr
    if isinstance(inner, exp.Count):
        target = "*" if inner.this is None or isinstance(inner.this, exp.Star) else _expr_name(inner.this)
        base = "the count of rows" if target in {"*", ""} else f"the count of {target}"
        return f"{base} as {alias}" if alias else base
    if isinstance(inner, exp.Sum):
        base = f"the sum of {_expr_name(inner.this)}"
        return f"{base} as {alias}" if alias else base
    if isinstance(inner, exp.Avg):
        base = f"the average of {_expr_name(inner.this)}"
        return f"{base} as {alias}" if alias else base
    if isinstance(inner, exp.Min):
        base = f"the minimum of {_expr_name(inner.this)}"
        return f"{base} as {alias}" if alias else base
    if isinstance(inner, exp.Max):
        base = f"the maximum of {_expr_name(inner.this)}"
        return f"{base} as {alias}" if alias else base
    if isinstance(inner, exp.Case):
        base = "a CASE expression"
        return f"{base} as {alias}" if alias else base
    name = _expr_name(inner)
    if alias:
        return f"{name} as {alias}"
    return name


def _table_names(node: exp.Expression) -> List[str]:
    names: List[str] = []
    from_ = node.args.get("from") if isinstance(node, exp.Select) else None
    if from_ is not None:
        for table in from_.find_all(exp.Table):
            names.append(_ident(table))
    else:
        for table in node.find_all(exp.Table):
            names.append(_ident(table))
    # Unique, preserve order; join targets also appear via find_all
    seen = set()
    out = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _first_table(node: exp.Expression) -> Optional[str]:
    table = node.find(exp.Table)
    return _ident(table) if table is not None else None


def _table_phrase(tables: List[str]) -> str:
    if not tables:
        return ""
    if len(tables) == 1:
        return f"the {tables[0]} table"
    return "the " + " and ".join(f"{t} table" for t in tables)


def _join_phrase(joins: List[exp.Join]) -> str:
    if not joins:
        return ""
    bits = []
    for join in joins:
        kind = (join.args.get("side") or join.args.get("kind") or "inner")
        if isinstance(kind, str):
            kind_s = kind.lower()
        else:
            kind_s = str(kind).lower()
        table = _ident(join.this) or "another table"
        on = join.args.get("on")
        on_bit = f" on {_condition_english(on)}" if on is not None else ""
        article = "an" if kind_s[:1] in "aeiou" else "a"
        bits.append(f"using {article} {kind_s} join to the {table} table{on_bit}")
    return ", ".join(bits)


def _where_phrase(condition: exp.Expression) -> str:
    return _condition_english(condition)


def _order_phrase(order: Optional[exp.Expression]) -> str:
    if order is None:
        return ""
    items = []
    expressions = order.expressions if hasattr(order, "expressions") else []
    for item in expressions:
        desc = False
        expr = item
        if isinstance(item, exp.Ordered):
            desc = bool(item.args.get("desc"))
            expr = item.this
        name = _expr_name(expr)
        direction = "in descending order" if desc else ""
        if name.lower() in {"name", "title", "email", "username"} and not desc:
            items.append(f"alphabetically by {name}")
        elif direction:
            items.append(f"by {name} {direction}")
        else:
            items.append(f"by {name}")
    if not items:
        return ""
    return _join_words(items)


def _has_subquery(select: exp.Select) -> bool:
    subs = list(select.find_all(exp.Subquery)) + list(select.find_all(exp.Select))
    # The root select is included in find_all(Select)
    nested = [s for s in subs if s is not select]
    return len(nested) > 0


def _condition_english(node: Optional[exp.Expression]) -> str:
    if node is None:
        return ""
    if isinstance(node, exp.And):
        return f"{_condition_english(node.left)} and {_condition_english(node.right)}"
    if isinstance(node, exp.Or):
        return f"{_condition_english(node.left)} or {_condition_english(node.right)}"
    if isinstance(node, exp.Not):
        return f"not {_condition_english(node.this)}"
    if isinstance(node, exp.Paren):
        return _condition_english(node.this)
    if isinstance(node, exp.EQ):
        return f"{_expr_name(node.left)} is {_literal_or_name(node.right)}"
    if isinstance(node, exp.NEQ):
        return f"{_expr_name(node.left)} is not {_literal_or_name(node.right)}"
    if isinstance(node, exp.GT):
        return f"{_expr_name(node.left)} is greater than {_literal_or_name(node.right)}"
    if isinstance(node, exp.GTE):
        return f"{_expr_name(node.left)} is at least {_literal_or_name(node.right)}"
    if isinstance(node, exp.LT):
        return f"{_expr_name(node.left)} is less than {_literal_or_name(node.right)}"
    if isinstance(node, exp.LTE):
        return f"{_expr_name(node.left)} is at most {_literal_or_name(node.right)}"
    if isinstance(node, exp.Like):
        return f"{_expr_name(node.this)} matches {_literal_or_name(node.expression)}"
    if isinstance(node, exp.In):
        query = node.args.get("query")
        if query is not None:
            return f"{_expr_name(node.this)} is in a subquery"
        vals = ", ".join(_literal_or_name(v) for v in node.expressions)
        return f"{_expr_name(node.this)} is in ({vals})"
    if isinstance(node, exp.Between):
        return (
            f"{_expr_name(node.this)} is between {_literal_or_name(node.args.get('low'))} "
            f"and {_literal_or_name(node.args.get('high'))}"
        )
    if isinstance(node, exp.Is):
        return f"{_expr_name(node.this)} is {_literal_or_name(node.expression)}"
    if isinstance(node, exp.Exists):
        return "a matching subquery exists"
    return _expr_name(node)


def _expr_name(node: Optional[exp.Expression]) -> str:
    if node is None:
        return ""
    if isinstance(node, exp.Column):
        name = node.name or node.sql()
        table = node.table
        if table:
            return f"{table}.{name}"
        return name
    if isinstance(node, exp.Count):
        target = node.this
        if target is None or isinstance(target, exp.Star):
            return "the row count"
        return f"the count of {_expr_name(target)}"
    if isinstance(node, exp.Table):
        return node.name
    if isinstance(node, exp.Identifier):
        return node.name
    if isinstance(node, exp.Alias):
        return str(node.args.get("alias") or _expr_name(node.this))
    if isinstance(node, exp.Literal):
        return _literal(node)
    if isinstance(node, exp.Star):
        return "*"
    if isinstance(node, exp.Null):
        return "NULL"
    if isinstance(node, exp.Boolean):
        return "true" if node.this else "false"
    if isinstance(node, exp.Anonymous):
        return node.sql()
    try:
        return node.sql()
    except Exception:
        return str(node)


def _ident(node: Optional[exp.Expression]) -> str:
    if node is None:
        return ""
    if isinstance(node, exp.Table):
        return node.name
    if isinstance(node, exp.Schema):
        return _ident(node.this)
    if isinstance(node, exp.Identifier):
        return node.name
    if isinstance(node, exp.Alias):
        return _ident(node.this)
    if hasattr(node, "name") and node.name:
        return node.name
    try:
        sql = node.sql()
        return sql.split()[0].strip('"[]`')
    except Exception:
        return ""


def _literal(node: Optional[exp.Expression]) -> str:
    if node is None:
        return ""
    if isinstance(node, exp.Literal):
        return str(node.this)
    if isinstance(node, exp.Identifier):
        return node.name
    return _expr_name(node)


def _literal_or_name(node: Optional[exp.Expression]) -> str:
    if node is None:
        return ""
    if isinstance(node, exp.Literal):
        value = str(node.this)
        if node.is_string:
            return value
        return value
    if isinstance(node, exp.Column):
        return _expr_name(node)
    if isinstance(node, exp.Select) or isinstance(node, exp.Subquery):
        return "a subquery"
    if isinstance(node, exp.Placeholder) or (hasattr(node, "sql") and node.sql() in {"?", "%s"}):
        return "a bound parameter"
    return _expr_name(node)


def _join_words(items: List[str]) -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _clean(text: str) -> str:
    text = " ".join(text.split())
    text = text.replace(" ,", ",").replace("..", ".")
    text = text.replace(" .", ".")
    if text and text[0].islower():
        text = text[0].upper() + text[1:]
    return text


def _repair_sql(sql: str) -> str:
    """Close obvious quote damage from reconstructing concatenated SQL."""
    repaired = sql.replace("= '", "= 'input'").replace("= \"", '= "input"')
    singles = repaired.count("'") - repaired.count("\\'")
    if singles % 2 == 1:
        repaired += "'"
    doubles = repaired.count('"')
    if doubles % 2 == 1:
        repaired += '"'
    return repaired


def _fallback_summary(sql: str) -> str:
    upper = sql.upper()
    if "SELECT" in upper:
        return (
            "This looks like a SELECT query, but the SQL could not be fully parsed. "
            "No extra operations were assumed."
        )
    if "INSERT" in upper:
        return "This looks like an INSERT statement, but it could not be fully parsed."
    if "UPDATE" in upper:
        return "This looks like an UPDATE statement, but it could not be fully parsed."
    if "DELETE" in upper:
        return "This looks like a DELETE statement, but it could not be fully parsed."
    return "The SQL could not be parsed, so no operation was assumed."
