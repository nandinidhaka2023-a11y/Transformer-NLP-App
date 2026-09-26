"""Extract SQL statements from raw SQL or Python source wrapping SQL."""

from __future__ import annotations

import ast
import re
from typing import List, Optional

SQL_START = re.compile(
    r"^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WITH|TRUNCATE|REPLACE|MERGE|GRANT|REVOKE|UNION)\b",
    re.IGNORECASE | re.DOTALL,
)


def looks_like_sql(text: str) -> bool:
    if not text or not text.strip():
        return False
    return bool(SQL_START.search(text.strip()))


def _const_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append("input")
        return "".join(parts)
    return None


def _binop_sql_string(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _binop_sql_string(node.left) or _const_str(node.left)
        right = _binop_sql_string(node.right) or _const_str(node.right)
        if left is None:
            left = "input"
        if right is None:
            right = "input"
        return f"{left}{right}"
    const = _const_str(node)
    if const is not None:
        return const
    return None


def _format_call_string(node: ast.Call) -> Optional[str]:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "format":
        base = _const_str(func.value)
        if base is not None:
            return re.sub(r"\{[^}]*\}", "?", base)
    return None


def extract_sql_snippets(source: str) -> List[str]:
    """Return SQL-like strings found in Python code or the source itself if it is SQL."""
    stripped = source.strip()
    if not stripped:
        return []

    if looks_like_sql(stripped) and _not_python_module(stripped):
        return [stripped]

    snippets: List[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # Maybe mixed or invalid Python; fall back to regex of quoted strings.
        snippets.extend(_quoted_sql_strings(source))
        if looks_like_sql(stripped):
            snippets.insert(0, stripped)
        return _dedupe(snippets)

    for node in ast.walk(tree):
        candidates: List[str] = []
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            candidates.append(node.value)
        elif isinstance(node, ast.JoinedStr):
            reconstructed = _const_str(node)
            if reconstructed:
                candidates.append(reconstructed)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            reconstructed = _binop_sql_string(node)
            if reconstructed:
                candidates.append(reconstructed)
        elif isinstance(node, ast.Call):
            formatted = _format_call_string(node)
            if formatted:
                candidates.append(formatted)

        for text in candidates:
            cleaned = text.strip()
            if looks_like_sql(cleaned) and _quote_balanced(cleaned):
                snippets.append(cleaned)

    return _dedupe(snippets)


def first_function_name(source: str) -> Optional[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            return node.name
    return None


def source_executes_sql(source: str) -> bool:
    execute_names = {"execute", "executemany", "query", "raw"}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        lowered = source.lower()
        return any(name in lowered for name in ("execute(", "executemany("))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in execute_names:
                return True
            if isinstance(func, ast.Attribute) and func.attr in execute_names:
                return True
    return False


def _not_python_module(text: str) -> bool:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return True
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
            return False
        if isinstance(node, ast.Assign):
            return False
        if isinstance(node, ast.Call):
            return False
    return True


def _quoted_sql_strings(source: str) -> List[str]:
    found: List[str] = []
    for match in re.finditer(r"(['\"])(.*?)(\1)", source, re.DOTALL):
        value = match.group(2)
        if looks_like_sql(value):
            found.append(value.strip())
    return found


def _quote_balanced(text: str) -> bool:
    # Allow reconstructed placeholders such as name = '?'
    singles = text.count("'")
    doubles = text.count('"')
    return singles % 2 == 0 and doubles % 2 == 0


def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        key = re.sub(r"\s+", " ", item).strip()
        if key and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def normalize_whitespace(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()
