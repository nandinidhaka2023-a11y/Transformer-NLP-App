"""Static detection of SQL injection and related code/security risks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

SQL_TOKEN = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WITH|TRUNCATE|MERGE)\b",
    re.IGNORECASE,
)

PLACEHOLDER = re.compile(r"(%s|\?|:\w+|\$\d+)")

SECRET_NAMES = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"private[_-]?key|secret[_-]?key|aws_secret|db_password|connection_string|token)$",
    re.IGNORECASE,
)

PLACEHOLDER_SECRET = re.compile(
    r"^(your[_-]?|changeme|placeholder|xxx+|todo|none|null|empty|<.+>|\{.+\})$",
    re.IGNORECASE,
)

AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
PEM_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

RISK_ORDER = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

EXECUTE_FUNCS = {"execute", "executemany", "executescript"}
SHELL_FUNCS = {"system", "popen", "popen2"}
SUBPROCESS_FUNCS = {"run", "call", "check_output", "check_call", "Popen", "getoutput", "getstatusoutput"}
EVAL_FUNCS = {"eval", "exec", "compile"}
USERISH = re.compile(r"(input|request|arg|param|user|name|query|cmd|command|path|file|filename|raw)", re.I)


@dataclass
class Finding:
    level: str
    vulnerability: str
    explanation: str
    fix: str


@dataclass
class SecurityReport:
    level: str
    vulnerability: str
    explanation: str
    fix: str
    findings: List[Finding] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "level": self.level,
            "vulnerability": self.vulnerability,
            "explanation": self.explanation,
            "fix": self.fix,
            "findings": [f.__dict__ for f in self.findings],
        }


def analyze_security(source: str) -> SecurityReport:
    text = source.strip()
    if not text:
        return _safe("No input was provided to analyze.")

    findings: List[Finding] = []
    tree: Optional[ast.AST] = None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        findings.extend(_regex_fallback(source))
        return _finalize(findings)

    findings.extend(_sql_injection_findings(tree, source))
    findings.extend(_command_injection_findings(tree))
    findings.extend(_path_traversal_findings(tree, source))
    findings.extend(_code_injection_findings(tree))
    findings.extend(_secret_findings(tree, source))
    return _finalize(findings)


def _finalize(findings: List[Finding]) -> SecurityReport:
    if not findings:
        return _safe(
            "No vulnerabilities found by the current static analysis rules. "
            "This does not mean the code is fully secure."
        )
    findings.sort(key=lambda f: RISK_ORDER.get(f.level, 0), reverse=True)
    top = findings[0]
    extra = ""
    if len(findings) > 1:
        others = "; ".join(f"{f.level} {f.vulnerability}" for f in findings[1:])
        extra = f" Additional findings: {others}."
    return SecurityReport(
        level=top.level,
        vulnerability=top.vulnerability,
        explanation=top.explanation + extra,
        fix=top.fix,
        findings=findings,
    )


def _safe(explanation: str) -> SecurityReport:
    return SecurityReport(
        level="SAFE",
        vulnerability="No vulnerabilities found",
        explanation=explanation,
        fix="Keep using parameterized queries and avoid executing untrusted input.",
        findings=[],
    )


def _sql_injection_findings(tree: ast.AST, source: str) -> List[Finding]:
    findings: List[Finding] = []
    parameterized_calls = _parameterized_execute_calls(tree)

    for node in ast.walk(tree):
        if id(node) in parameterized_calls:
            continue

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            sql_part, dynamic = _additive_sql(node)
            if sql_part and dynamic:
                findings.append(
                    Finding(
                        level="HIGH",
                        vulnerability="SQL Injection",
                        explanation=(
                            "User-controlled or dynamic values are concatenated directly into a SQL string. "
                            "An attacker can change the query structure."
                        ),
                        fix="Use parameterized queries or prepared statements instead of string concatenation.",
                    )
                )

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            left_sql = _sql_from_node(node.left)
            if left_sql and not _only_placeholders_and_literals(left_sql):
                # "SELECT ... %s" % value is interpolation, unsafe.
                # "SELECT ... %s" used later with execute(sql, params) is handled via skip of execute.
                if _is_percent_sql_interpolation(node):
                    findings.append(
                        Finding(
                            level="HIGH",
                            vulnerability="SQL Injection",
                            explanation=(
                                "A SQL string is built with % formatting, which interpolates values into the query."
                            ),
                            fix="Pass parameters as a separate argument to cursor.execute(), and keep %s as placeholders only.",
                        )
                    )

        if isinstance(node, ast.JoinedStr):
            sql_text = _joined_sql(node)
            if sql_text and _joined_has_dynamic(node):
                findings.append(
                    Finding(
                        level="HIGH",
                        vulnerability="SQL Injection",
                        explanation=(
                            "An f-string interpolates Python values directly into SQL. "
                            "This is dynamic SQL and is vulnerable to SQL injection."
                        ),
                        fix="Use parameterized queries/prepared statements instead of f-strings for SQL.",
                    )
                )

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            base = _string_const(node.func.value)
            if base and SQL_TOKEN.search(base):
                findings.append(
                    Finding(
                        level="HIGH",
                        vulnerability="SQL Injection",
                        explanation=(
                            "str.format() is used to insert values into a SQL string, which can alter the query."
                        ),
                        fix="Use parameterized queries (for example, '?' or '%s' placeholders with a parameter tuple).",
                    )
                )

        if isinstance(node, ast.Call) and _call_name(node) in EXECUTE_FUNCS | {"execute"}:
            if node.args:
                first = node.args[0]
                if _is_dynamic_sql_arg(first) and len(node.args) < 2:
                    findings.append(
                        Finding(
                            level="HIGH",
                            vulnerability="SQL Injection",
                            explanation="execute() is called with a dynamically built SQL string and no bound parameters.",
                            fix="Pass the SQL template and parameters separately: cursor.execute(sql, (value,)).",
                        )
                    )

    return _unique(findings)


def _parameterized_execute_calls(tree: ast.AST) -> Set[int]:
    """IDs of AST nodes that are SQL strings used safely with execute(sql, params)."""
    safe: Set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name not in EXECUTE_FUNCS and attr not in EXECUTE_FUNCS:
            continue
        if len(node.args) >= 2:
            safe.add(id(node.args[0]))
            # Also mark inner constants of the first arg
            for child in ast.walk(node.args[0]):
                safe.add(id(child))
        elif node.keywords:
            if any(k.arg in {"params", "parameters", "args"} for k in node.keywords):
                safe.add(id(node.args[0]) if node.args else 0)
    return safe


def _is_dynamic_sql_arg(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return False
    if isinstance(node, ast.JoinedStr):
        return SQL_TOKEN.search(_joined_sql(node) or "") is not None and _joined_has_dynamic(node)
    if isinstance(node, ast.BinOp):
        sql_part, dynamic = _additive_sql(node)
        return bool(sql_part and dynamic)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        base = _string_const(node.func.value)
        return bool(base and SQL_TOKEN.search(base))
    if isinstance(node, ast.Name):
        return True
    return False


def _additive_sql(node: ast.BinOp) -> Tuple[bool, bool]:
    sql = False
    dynamic = False

    def walk(n: ast.AST) -> None:
        nonlocal sql, dynamic
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            walk(n.left)
            walk(n.right)
            return
        const = _string_const(n)
        if const is not None:
            if SQL_TOKEN.search(const):
                sql = True
            return
        dynamic = True

    walk(node)
    return sql, dynamic


def _sql_from_node(node: ast.AST) -> Optional[str]:
    const = _string_const(node)
    if const and SQL_TOKEN.search(const):
        return const
    return None


def _only_placeholders_and_literals(sql: str) -> bool:
    return bool(PLACEHOLDER.search(sql))


def _is_percent_sql_interpolation(node: ast.BinOp) -> bool:
    left = _string_const(node.left)
    if not left or not SQL_TOKEN.search(left):
        return False
    # execute("...%s", params) is a Call, not a Mod BinOp.
    return True


def _joined_sql(node: ast.JoinedStr) -> Optional[str]:
    parts = []
    for v in node.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(v.value)
        else:
            parts.append("?")
    text = "".join(parts)
    return text if SQL_TOKEN.search(text) else None


def _joined_has_dynamic(node: ast.JoinedStr) -> bool:
    return any(not isinstance(v, ast.Constant) for v in node.values)


def _command_injection_findings(tree: ast.AST) -> List[Finding]:
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        owner = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            owner = node.func.value.id

        dangerous = False
        dynamic = False
        shell = _keyword_true(node, "shell")

        if attr in SHELL_FUNCS and owner in {"os", "posix"}:
            dangerous = True
            dynamic = bool(node.args) and not _is_str_const(node.args[0])
        elif owner == "subprocess" and attr in SUBPROCESS_FUNCS:
            dangerous = True
            dynamic = bool(node.args) and not _is_static_command(node.args[0])
        elif name in {"system"} and node.args:
            dangerous = True
            dynamic = not _is_str_const(node.args[0])

        if dangerous and (dynamic or shell):
            level = "CRITICAL" if (dynamic and shell) or (dynamic and attr in SHELL_FUNCS) else "HIGH"
            if dynamic and attr in SHELL_FUNCS:
                level = "CRITICAL"
            elif dynamic:
                level = "HIGH"
            elif shell:
                level = "MEDIUM"
            findings.append(
                Finding(
                    level=level,
                    vulnerability="Command Injection",
                    explanation=(
                        "A system/shell command is built from dynamic data. "
                        "Untrusted input can execute additional OS commands."
                    ),
                    fix=(
                        "Avoid os.system and shell=True. Use subprocess with a list of arguments "
                        "and never interpolate untrusted strings into a shell command."
                    ),
                )
            )
    return _unique(findings)


def _path_traversal_findings(tree: ast.AST, source: str) -> List[Finding]:
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name not in {"open"} and attr not in {"open", "read_text", "read_bytes", "write_text"}:
            continue
        if not node.args:
            continue
        arg = node.args[0]
        path_text = _string_const(arg) or ""
        dynamic = not _is_str_const(arg)
        has_dotdot = ".." in path_text or _contains_dotdot(arg)
        userish = _mentions_userish(arg)
        if has_dotdot or (dynamic and userish) or (dynamic and attr in {"open"} or (name == "open" and dynamic)):
            level = "HIGH" if has_dotdot else "MEDIUM"
            findings.append(
                Finding(
                    level=level,
                    vulnerability="Path Traversal / Unsafe File Access",
                    explanation=(
                        "A file path is taken from dynamic input or contains '..', which can read or write "
                        "files outside the intended directory."
                    ),
                    fix=(
                        "Resolve the path, reject '..' segments, and allow only files inside a trusted base directory."
                    ),
                )
            )
    return _unique(findings)


def _code_injection_findings(tree: ast.AST) -> List[Finding]:
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name not in EVAL_FUNCS:
            continue
        arg_dynamic = bool(node.args) and not _is_str_const(node.args[0])
        if name in {"eval", "exec"}:
            findings.append(
                Finding(
                    level="CRITICAL" if arg_dynamic else "HIGH",
                    vulnerability="Code Injection",
                    explanation=(
                        f"{name}() executes Python code. "
                        + (
                            "The argument is dynamic, so an attacker may run arbitrary code."
                            if arg_dynamic
                            else "Even a constant argument is a dangerous pattern if the code path can change."
                        )
                    ),
                    fix="Do not use eval() or exec() on untrusted data. Use safe parsers (json, ast.literal_eval) instead.",
                )
            )
        elif name == "compile" and _compile_is_exec(node):
            findings.append(
                Finding(
                    level="HIGH",
                    vulnerability="Code Injection",
                    explanation="compile() is used in a mode that can produce executable code from a string.",
                    fix="Avoid compiling and executing untrusted strings.",
                )
            )
    return _unique(findings)


def _secret_findings(tree: ast.AST, source: str) -> List[Finding]:
    findings: List[Finding] = []
    if AWS_KEY.search(source) or PEM_KEY.search(source):
        findings.append(
            Finding(
                level="CRITICAL",
                vulnerability="Hardcoded Secrets/Credentials",
                explanation="The input contains a credential pattern such as an AWS access key or a private key block.",
                fix="Remove the secret, rotate it, and load credentials from a secret manager or environment variables.",
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = _string_const(node.value)
            if value is None or len(value) < 4:
                continue
            if PLACEHOLDER_SECRET.match(value.strip()):
                continue
            for target in node.targets:
                name = _target_name(target)
                if name and SECRET_NAMES.search(name):
                    findings.append(
                        Finding(
                            level="HIGH",
                            vulnerability="Hardcoded Secrets/Credentials",
                            explanation=(
                                f"A secret-like value is hardcoded in `{name}`. "
                                "Anyone with the source can reuse the credential."
                            ),
                            fix="Store secrets in environment variables or a vault; never commit them in source code.",
                        )
                    )
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if "password=" in node.value.lower() and "://" in node.value.lower():
                findings.append(
                    Finding(
                        level="HIGH",
                        vulnerability="Hardcoded Secrets/Credentials",
                        explanation="A connection string includes an embedded password.",
                        fix="Use environment variables or a secrets manager for database credentials.",
                    )
                )
    return _unique(findings)


def _regex_fallback(source: str) -> List[Finding]:
    """When the input is not valid Python, still catch common risky patterns including SQL-only files."""
    findings: List[Finding] = []
    compact = re.sub(r"\s+", " ", source)

    if _looks_like_python_dynamic_sql(source):
        findings.append(
            Finding(
                level="HIGH",
                vulnerability="SQL Injection",
                explanation="Dynamic SQL construction was detected (concatenation, f-string, or format).",
                fix="Use parameterized queries/prepared statements.",
            )
        )

    if re.search(r"\bos\.system\s*\(", source) or re.search(r"subprocess\.[a-zA-Z]+\([^)]*shell\s*=\s*True", source):
        findings.append(
            Finding(
                level="HIGH",
                vulnerability="Command Injection",
                explanation="A shell/system command call is present.",
                fix="Use subprocess with a argument list and shell=False.",
            )
        )
    if re.search(r"\beval\s*\(|\bexec\s*\(", source):
        findings.append(
            Finding(
                level="CRITICAL",
                vulnerability="Code Injection",
                explanation="eval/exec is present in the input.",
                fix="Remove eval/exec; parse data with safe libraries.",
            )
        )
    if ".." in source and re.search(r"\bopen\s*\(", source):
        findings.append(
            Finding(
                level="HIGH",
                vulnerability="Path Traversal / Unsafe File Access",
                explanation="File access uses a path that may contain '..'.",
                fix="Canonicalize paths and restrict access to a safe directory.",
            )
        )
    _ = compact
    return findings


def _looks_like_python_dynamic_sql(source: str) -> bool:
    if not SQL_TOKEN.search(source):
        return False
    if re.search(r"""['"]\s*\+\s*\w+""", source):
        return True
    if re.search(r"""\w+\s*\+\s*['"]""", source) and SQL_TOKEN.search(source):
        return True
    if re.search(r"""f['"].*(SELECT|INSERT|UPDATE|DELETE).*\{""", source, re.I | re.S):
        return True
    if re.search(r"""['"].*(SELECT|INSERT|UPDATE|DELETE).*['"]\s*\.format\s*\(""", source, re.I | re.S):
        return True
    return False


def _string_const(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_str_const(node: ast.AST) -> bool:
    return _string_const(node) is not None


def _is_static_command(node: ast.AST) -> bool:
    if _is_str_const(node):
        return True
    if isinstance(node, ast.List) and all(_is_str_const(elt) for elt in node.elts):
        return True
    return False


def _keyword_true(call: ast.Call, name: str) -> bool:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _contains_dotdot(node: ast.AST) -> bool:
    for child in ast.walk(node):
        const = _string_const(child)
        if const and ".." in const:
            return True
    return False


def _mentions_userish(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and USERISH.search(child.id):
            return True
    return False


def _compile_is_exec(node: ast.Call) -> bool:
    if len(node.args) >= 3:
        mode = _string_const(node.args[2])
        return mode in {"exec", "eval", "single"}
    return True


def _unique(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out: List[Finding] = []
    for f in findings:
        key = (f.level, f.vulnerability)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
