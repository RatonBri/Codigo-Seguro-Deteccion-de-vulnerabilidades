from __future__ import annotations

import ast
import re
from pathlib import Path

from .core import Finding, make_finding, relative_path

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".sql", ".tf", ".yaml", ".yml",
    ".json", ".toml", ".env", ".sh",
    ".txt", ".properties",
}

SECRET_RE = re.compile(
    r"""(?i)\b(?:api[_-]?key|secret(?:_key)?|access[_-]?token|"""
    r"""password|private[_-]?key)\b\s*[:=]\s*["']([^"'\n]{8,})["']"""
)

JS_SOURCE_RE = re.compile(
    r"\b(?:req|request)\.(?:query|params|body|headers)\b"
)

JS_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)"
)

JS_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$.]*)\s*\(")

PLACEHOLDERS = (
    "example", "placeholder", "changeme", "your_", "dummy",
    "fake", "sample", "test_", "process.env", "${",
)


def _name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return _name(node.value)
    return ""


def _python_tainted(node: ast.AST, tainted: set[str]) -> bool:
    sources = (
        "request.args", "request.form", "request.json",
        "request.values", "request.data", "request.headers",
        "request.GET", "request.POST", "request.query_params",
    )

    for item in ast.walk(node):
        if isinstance(item, ast.Name) and item.id in tainted:
            return True

        if isinstance(item, ast.Attribute):
            value = _name(item)
            if any(value.startswith(source) for source in sources):
                return True

        if isinstance(item, ast.Call):
            if _name(item.func) in {"input", "sys.stdin.readline"}:
                return True

    return False


def _dynamic_string(node: ast.AST) -> bool:
    return isinstance(
        node, (ast.JoinedStr, ast.BinOp, ast.FormattedValue)
    )


def _python_findings(
    text: str, rel: str, level: str
) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    results: list[Finding] = []
    tainted: set[str] = set()

    nodes = sorted(
        ast.walk(tree),
        key=lambda n: (
            getattr(n, "lineno", 0),
            getattr(n, "col_offset", 0),
        ),
    )

    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is not None and _python_tainted(value, tainted):
                targets = (
                    node.targets if isinstance(node, ast.Assign)
                    else [node.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name):
                        tainted.add(target.id)

        if not isinstance(node, ast.Call):
            continue

        name = _name(node.func)
        line = node.lineno
        first = node.args[0] if node.args else None
        tainted_arg = (
            first is not None and _python_tainted(first, tainted)
        )

        shell_true = any(
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        )

        if name in {
            "os.system", "os.popen",
            "subprocess.run", "subprocess.call",
            "subprocess.Popen", "subprocess.check_output",
        }:
            if tainted_arg:
                results.append(make_finding(
                    "VS002", rel, line,
                    f"Untrusted data may reach {name}.",
                    evidence=f"Call: {name}",
                ))
            elif shell_true:
                results.append(make_finding(
                    "VS022", rel, line,
                    f"{name} uses shell=True.",
                    evidence=f"Call: {name}",
                ))

        if name in {"eval", "exec"}:
            if tainted_arg or level == "deep":
                results.append(make_finding(
                    "VS008", rel, line,
                    f"Dynamic evaluation via {name}.",
                    evidence=f"Call: {name}",
                    confidence="high" if tainted_arg else "medium",
                ))

        if name in {
            "pickle.loads", "pickle.load",
            "yaml.unsafe_load",
        }:
            if tainted_arg or level == "deep":
                results.append(make_finding(
                    "VS004", rel, line,
                    f"Potentially unsafe deserialization via {name}.",
                    evidence=f"Call: {name}",
                ))

        if name.endswith(".execute") and first is not None:
            if _dynamic_string(first):
                results.append(make_finding(
                    "VS003", rel, line,
                    "SQL execution receives a dynamically "
                    "constructed expression.",
                    evidence=f"Call: {name}",
                    confidence=(
                        "high" if tainted_arg else "medium"
                    ),
                ))

        if name in {
            "requests.get", "requests.post",
            "requests.put", "requests.request",
            "httpx.get", "httpx.post",
            "urllib.request.urlopen",
        } and tainted_arg:
            results.append(make_finding(
                "VS005", rel, line,
                f"Untrusted data may control the URL in {name}.",
                evidence=f"Call: {name}",
            ))

        if name in {
            "requests.get", "requests.post",
            "requests.request",
            "requests.Session.get",
        }:
            for kw in node.keywords:
                if (
                    kw.arg == "verify"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                ):
                    results.append(make_finding(
                        "VS007", rel, line,
                        "HTTP request disables TLS verification.",
                        evidence="verify=False",
                    ))

        if name.endswith(".run"):
            for kw in node.keywords:
                if (
                    kw.arg == "debug"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    results.append(make_finding(
                        "VS006", rel, line,
                        "Application run call enables debug mode.",
                        evidence="debug=True",
                    ))

        if level == "deep" and name in {"open", "pathlib.Path"}:
            if tainted_arg:
                results.append(make_finding(
                    "VS009", rel, line,
                    "User-controlled input may influence a file path.",
                    evidence=f"Call: {name}",
                    hypothesis=True,
                ))

        if level == "deep" and (
            name.endswith(".query.get")
            or name.endswith(".objects.get")
        ):
            if tainted_arg:
                results.append(make_finding(
                    "VS010", rel, line,
                    "Resource lookup uses a client-controlled "
                    "identifier. Verify ownership checks.",
                    evidence=f"Call: {name}",
                    hypothesis=True,
                ))

    return results


def _js_tainted_variables(text: str) -> set[str]:
    tainted: set[str] = set()

    for line in text.splitlines():
        match = JS_ASSIGN_RE.search(line)
        if not match:
            continue

        variable, expression = match.groups()

        if JS_SOURCE_RE.search(expression) or any(
            re.search(rf"\b{re.escape(name)}\b", expression)
            for name in tainted
        ):
            tainted.add(variable)

    return tainted


def _js_ast_calls(text: str, suffix: str):
    """
    Optional Tree-sitter syntax parsing.
    Yields (line, callee, argument_source).
    Returns None if the optional parsers are unavailable.
    """
    try:
        from tree_sitter import Language, Parser

        if suffix in {".ts", ".tsx"}:
            import tree_sitter_typescript as grammar
            language_pointer = (
                grammar.language_tsx()
                if suffix == ".tsx"
                else grammar.language_typescript()
            )
        else:
            import tree_sitter_javascript as grammar
            language_pointer = grammar.language()

        parser = Parser(Language(language_pointer))
        data = text.encode("utf-8")
        tree = parser.parse(data)
    except (ImportError, TypeError, AttributeError):
        return None

    calls = []
    stack = [tree.root_node]

    while stack:
        node = stack.pop()
        stack.extend(reversed(node.children))

        if node.type != "call_expression":
            continue

        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")

        if function is None or arguments is None:
            continue

        callee = data[
            function.start_byte:function.end_byte
        ].decode("utf-8", errors="replace")

        args = data[
            arguments.start_byte:arguments.end_byte
        ].decode("utf-8", errors="replace")

        calls.append((node.start_point.row + 1, callee, args))

    return calls


def _js_findings(
    text: str, rel: str, level: str, suffix: str
) -> list[Finding]:
    results: list[Finding] = []
    tainted = _js_tainted_variables(text)

    calls = _js_ast_calls(text, suffix)

    if calls is None:
        # Conservative fallback when Tree-sitter is not installed.
        calls = []
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in JS_CALL_RE.finditer(line):
                calls.append((line_no, match.group(1), line))

    for line, callee, args in calls:
        has_source = bool(JS_SOURCE_RE.search(args))
        has_variable = any(
            re.search(rf"\b{re.escape(name)}\b", args)
            for name in tainted
        )
        is_tainted = has_source or has_variable
        normalized = callee.replace(" ", "")

        if normalized in {
            "exec", "execSync", "child_process.exec",
            "child_process.execSync",
        } and is_tainted:
            results.append(make_finding(
                "VS002", rel, line,
                "Untrusted input may reach a shell command.",
                evidence=f"Call: {normalized}",
            ))

        if normalized in {"eval", "Function"}:
            if is_tainted or level == "deep":
                results.append(make_finding(
                    "VS008", rel, line,
                    "Dynamic JavaScript evaluation requires review.",
                    evidence=f"Call: {normalized}",
                ))

        if normalized in {
            "fetch", "axios.get", "axios.post",
            "http.get", "https.get", "got",
        } and is_tainted:
            results.append(make_finding(
                "VS005", rel, line,
                "Untrusted input may control an outbound URL.",
                evidence=f"Call: {normalized}",
            ))

        if (
            normalized.endswith(".query")
            and is_tainted
            and re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b",
                          args, re.IGNORECASE)
        ):
            results.append(make_finding(
                "VS003", rel, line,
                "SQL query construction includes untrusted input.",
                evidence=f"Call: {normalized}",
            ))

        if level == "deep" and (
            normalized.endswith(".findUnique")
            or normalized.endswith(".findFirst")
        ) and is_tainted:
            results.append(make_finding(
                "VS010", rel, line,
                "Client-controlled resource lookup; check "
                "tenant and ownership authorization.",
                evidence=f"Call: {normalized}",
                hypothesis=True,
            ))

        if level == "deep" and (
            "completions.create" in normalized
            or "responses.create" in normalized
        ) and is_tainted:
            results.append(make_finding(
                "VS020", rel, line,
                "Untrusted input is passed to an LLM call; "
                "review instruction/data separation.",
                evidence=f"Call: {normalized}",
                hypothesis=True,
            ))

    for line_no, line in enumerate(text.splitlines(), 1):
        if "dangerouslySetInnerHTML" in line:
            results.append(make_finding(
                "VS013", rel, line,
                "Direct HTML insertion requires sanitization review.",
                evidence="dangerouslySetInnerHTML",
                hypothesis=True,
            ))

    return results



def _configuration_findings(
    text: str, rel: str, level: str
) -> list[Finding]:
    results: list[Finding] = []
    name = Path(rel).name.lower()
    suffix = Path(rel).suffix.lower()

    # Detectar archivos de entorno
    if name == ".env" or name.startswith(".env."):
        if name != ".env.example":
            results.append(make_finding(
                "VS021", rel, 1,
                "Environment file found in the scan directory.",
                evidence="Environment file; contents not displayed",
                hypothesis=True,
            ))

    # Recorrer cada línea del archivo
    for line_no, line in enumerate(text.splitlines(), start=1):

        # Detectar RLS deshabilitado
        if suffix == ".sql" and re.search(
            r"\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b",
            line, re.IGNORECASE
        ):
            results.append(make_finding(
                "VS011", rel, line_no,
                "SQL statement disables row-level security.",
                evidence="DISABLE ROW LEVEL SECURITY",
            ))

        # Detectar configuraciones públicas en Terraform
        if suffix == ".tf" and re.search(
            r'\b(?:acl\s*=\s*"public-read"|'
            r'block_public_acls\s*=\s*false|'
            r'block_public_policy\s*=\s*false)',
            line, re.IGNORECASE
        ):
            results.append(make_finding(
                "VS012", rel, line_no,
                "Terraform configuration may expose a resource.",
                evidence="Public access configuration",
            ))

        # Detectar configuraciones CORS permisivas
        if re.search(
            r"Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*",
            line, re.IGNORECASE
        ):
            results.append(make_finding(
                "VS014", rel, line_no,
                "Wildcard origin appears in CORS configuration.",
                evidence="Access-Control-Allow-Origin: *",
            ))

        # Detectar contenedores configurados para usar root
        if name in {"dockerfile", "containerfile"} and re.search(
            r"^\s*USER\s+(?:root|0)\s*$",
            line, re.IGNORECASE
        ):
            results.append(make_finding(
                "VS023", rel, line_no,
                "Container explicitly runs as root.",
                evidence="USER root",
            ))

    # Detectar patrones que requieren revisión en GitHub Actions
    if level == "deep" and (
        rel.startswith(".github/workflows/")
        and "pull_request_target:" in text
        and "actions/checkout@" in text
    ):
        results.append(make_finding(
            "VS019", rel, 1,
            "Workflow combines pull_request_target and checkout. "
            "Review whether untrusted code can execute.",
            evidence="pull_request_target + actions/checkout",
            hypothesis=True,
        ))

    return results


def scan_source(
    path: Path, root: Path, level: str = "standard"
) -> list[Finding]:
    rel = relative_path(path, root)
    suffix = path.suffix.lower()
    filename = path.name.lower()

    if (
        suffix not in SOURCE_EXTENSIONS
        and filename not in {
            "dockerfile", "containerfile",
            ".env", ".gitignore",
        }
        and not filename.startswith(".env.")
    ):
        return []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    results: list[Finding] = []

    for line_no, line in enumerate(text.splitlines(), 1):
        match = SECRET_RE.search(line)
        if match:
            value = match.group(1)
            if not any(
                marker in value.lower()
                for marker in PLACEHOLDERS
            ):
                results.append(make_finding(
                    "VS001", rel, line_no,
                    "Possible credential embedded in source code.",
                    evidence="Credential value redacted",
                ))

    results.extend(_configuration_findings(text, rel, level))

    if level != "quick":
        if suffix == ".py":
            results.extend(_python_findings(text, rel, level))

        if suffix in {".js", ".jsx", ".ts", ".tsx"}:
            results.extend(
                _js_findings(text, rel, level, suffix)
            )

    if level == "deep":
        # Anomaly = review hypothesis, never a confirmed vulnerability.
        markers = [
            r"\b(?:base64\.b64decode|atob)\b",
            r"\b(?:subprocess|child_process|os\.system)\b",
            r"\b(?:requests\.post|fetch|axios\.post)\b",
        ]
        if all(re.search(pattern, text) for pattern in markers):
            results.append(make_finding(
                "VS015", rel, 1,
                "File combines decoding, process execution and "
                "network communication. Manual review recommended.",
                evidence="Three sensitive operation families",
                hypothesis=True,
            ))

    return results