from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass
from pathlib import Path

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# ID: (title, severity, confidence, category, CWE, remediation)
RULES = {
    "VS001": (
        "Possible hardcoded secret", "high", "medium", "secrets",
        "CWE-798",
        "Remove the credential from source code, rotate it if real, "
        "and use a secret manager or environment configuration."
    ),
    "VS002": (
        "Untrusted input reaches a shell command", "critical", "medium",
        "code", "CWE-78",
        "Avoid shell execution. Use argument arrays, strict validation, "
        "and an allowlist of permitted operations."
    ),
    "VS003": (
        "Potential SQL injection", "high", "medium", "code",
        "CWE-89",
        "Use parameterized queries or safe ORM query builders. "
        "Never concatenate untrusted input into SQL."
    ),
    "VS004": (
        "Unsafe deserialization", "high", "medium", "code",
        "CWE-502",
        "Avoid deserializing untrusted objects. Prefer JSON with "
        "schema validation and explicit allowed types."
    ),
    "VS005": (
        "Potential server-side request forgery", "high", "medium",
        "code", "CWE-918",
        "Validate destinations with an allowlist and enforce network "
        "egress restrictions. Reject unexpected schemes and redirects."
    ),
    "VS006": (
        "Debug mode enabled", "medium", "high", "config",
        "CWE-489",
        "Disable debug mode in production deployments."
    ),
    "VS007": (
        "TLS certificate verification disabled", "high", "high",
        "config", "CWE-295",
        "Enable certificate verification and configure a trusted CA."
    ),
    "VS008": (
        "Dynamic code evaluation", "high", "medium", "code",
        "CWE-95",
        "Avoid eval/exec on dynamic input. Use a constrained parser "
        "or explicit dispatch table."
    ),
    "VS009": (
        "Possible path traversal", "medium", "low", "code",
        "CWE-22",
        "Resolve paths against an approved base directory and "
        "verify the resolved path remains inside that directory."
    ),
    "VS010": (
        "Authorization or tenant isolation requires review",
        "medium", "low", "code", "CWE-639",
        "Verify object ownership and tenant membership on the server "
        "for every resource access. Add negative authorization tests."
    ),
    "VS011": (
        "Row-level security disabled", "high", "high", "config",
        "CWE-284",
        "Review database policies and enable row-level security "
        "where tenant isolation depends on it."
    ),
    "VS012": (
        "Potentially public cloud resource", "high", "medium",
        "config", "CWE-732",
        "Review resource exposure and apply least-privilege access."
    ),
    "VS013": (
        "Potential DOM injection", "medium", "low", "code",
        "CWE-79",
        "Avoid injecting untrusted HTML. Use safe rendering and "
        "context-appropriate sanitization when HTML is required."
    ),
    "VS014": (
        "Wildcard CORS configuration", "low", "medium", "config",
        "CWE-942",
        "Restrict allowed origins where sensitive APIs or credentials "
        "are involved."
    ),
    "VS015": (
        "Unusual combination of sensitive operations", "low", "low",
        "anomaly", "CWE-693",
        "Manually review the data flow and confirm that the "
        "combination of operations is expected."
    ),
    "VS016": (
        "Dependency vulnerability reported by OSV", "medium",
        "high", "dependencies", "CWE-1104",
        "Consult the linked advisory and upgrade or mitigate the "
        "affected dependency. Confirm applicability."
    ),
    "VS017": (
        "Missing recommended HTTP security header", "low",
        "medium", "http", "CWE-693",
        "Review the response headers and configure an appropriate "
        "security policy for the application."
    ),
    "VS018": (
        "HTTPS response missing HSTS", "low", "medium",
        "http", "CWE-319",
        "Consider Strict-Transport-Security for production HTTPS "
        "applications after checking deployment requirements."
    ),
    "VS019": (
        "Sensitive GitHub Actions workflow pattern", "medium",
        "low", "config", "CWE-829",
        "Review workflow permissions, checkout references, and "
        "execution of untrusted pull-request content."
    ),
    "VS020": (
        "Possible LLM trust-boundary issue", "medium", "low",
        "code", "CWE-74",
        "Treat model input as untrusted. Separate instructions from "
        "data and enforce authorization outside the model."
    ),
    "VS021": (
        "Environment file requires repository review", "low",
        "low", "secrets", "CWE-200",
        "Ensure this file is not committed if it contains credentials. "
        "Use a sanitized example file for documentation."
    ),
    "VS022": (
        "Shell execution enabled", "medium", "medium",
        "code", "CWE-78",
        "Avoid shell=True where possible and pass arguments as a list."
    ),
    "VS023": (
        "Container configured to run as root", "medium",
        "high", "config", "CWE-250",
        "Create a dedicated unprivileged user and use USER in "
        "the container configuration."
    ),
}

IGNORE_DIRS = {
    ".git", ".venv", "venv", "node_modules", "dist", "build",
    "__pycache__", ".next", ".nuxt", ".pytest_cache",
    ".mypy_cache", ".tox", "coverage", "reports",
}

MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    category: str
    path: str
    line: int
    detail: str
    remediation: str
    cwe: str
    evidence: str = ""
    hypothesis: bool = False

    @property
    def id(self) -> str:
        key = (
            f"{self.rule_id}:{self.path}:{self.line}:"
            f"{self.detail}:{self.evidence}"
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {"id": self.id, **asdict(self)}


def make_finding(
    rule_id: str,
    path: str,
    line: int,
    detail: str,
    *,
    evidence: str = "",
    hypothesis: bool = False,
    severity: str | None = None,
    confidence: str | None = None,
) -> Finding:
    title, default_severity, default_confidence, category, cwe, fix = (
        RULES[rule_id]
    )
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity or default_severity,
        confidence=confidence or default_confidence,
        category=category,
        path=path,
        line=max(1, line),
        detail=detail[:500],
        remediation=fix,
        cwe=cwe,
        evidence=evidence[:200],
        hypothesis=hypothesis,
    )


def iter_source_files(root: Path, max_files: int):
    count = 0

    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in IGNORE_DIRS
            and not (Path(directory) / name).is_symlink()
        )

        for name in sorted(files):
            path = Path(directory) / name

            if path.is_symlink() or not path.is_file():
                continue

            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue

            yield path
            count += 1

            if count >= max_files:
                return


def relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def deduplicate(findings: list[Finding]) -> list[Finding]:
    unique = {f.id: f for f in findings}
    return sorted(
        unique.values(),
        key=lambda f: (
            -SEVERITY_ORDER[f.severity],
            f.path,
            f.line,
            f.rule_id,
        ),
    )