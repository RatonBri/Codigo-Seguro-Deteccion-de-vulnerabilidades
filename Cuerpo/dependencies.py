from __future__ import annotations

import json
import re
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .core import Finding, make_finding, relative_path


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    path: str


def _requirements(path: Path, root: Path) -> list[Dependency]:
    results = []

    try:
        lines = path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return results

    pattern = re.compile(
        r"^\s*([A-Za-z0-9_.-]+)"
        r"(?:\[[^\]]+\])?"
        r"==([A-Za-z0-9_.+!-]+)"
    )

    for line in lines:
        match = pattern.match(line)
        if match:
            results.append(Dependency(
                match.group(1),
                match.group(2),
                "PyPI",
                relative_path(path, root),
            ))

    return results


def _package_lock(path: Path, root: Path) -> list[Dependency]:
    results = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return results

    rel = relative_path(path, root)
    packages = data.get("packages", {})

    if isinstance(packages, dict) and packages:
        for key, info in packages.items():
            if (
                not isinstance(info, dict)
                or "node_modules/" not in key
            ):
                continue

            name = key.rsplit("node_modules/", 1)[-1]
            version = info.get("version")

            if isinstance(version, str) and name:
                results.append(Dependency(
                    name, version, "npm", rel
                ))
    else:
        def visit(items):
            for name, info in items.items():
                if not isinstance(info, dict):
                    continue

                version = info.get("version")
                if isinstance(version, str):
                    results.append(Dependency(
                        name, version, "npm", rel
                    ))

                nested = info.get("dependencies", {})
                if isinstance(nested, dict):
                    visit(nested)

        dependencies = data.get("dependencies", {})
        if isinstance(dependencies, dict):
            visit(dependencies)

    return results


def _poetry_lock(path: Path, root: Path) -> list[Dependency]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return []

    results = []
    for item in data.get("package", []):
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        version = item.get("version")

        if isinstance(name, str) and isinstance(version, str):
            results.append(Dependency(
                name, version, "PyPI",
                relative_path(path, root),
            ))

    return results


def _pipfile_lock(path: Path, root: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []

    results = []

    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            if not isinstance(info, dict):
                continue

            version = info.get("version", "")
            if isinstance(version, str) and version.startswith("=="):
                results.append(Dependency(
                    name, version[2:], "PyPI",
                    relative_path(path, root),
                ))

    return results


def collect_dependencies(
    files: list[Path], root: Path
) -> list[Dependency]:
    found = []

    for path in files:
        name = path.name.lower()

        if name.startswith("requirements") and name.endswith(".txt"):
            found.extend(_requirements(path, root))
        elif name == "package-lock.json":
            found.extend(_package_lock(path, root))
        elif name == "poetry.lock":
            found.extend(_poetry_lock(path, root))
        elif name == "pipfile.lock":
            found.extend(_pipfile_lock(path, root))

    unique = {
        (d.ecosystem, d.name, d.version, d.path): d
        for d in found
    }

    return sorted(
        unique.values(),
        key=lambda d: (
            d.ecosystem, d.name, d.version, d.path
        ),
    )


def check_osv(
    dependencies: list[Dependency],
    max_queries: int = 30,
    timeout: float = 6.0,
) -> tuple[list[Finding], list[str]]:
    """
    Sends only dependency name, version and ecosystem to OSV.
    Never sends source code or local file contents.
    """
    findings: list[Finding] = []
    warnings: list[str] = []
    queried = set()

    if len(dependencies) > max_queries:
        warnings.append(
            f"OSV limited to {max_queries} unique package queries."
        )

    for dep in dependencies:
        key = (dep.ecosystem, dep.name, dep.version)
        if key in queried:
            continue

        if len(queried) >= max_queries:
            break

        if not re.fullmatch(r"[@A-Za-z0-9_.\/-]{1,160}", dep.name):
            continue

        if not re.fullmatch(r"[A-Za-z0-9_.+~:-]{1,100}", dep.version):
            continue

        queried.add(key)

        payload = {
            "package": {
                "name": dep.name,
                "ecosystem": dep.ecosystem,
            },
            "version": dep.version,
        }

        request = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "VibeShield/0.2",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request, timeout=timeout
            ) as response:
                data = json.load(response)
        except (
            urllib.error.URLError,
            TimeoutError,
            ValueError,
            OSError,
        ) as exc:
            warnings.append(
                f"OSV query failed for {dep.name}: "
                f"{type(exc).__name__}"
            )
            continue

        for vulnerability in data.get("vulns", []):
            if not isinstance(vulnerability, dict):
                continue

            advisory_id = vulnerability.get("id", "unknown")
            if not isinstance(advisory_id, str):
                advisory_id = "unknown"

            summary = vulnerability.get("summary", "")
            if not isinstance(summary, str):
                summary = ""

            findings.append(make_finding(
                "VS016",
                dep.path,
                1,
                f"OSV advisory {advisory_id} reported for "
                f"{dep.name}@{dep.version}. "
                f"{summary[:180]}",
                evidence=(
                    f"{dep.ecosystem}: {dep.name}@{dep.version}; "
                    f"advisory={advisory_id}"
                ),
            ))

    return findings, warnings