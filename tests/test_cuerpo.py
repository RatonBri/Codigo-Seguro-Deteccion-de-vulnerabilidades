import json

import pytest

from Cuerpo.cli import main
from Cuerpo.detectors import scan_source
from Cuerpo.dependencies import collect_dependencies
from Cuerpo.httpcheck import validate_url
from Cuerpo.reports import write_reports


def create_file(tmp_path, name, content):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_detects_hardcoded_secret_and_redacts_value(tmp_path):
    path = create_file(
        tmp_path,
        "settings.py",
        'API_KEY = "supersecretvalue123"\n',
    )

    findings = scan_source(path, tmp_path)

    assert any(f.rule_id == "VS001" for f in findings)
    assert "supersecretvalue123" not in json.dumps(
        [f.to_dict() for f in findings]
    )


def test_detects_python_sql_injection_pattern(tmp_path):
    path = create_file(
        tmp_path,
        "app.py",
        """
from flask import request
user_id = request.args.get("id")
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
""",
    )

    findings = scan_source(path, tmp_path)

    assert any(f.rule_id == "VS003" for f in findings)


def test_detects_python_command_pattern(tmp_path):
    path = create_file(
        tmp_path,
        "app.py",
        """
import os
from flask import request
command = request.args.get("cmd")
os.system(command)
""",
    )

    findings = scan_source(path, tmp_path)

    assert any(f.rule_id == "VS002" for f in findings)


def test_detects_javascript_ssrf_pattern(tmp_path):
    path = create_file(
        tmp_path,
        "server.js",
        """
const url = req.query.url;
fetch(url);
""",
    )

    findings = scan_source(path, tmp_path)

    assert any(f.rule_id == "VS005" for f in findings)


def test_detects_disabled_rls(tmp_path):
    path = create_file(
        tmp_path,
        "schema.sql",
        "ALTER TABLE documents DISABLE ROW LEVEL SECURITY;\n",
    )

    findings = scan_source(path, tmp_path)

    assert any(f.rule_id == "VS011" for f in findings)


def test_clean_python_file(tmp_path):
    path = create_file(
        tmp_path,
        "clean.py",
        "def add(a, b):\n    return a + b\n",
    )

    assert scan_source(path, tmp_path) == []


def test_collects_pinned_dependencies(tmp_path):
    path = create_file(
        tmp_path,
        "requirements.txt",
        "flask==3.0.0\nrequests>=2.0\n",
    )

    dependencies = collect_dependencies([path], tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "flask"
    assert dependencies[0].version == "3.0.0"
    assert dependencies[0].ecosystem == "PyPI"


def test_blocks_unauthorized_remote_http():
    with pytest.raises(ValueError):
        validate_url("https://example.com/")


def test_allows_loopback_http():
    assert (
        validate_url("http://127.0.0.1:8000/")
        == "http://127.0.0.1:8000/"
    )


def test_reports_and_sarif_are_generated(tmp_path):
    source = create_file(
        tmp_path,
        "app.py",
        'API_KEY = "anothersecretvalue123"\n',
    )

    findings = scan_source(source, tmp_path)
    output = tmp_path / "output"

    created = write_reports(
        findings, [], output, "all"
    )

    assert len(created) == 4
    assert (output / "report.html").exists()
    assert (output / "report.md").exists()
    assert (output / "report.json").exists()
    assert (output / "report.sarif").exists()

    sarif = json.loads(
        (output / "report.sarif").read_text()
    )

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "VS001"

    prompts = list(
        (output / "remediation-prompts").glob("*.md")
    )
    assert len(prompts) == 1


def test_cli_scan(tmp_path):
    create_file(
        tmp_path,
        "app.py",
        'PASSWORD = "secretvalue123456"\n',
    )

    exit_code = main([
        "scan",
        str(tmp_path),
        "--level", "standard",
        "--format", "json",
        "--output", str(tmp_path / "reports"),
        "--fail-on", "high",
    ])

    assert exit_code == 1

    report = json.loads(
        (tmp_path / "reports" / "report.json").read_text()
    )
    assert report["summary"]["high"] >= 1