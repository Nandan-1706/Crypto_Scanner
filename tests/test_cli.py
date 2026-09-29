"""
tests/test_cli.py

Integration tests that actually invoke main.py as a subprocess - not just
its internal functions - to verify the CLI itself works against arbitrary
project paths, not just sample_project.
"""

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


def _run_main(args, cwd=PROJECT_ROOT):
    return subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "main.py")] + args,
        capture_output=True, text=True, cwd=cwd,
    )


def test_cli_accepts_a_custom_project_path_not_sample_project(tmp_path):
    """The scanner must not be hard-coded to sample_project."""
    custom_project = tmp_path / "my_custom_app"
    custom_project.mkdir()
    (custom_project / "crypto_stuff.py").write_text(
        "import hashlib\ndef h(x):\n    return hashlib.md5(x).hexdigest()\n"
    )
    output_path = tmp_path / "out.json"

    result = _run_main([str(custom_project), "--json-only", "--output", str(output_path)])

    assert result.returncode == 0
    report = json.loads(output_path.read_text())
    assert report["project"] == "my_custom_app"
    assert any(a["algorithm"] == "MD5" for a in report["assets"])


def test_cli_missing_project_path_exits_nonzero(tmp_path):
    result = _run_main([str(tmp_path / "does_not_exist")])
    assert result.returncode == 1
    assert "Error" in result.stderr


def test_cli_produces_both_json_and_human_readable_by_default(tmp_path):
    output_path = tmp_path / "out.json"
    result = _run_main(["sample_project", "--output", str(output_path)])

    assert result.returncode == 0
    assert "CRYPTOGRAPHIC RISK REPORT" in result.stdout  # human-readable went to stdout
    assert output_path.exists()  # JSON went to file
    json.loads(output_path.read_text())  # valid JSON


def test_cli_json_only_flag_suppresses_human_readable(tmp_path):
    output_path = tmp_path / "out.json"
    result = _run_main(["sample_project", "--json-only", "--output", str(output_path)])
    assert "CRYPTOGRAPHIC RISK REPORT" not in result.stdout


def test_cli_set_status_and_verify_workflow(tmp_path):
    project = tmp_path / "workflow_project"
    project.mkdir()
    source = project / "auth.py"
    source.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def make_key():\n"
        '    """weak rsa key"""\n'
        "    return rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
    )
    out1 = tmp_path / "r1.json"

    scan1 = _run_main([str(project), "--json-only", "--output", str(out1)])
    assert scan1.returncode == 0
    report1 = json.loads(out1.read_text())
    rsa_asset = next(a for a in report1["assets"] if a["algorithm"] == "RSA" and a["confidence"] == "high")
    tracking_id = rsa_asset["tracking_id"]

    set_status_result = _run_main([str(project), "--set-status", tracking_id, "MIGRATED"])
    assert set_status_result.returncode == 0
    assert "MIGRATED" in set_status_result.stdout

    state_file = project / "migration_state.json"
    assert state_file.exists()
    state = json.loads(state_file.read_text())
    assert state[tracking_id]["status"] == "MIGRATED"

    verify_before_fix = _run_main([str(project), "--verify"])
    assert verify_before_fix.returncode == 0
    assert "not_verified_unchanged" in verify_before_fix.stdout

    source.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def make_key():\n"
        '    """modern rsa key"""\n'
        "    return rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
    )

    verify_after_fix = _run_main([str(project), "--verify"])
    assert verify_after_fix.returncode == 0
    assert "verified_risk_reduced" in verify_after_fix.stdout

    final_state = json.loads(state_file.read_text())
    assert final_state[tracking_id]["status"] == "VERIFIED"


def test_cli_rejects_invalid_status(tmp_path):
    project = tmp_path / "invalid_status_project"
    project.mkdir()
    (project / "x.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    _run_main([str(project), "--json-only", "--output", str(tmp_path / "out.json")])

    result = _run_main([str(project), "--set-status", "any_id", "NOT_A_STATUS"])
    assert result.returncode == 1
