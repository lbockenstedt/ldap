"""install_ldap.sh cn=config changes must actually apply (or fail loudly).

Regression: slapd's SASL mech_list was "plain login", which drops EXTERNAL, so
after any slapd restart every `ldapmodify -Y EXTERNAL` (admin password reset,
replication, TLS) failed — and the installer discarded the error, reporting a
successful deploy that changed nothing.
"""
import os
import re
import stat
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = open(os.path.join(ROOT, "install_ldap.sh")).read()


def test_sasl_mech_list_keeps_external():
    m = re.search(r"^mech_list: (.+)$", SCRIPT, re.M)
    assert m and "external" in m.group(1).lower().split()


def test_no_ldapmodify_errors_swallowed():
    for line in SCRIPT.splitlines():
        if "ldapmodify" in line and not line.lstrip().startswith("#"):
            assert ">/dev/null 2>&1" not in line and "|| true" not in line, line


def _function(name):
    start = SCRIPT.index(f"{name}() {{")
    end = SCRIPT.index("\n}\n", start) + 3
    return SCRIPT[start:end]


def _run_apply(tmp_path, rc):
    stub = tmp_path / "ldapmodify"
    stub.write_text(f"#!/bin/sh\ncat >/dev/null\necho 'ldap_modify: result {rc}' >&2\nexit {rc}\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    script = "set -e\n" + _function("apply_config_ldif") + "\necho dn: x | apply_config_ldif\n"
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)


def test_apply_config_ldif_tolerates_exists(tmp_path):
    for rc in (0, 20, 68):
        assert _run_apply(tmp_path, rc).returncode == 0


def test_apply_config_ldif_reports_real_failures(tmp_path):
    res = _run_apply(tmp_path, 80)
    assert res.returncode == 80 and "failed rc=80" in res.stderr
