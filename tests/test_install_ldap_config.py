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


def test_no_secret_on_a_command_line():
    """Secrets must not reach argv (ps, /proc/<pid>/cmdline) or ExecStart."""
    for line in SCRIPT.splitlines():
        code = line.split("#", 1)[0]
        assert not re.search(r"-[sw] \"?\$ADMIN_PW", code), line
        assert not re.search(r"src\.replication syncrepl .*\$ADMIN_PW", code), line
        if code.lstrip().startswith("ExecStart="):
            assert "SECRET" not in code and "--secret" not in code, line


def test_env_files_written_under_umask_077():
    for target in ('"$INSTALL_DIR/ldap/.env"', ".env)"):
        assert f"(umask 077; cat > {target}" in SCRIPT


def test_no_fixed_tmp_paths():
    assert not re.search(r'"/tmp/[\w.-]+"', SCRIPT)


def _run_mirror(tmp_path, fail_step=None, tls_ready="1"):
    """Run configure_mirror_mode with a stub builder (``fail_step`` exits 2,
    printing nothing, like a refused value) and a stub ldapmodify that logs
    what it was fed."""
    bindir = tmp_path / "venv" / "bin"
    bindir.mkdir(parents=True)
    builder = bindir / "python3"
    builder.write_text(f'#!/bin/sh\n[ "$3" = "{fail_step}" ] && exit 2\necho "dn: step-$3"\n')
    builder.chmod(0o755)
    modify = tmp_path / "ldapmodify"
    modify.write_text(f"#!/bin/sh\ncat >> {tmp_path}/applied\necho '---' >> {tmp_path}/applied\n")
    modify.chmod(0o755)
    script = ("set -e\nSERVER_ID=1 BASE_DN=dc=x ADMIN_DN=cn=a,dc=x ADMIN_PW=pw\n"
              "PEERS=(ldap://p:389)\n" + (f"TLS_READY={tls_ready}\n" if tls_ready else "")
              + _function("apply_config_ldif") + _function("repl_step")
              + _function("configure_mirror_mode") + "\nconfigure_mirror_mode\n")
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    res = subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env,
                         capture_output=True, text=True)
    applied = (tmp_path / "applied").read_text() if (tmp_path / "applied").exists() else ""
    return res, applied


def test_mirror_mode_applies_every_step_in_order(tmp_path):
    res, applied = _run_mirror(tmp_path)
    assert res.returncode == 0, res.stderr
    steps = re.findall(r"dn: step-(\S+)", applied)
    assert steps == ["syncprov-module", "syncprov", "serverid", "syncrepl", "mirrormode"]


def test_a_refused_replication_value_stops_the_chain(tmp_path):
    """A builder that refuses its input must fail the deploy, not feed
    ldapmodify an empty LDIF and go on to enable mirror mode."""
    res, applied = _run_mirror(tmp_path, fail_step="syncrepl")
    assert res.returncode != 0 and "replication setup failed" in res.stderr
    assert "step-mirrormode" not in applied and "---\n---" not in applied


def test_mirror_mode_refuses_a_node_without_tls(tmp_path):
    res, applied = _run_mirror(tmp_path, tls_ready=None)
    assert res.returncode != 0 and "needs slapd TLS" in res.stderr
    assert applied == ""


def test_apply_config_ldif_redacts_syncrepl_credentials(tmp_path):
    stub = tmp_path / "ldapmodify"
    stub.write_text("#!/bin/sh\ncat >/dev/null\n"
                    "echo 'olcSyncrepl: value #0: bad credentials=\"s3 \\\"cr3t\" rid=001' >&2\nexit 80\n")
    stub.chmod(0o755)
    script = "set -e\n" + _function("apply_config_ldif") + "\necho dn: x | apply_config_ldif\n"
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    res = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert res.returncode == 80 and "credentials=***" in res.stderr
    assert "cr3t" not in res.stderr and "s3" not in res.stderr.split("credentials=")[1]


def test_secret_tmpfile_is_removed_when_the_installer_exits_early(tmp_path):
    """The EXIT trap runs after the function that made the file has
    returned, so it must not depend on that function's locals."""
    record = tmp_path / "path"
    script = ("set -e\n_TMPFILES=()\n" + _function("cleanup_tmpfiles") + _function("new_tmpfile")
              + f'step() {{ local PW; new_tmpfile PW; printf secret > "$PW"; echo "$PW" > {record};'
              + " false; }\nstep\n")
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert res.returncode != 0
    left = record.read_text().strip()
    assert left and not os.path.exists(left)


def test_provision_server_makes_its_temp_files_through_new_tmpfile():
    body = "\n".join(l for l in _function("provision_server").splitlines()
                     if not l.strip().startswith("#"))
    assert "$(mktemp" not in body and "trap " not in body
    assert "new_tmpfile PWFILE" in body and "new_tmpfile TMPLDIF" in body
