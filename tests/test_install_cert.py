"""Tests for LdapSpoke.install_cert — the directory (OpenLDAP) INSTALL_CERT target.

The le spoke (via the hub) pushes a Let's Encrypt cert here; the spoke writes the
PEM leaf/CA/key to /etc/ldap/tls, points slapd's olcTLS* at them via
``ldapmodify -Y EXTERNAL -H ldapi:///`` on cn=config (with ``replace:``), and
restarts slapd so the new SSL context takes effect (OpenLDAP ITS#6135). The
leaf goes to olcTLSCertificateFile alone; intermediates (+ any supplied chain)
go to the CA bundle. The key is 0600 + chowned to the slapd user (best-effort)
so slapd can read it. The spoke runs as root (install_ldap.sh User=root).

Self-contained: stubs python-ldap (not installed in dev) so ldap_manager
imports, loads ldap_spoke as a synthetic namespace package (it uses relative
imports under ``-m src.main``), and puts lm/core/src on the path for base_spoke.
install_cert doesn't touch LdapManager (it's host-OS work), so the stub's
behavior is irrelevant — it only needs to import.
"""
import asyncio
import base64
import importlib.util
import os
import shutil
import sys
import tempfile
import types
from pathlib import Path

_PXMX_ROOT = Path(__file__).resolve().parent.parent
# base_spoke (stdlib-only) lives in lm/core/src.
sys.path.insert(0, "/Users/lbockenstedt/vscode/lm/core/src")

# Stub python-ldap (not installed in dev) just enough that ldap_manager imports.
_ldap = types.ModuleType("ldap")
_ldap.SCOPE_SUBTREE = 2
_ldap.LDAPError = type("LDAPError", (Exception,), {})
_ldap.MOD_ADD = 0
_ldap.MOD_DELETE = 1
_ldap.MOD_REPLACE = 2
_ldap.initialize = lambda url: None
_ldap.filter = types.ModuleType("ldap.filter")
_ldap.dn = types.ModuleType("ldap.dn")
_ldap.dn.escape_dn_chars = lambda v: v  # identity stub (real one escapes DN chars)
sys.modules["ldap"] = _ldap
sys.modules["ldap.filter"] = _ldap.filter
sys.modules["ldap.dn"] = _ldap.dn
_ldap.modlist = types.ModuleType("ldap.modlist")
_ldap.modlist.addModlist = lambda entry: [(k, v) for k, v in entry.items() if v]
sys.modules["ldap.modlist"] = _ldap.modlist

SRC = _PXMX_ROOT / "src"
_pkg = types.ModuleType("ldap_src_pkg")
_pkg.__path__ = [str(SRC)]
sys.modules["ldap_src_pkg"] = _pkg
_spec_m = importlib.util.spec_from_file_location(
    "ldap_src_pkg.ldap_manager", SRC / "ldap_manager.py")
_mgr = importlib.util.module_from_spec(_spec_m)
sys.modules["ldap_src_pkg.ldap_manager"] = _mgr
_spec_m.loader.exec_module(_mgr)
_spec_s = importlib.util.spec_from_file_location(
    "ldap_src_pkg.ldap_spoke", SRC / "ldap_spoke.py")
spoke_mod = importlib.util.module_from_spec(_spec_s)
sys.modules["ldap_src_pkg.ldap_spoke"] = spoke_mod
_spec_s.loader.exec_module(spoke_mod)
LdapSpoke = spoke_mod.LdapSpoke


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


_LEAF = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
_INTER = "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n"
_FC = _LEAF + _INTER
_KEY = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"


class _FakeProc:
    def __init__(self, returncode, name, capture, stderr=b""):
        self.returncode = returncode
        self._name = name
        self._capture = capture
        self._stderr = stderr

    async def communicate(self, input=None):
        if input is not None:
            self._capture[self._name + "_stdin"] = input.decode()
        return b"", self._stderr


def _patch_exec(spoke_mod, capture, rc_map):
    """Route ldapmodify / systemctl to fakes that record the call. ``rc_map``
    maps name → returncode (default 0). Returns the real exec to restore."""
    real = spoke_mod.asyncio.create_subprocess_exec
    rc_map = {"ldapmodify": 0, "systemctl": 0, **rc_map}

    async def fake_exec(bin_, *args, **kwargs):
        name = bin_
        capture.setdefault("calls", []).append([bin_, *args])
        return _FakeProc(rc_map.get(name, 0), name, capture,
                         stderr=b"boom" if rc_map.get(name, 0) != 0 else b"")

    spoke_mod.asyncio.create_subprocess_exec = fake_exec
    return real


def _make_spoke(cert_dir):
    return LdapSpoke("ldap-1", {"LDAP_TLS_DIR": cert_dir,
                                "LDAP_SLAPD_USER": "openldap"})


def test_install_cert_writes_files_runs_ldapmodify_and_restarts():
    with tempfile.TemporaryDirectory() as d:
        sp = _make_spoke(d)
        cap = {}
        real = _patch_exec(spoke_mod, cap, {})
        try:
            res = _run(sp.install_cert(_FC, _KEY))
        finally:
            spoke_mod.asyncio.create_subprocess_exec = real
        assert res["status"] == "SUCCESS"
        # Cert = leaf only; CA bundle = intermediate; key = privkey.
        assert open(f"{d}/slapd-cert.pem").read() == _LEAF
        assert open(f"{d}/slapd-ca.pem").read() == _INTER
        assert open(f"{d}/slapd-key.pem").read() == _KEY.strip()
        assert os.stat(f"{d}/slapd-cert.pem").st_mode & 0o777 == 0o644
        assert os.stat(f"{d}/slapd-key.pem").st_mode & 0o777 == 0o600
        # ldapmodify ran EXTERNAL over ldapi with the right LDIF (replace:).
        ldif = cap.get("ldapmodify_stdin", "")
        assert "dn: cn=config" in ldif
        assert "replace: olcTLSCertificateFile" in ldif
        assert "replace: olcTLSCertificateKeyFile" in ldif
        assert "replace: olcTLSCACertificateFile" in ldif
        assert f"olcTLSCertificateFile: {d}/slapd-cert.pem" in ldif
        assert f"olcTLSCertificateKeyFile: {d}/slapd-key.pem" in ldif
        # systemctl restart slapd ran.
        assert any(c[:3] == ["systemctl", "restart", "slapd"] for c in cap["calls"])


def test_install_cert_leaf_only_omits_ca_block():
    with tempfile.TemporaryDirectory() as d:
        sp = _make_spoke(d)
        cap = {}
        real = _patch_exec(spoke_mod, cap, {})
        try:
            res = _run(sp.install_cert(_LEAF, _KEY))
        finally:
            spoke_mod.asyncio.create_subprocess_exec = real
        assert res["status"] == "SUCCESS"
        assert not os.path.exists(f"{d}/slapd-ca.pem")  # no CA file written
        ldif = cap.get("ldapmodify_stdin", "")
        assert "olcTLSCACertificateFile" not in ldif  # CA block omitted


def test_install_cert_supplied_ca_appended_to_bundle():
    with tempfile.TemporaryDirectory() as d:
        sp = _make_spoke(d)
        cap = {}
        real = _patch_exec(spoke_mod, cap, {})
        extra = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n"
        try:
            res = _run(sp.install_cert(_FC, _KEY, ca_pem=extra))
        finally:
            spoke_mod.asyncio.create_subprocess_exec = real
        assert res["status"] == "SUCCESS"
        # CA bundle = intermediate (from fullchain) + supplied root.
        assert _INTER in open(f"{d}/slapd-ca.pem").read()
        assert "ROOT" in open(f"{d}/slapd-ca.pem").read()


def test_install_cert_missing_material_errors_without_subprocess():
    with tempfile.TemporaryDirectory() as d:
        sp = _make_spoke(d)
        cap = {}
        real = _patch_exec(spoke_mod, cap, {})
        try:
            r1 = _run(sp.install_cert("", _KEY))
            r2 = _run(sp.install_cert("not a cert", _KEY))
            r3 = _run(sp.install_cert(_FC, ""))
        finally:
            spoke_mod.asyncio.create_subprocess_exec = real
        assert r1["status"] == "ERROR" and "fullchain" in r1["message"]
        assert r2["status"] == "ERROR"
        assert r3["status"] == "ERROR" and "private key" in r3["message"]
        assert cap.get("calls", []) == []  # no subprocess on bad input


def test_install_cert_ldapmodify_failure_skips_restart():
    with tempfile.TemporaryDirectory() as d:
        sp = _make_spoke(d)
        cap = {}
        real = _patch_exec(spoke_mod, cap, {"ldapmodify": 1})
        try:
            res = _run(sp.install_cert(_FC, _KEY))
        finally:
            spoke_mod.asyncio.create_subprocess_exec = real
        assert res["status"] == "ERROR"
        assert "ldapmodify failed" in res["message"]
        # restart must NOT run when ldapmodify failed
        assert not any(c[:3] == ["systemctl", "restart", "slapd"] for c in cap["calls"])


def test_install_cert_restart_failure_errors():
    with tempfile.TemporaryDirectory() as d:
        sp = _make_spoke(d)
        cap = {}
        real = _patch_exec(spoke_mod, cap, {"systemctl": 1})
        try:
            res = _run(sp.install_cert(_FC, _KEY))
        finally:
            spoke_mod.asyncio.create_subprocess_exec = real
        assert res["status"] == "ERROR"
        assert "slapd restart failed" in res["message"]


def test_install_cert_no_restart_when_disabled():
    with tempfile.TemporaryDirectory() as d:
        sp = LdapSpoke("ldap-1", {"LDAP_TLS_DIR": d, "LDAP_TLS_RESTART": False,
                                  "LDAP_SLAPD_USER": "openldap"})
        cap = {}
        real = _patch_exec(spoke_mod, cap, {})
        try:
            res = _run(sp.install_cert(_FC, _KEY))
        finally:
            spoke_mod.asyncio.create_subprocess_exec = real
        assert res["status"] == "SUCCESS"
        assert not any(c[:3] == ["systemctl", "restart", "slapd"] for c in cap["calls"])


def test_split_chain():
    leaf, cas = LdapSpoke._split_chain(_FC)
    assert leaf == _LEAF
    assert cas == [_INTER]
    assert LdapSpoke._split_chain(_LEAF) == (_LEAF, [])
    assert LdapSpoke._split_chain("") == ("", [])
    assert LdapSpoke._split_chain("no pem") == ("", [])


def test_build_tls_ldif():
    ldif = LdapSpoke._build_tls_ldif("/c.pem", "/k.pem", "/ca.pem")
    assert "replace: olcTLSCertificateFile" in ldif
    assert "olcTLSCertificateFile: /c.pem" in ldif
    assert "olcTLSCertificateKeyFile: /k.pem" in ldif
    assert "olcTLSCACertificateFile: /ca.pem" in ldif
    # No CA path → CA block omitted.
    ldif2 = LdapSpoke._build_tls_ldif("/c.pem", "/k.pem")
    assert "olcTLSCACertificateFile" not in ldif2

# ── Rollback: a failed install leaves the previous certificate live ─────────

_OLD_CERT = "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n"
_OLD_KEY = "-----BEGIN PRIVATE KEY-----\nOLDKEY\n-----END PRIVATE KEY-----\n"


def _scripted_exec(spoke_mod, calls, script, search_out=b""):
    """Fake create_subprocess_exec: ``script`` maps a binary to a list of
    return codes used in call order (then 0). ldapsearch prints
    ``search_out``. Every call is recorded with its stdin."""
    real = spoke_mod.asyncio.create_subprocess_exec

    async def fake_exec(bin_, *args, **kwargs):
        rcs = script.get(bin_, [])
        rc = rcs.pop(0) if rcs else 0
        entry = {"argv": [bin_, *args], "stdin": None}
        calls.append(entry)

        class _P:
            returncode = rc

            async def communicate(self, input=None):
                entry["stdin"] = input.decode() if input is not None else None
                if rc == "timeout":
                    raise asyncio.TimeoutError()
                out = search_out if bin_ == "ldapsearch" else b""
                return out, (b"boom" if rc else b"")
        return _P()

    spoke_mod.asyncio.create_subprocess_exec = fake_exec
    return real


def _seed_old(d):
    """An installed previous cert/key, as the installer leaves them."""
    for name, body, mode in (("slapd-cert.pem", _OLD_CERT, 0o644), ("slapd-key.pem", _OLD_KEY, 0o600)):
        with open(f"{d}/{name}", "w") as f:
            f.write(body)
        os.chmod(f"{d}/{name}", mode)


def _install(d, script, search_out=b"", **cfg):
    calls = []
    sp = LdapSpoke("ldap-1", {"LDAP_TLS_DIR": d, "LDAP_SLAPD_USER": "openldap", **cfg})
    real = _scripted_exec(spoke_mod, calls, script, search_out)
    try:
        res = _run(sp.install_cert(_FC, _KEY))
    finally:
        spoke_mod.asyncio.create_subprocess_exec = real
    return res, calls


def _names(calls):
    return [c["argv"][0] for c in calls]




def test_timed_out_modify_restores_files_and_cn_config():
    old = (b"dn: cn=config\nolcTLSCertificateFile: /old/cert.pem\n"
           b"olcTLSCertificateKeyFile:: L29sZC9rZXkucGVt\n\n")
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        res, calls = _install(d, {"ldapmodify": ["timeout", 0]}, search_out=old)
        assert res["status"] == "ERROR" and "error" not in res
        assert "ldapmodify timed out" in res["message"]
        assert open(f"{d}/slapd-cert.pem").read() == _OLD_CERT
        assert open(f"{d}/slapd-key.pem").read() == _OLD_KEY
        # The first ldapmodify timed out; cn=config may have applied it, so undo modify was run!
        assert _names(calls) == ["ldapsearch", "ldapmodify", "ldapmodify"]
        undo = calls[2]["stdin"]
        assert "olcTLSCertificateFile:: " + base64.b64encode(b"/old/cert.pem").decode() in undo
        assert "olcTLSCertificateKeyFile:: " + base64.b64encode(b"/old/key.pem").decode() in undo

def test_refused_modify_restores_previous_files_and_skips_restart():
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        res, calls = _install(d, {"ldapmodify": [1]})
        assert res["status"] == "ERROR" and "error" not in res
        assert "ldapmodify failed" in res["message"] and "previous certificate restored" in res["message"]
        assert open(f"{d}/slapd-cert.pem").read() == _OLD_CERT
        assert open(f"{d}/slapd-key.pem").read() == _OLD_KEY
        assert os.stat(f"{d}/slapd-key.pem").st_mode & 0o777 == 0o600
        assert not os.path.exists(f"{d}/slapd-ca.pem")  # absent before, removed again
        # slapd refused the modify whole: no undo modify, no restart.
        assert _names(calls) == ["ldapsearch", "ldapmodify"]


def test_tls_config_read_passes_a_filter_before_the_attributes():
    # ldapsearch takes `filter [attrs...]`; a bare attribute name would be
    # parsed as an invalid filter and fail every install.
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        _, calls = _install(d, {})
        argv = calls[0]["argv"]
        assert argv[0] == "ldapsearch"
        i = argv.index("base") + 1
        assert argv[i:] == ["(objectClass=*)", "olcTLSCertificateFile",
                            "olcTLSCertificateKeyFile", "olcTLSCACertificateFile"]


def test_failed_restart_restores_files_and_cn_config_then_restarts_again():
    old = (b"dn: cn=config\nolcTLSCertificateFile: /old/cert.pem\n"
           b"olcTLSCertificateKeyFile:: L29sZC9rZXkucGVt\n\n")  # base64 of /old/key.pem
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        res, calls = _install(d, {"systemctl": [1]}, search_out=old)
        assert res["status"] == "ERROR" and "error" not in res
        assert "slapd restart failed" in res["message"]
        assert open(f"{d}/slapd-cert.pem").read() == _OLD_CERT
        assert open(f"{d}/slapd-key.pem").read() == _OLD_KEY
        # slapd is started again before the cn=config undo, which needs its
        # ldapi socket; the final restart applies the old paths.
        assert _names(calls) == ["ldapsearch", "ldapmodify", "systemctl", "systemctl",
                                 "ldapmodify", "systemctl"]
        assert not os.path.exists(f"{d}/slapd-ca.pem")  # created, removed once unnamed
        undo = calls[4]["stdin"]
        assert "olcTLSCertificateFile:: " + base64.b64encode(b"/old/cert.pem").decode() in undo
        assert "olcTLSCertificateKeyFile:: " + base64.b64encode(b"/old/key.pem").decode() in undo
        # The CA attribute was unset before: a bare replace removes it again.
        assert "replace: olcTLSCACertificateFile\n-" in undo


def test_failed_undo_reports_partial_rollback():
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        res, _calls = _install(d, {"systemctl": [1, 1]})
        assert res["status"] == "ERROR" and res["error"] == "PARTIAL_ROLLBACK"
        assert "restarting slapd failed" in res["message"]


def test_unreadable_tls_config_changes_nothing():
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        res, calls = _install(d, {"ldapsearch": [1]})
        assert res["status"] == "ERROR" and "nothing changed" in res["message"]
        assert open(f"{d}/slapd-cert.pem").read() == _OLD_CERT
        assert _names(calls) == ["ldapsearch"]


def test_failed_key_write_restores_the_cert_already_written():
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        # The key's directory doesn't exist, so the key write fails after the cert's.
        res, calls = _install(d, {}, LDAP_TLS_KEY=f"{d}/missing/slapd-key.pem")
        assert res["status"] == "ERROR" and "previous certificate restored" in res["message"]
        assert open(f"{d}/slapd-cert.pem").read() == _OLD_CERT
        assert _names(calls) == ["ldapsearch"]


def test_symlinked_cert_is_restored_as_the_same_link():
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        os.rename(f"{d}/slapd-cert.pem", f"{d}/real-cert.pem")
        os.symlink(f"{d}/real-cert.pem", f"{d}/slapd-cert.pem")
        _install(d, {"ldapmodify": [1]})
        assert os.readlink(f"{d}/slapd-cert.pem") == f"{d}/real-cert.pem"
        assert open(f"{d}/real-cert.pem").read() == _OLD_CERT


def test_new_file_is_kept_while_cn_config_still_names_it():
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        # Restart fails, slapd won't come back, so the undo modify fails too.
        res, calls = _install(d, {"systemctl": [1, 1], "ldapmodify": [0, 1]})
        assert res["error"] == "PARTIAL_ROLLBACK"
        assert "restoring cn=config failed" in res["message"]
        assert open(f"{d}/slapd-cert.pem").read() == _OLD_CERT
        # cn=config may still point at the new CA bundle: removing it would
        # stop slapd starting at all.
        assert os.path.exists(f"{d}/slapd-ca.pem")
        assert _names(calls) == ["ldapsearch", "ldapmodify", "systemctl", "systemctl", "ldapmodify"]


def test_timed_out_child_is_killed_and_reaped():
    async def go():
        proc = await asyncio.create_subprocess_exec(
            "sleep", "30", stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            await LdapSpoke._communicate(proc, None, 0.2)
        except asyncio.TimeoutError:
            pass
        return proc.returncode
    # A child left running could apply its change after the rollback.
    assert _run(go()) is not None


def _cancel_during_modify(d, cancel_work):
    """Run install_cert with a slow first ldapmodify and cancel either the
    caller's task or (cancel_work) the inner _apply_cert task mid-modify."""
    calls = []
    sp = LdapSpoke("ldap-1", {"LDAP_TLS_DIR": d, "LDAP_SLAPD_USER": "openldap"})
    real_exec = spoke_mod.asyncio.create_subprocess_exec
    real_apply = sp._apply_cert
    inner = {}

    async def fake_exec(bin_, *args, **kwargs):
        calls.append(bin_)
        slow = bin_ == "ldapmodify" and calls.count("ldapmodify") == 1

        class _P:
            returncode = 0

            async def communicate(self, input=None):
                if slow:
                    await asyncio.sleep(0.3)
                return b"", b""

            def kill(self):
                pass

            async def wait(self):
                return 0
        return _P()

    async def spy_apply(*a, **kw):
        inner["task"] = asyncio.current_task()
        return await real_apply(*a, **kw)

    async def go():
        sp._apply_cert = spy_apply
        outer = asyncio.ensure_future(sp.install_cert(_FC, _KEY))
        await asyncio.sleep(0.1)
        (inner["task"] if cancel_work else outer).cancel()
        try:
            await outer
        except asyncio.CancelledError:
            return "cancelled"
        return "returned"

    spoke_mod.asyncio.create_subprocess_exec = fake_exec
    try:
        return _run(go()), calls
    finally:
        spoke_mod.asyncio.create_subprocess_exec = real_exec


def test_cancelled_caller_lets_the_install_finish():
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        outcome, calls = _cancel_during_modify(d, cancel_work=False)
        assert outcome == "cancelled"
        # Not stopped between steps: the modify and restart both ran.
        assert calls == ["ldapsearch", "ldapmodify", "systemctl"]
        assert open(f"{d}/slapd-cert.pem").read() == _LEAF


def test_cancelled_install_rolls_back_then_reraises():
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        outcome, calls = _cancel_during_modify(d, cancel_work=True)
        assert outcome == "cancelled"
        assert open(f"{d}/slapd-cert.pem").read() == _OLD_CERT
        assert open(f"{d}/slapd-key.pem").read() == _OLD_KEY
        # The modify may have applied: it is undone.
        assert calls == ["ldapsearch", "ldapmodify", "ldapmodify"]


def test_overlapping_installs_run_one_at_a_time():
    """A second INSTALL_CERT waits for the first to finish or roll back, so a
    failing first install cannot restore its snapshot over the second's cert."""
    leaf_b = "-----BEGIN CERTIFICATE-----\nLEAFB\n-----END CERTIFICATE-----\n"
    with tempfile.TemporaryDirectory() as d:
        _seed_old(d)
        calls = []
        sp = LdapSpoke("ldap-1", {"LDAP_TLS_DIR": d, "LDAP_SLAPD_USER": "openldap"})
        real_exec = spoke_mod.asyncio.create_subprocess_exec

        async def fake_exec(bin_, *args, **kwargs):
            calls.append(bin_)
            # The first modify is slow (so the second install overlaps it);
            # the first restart fails (so the first install rolls back).
            slow = bin_ == "ldapmodify" and calls.count("ldapmodify") == 1
            rc = 1 if bin_ == "systemctl" and calls.count("systemctl") == 1 else 0

            class _P:
                returncode = rc

                async def communicate(self, input=None):
                    if slow:
                        await asyncio.sleep(0.3)
                    return b"", (b"boom" if rc else b"")
            return _P()

        async def go():
            a = asyncio.ensure_future(sp.install_cert(_FC, _KEY))
            await asyncio.sleep(0.05)
            b = asyncio.ensure_future(sp.install_cert(leaf_b + _INTER, _KEY))
            return await asyncio.gather(a, b)

        spoke_mod.asyncio.create_subprocess_exec = fake_exec
        try:
            res_a, res_b = _run(go())
        finally:
            spoke_mod.asyncio.create_subprocess_exec = real_exec
        assert res_a["status"] == "ERROR"
        assert res_b["status"] == "SUCCESS"
        assert open(f"{d}/slapd-cert.pem").read() == leaf_b
        # The second install only read the TLS config after the first ended.
        assert calls.index("ldapsearch", 1) > calls.index("systemctl", calls.index("systemctl") + 1)
