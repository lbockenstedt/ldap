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
sys.modules["ldap"] = _ldap
sys.modules["ldap.filter"] = _ldap.filter

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