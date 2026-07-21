"""LdapSpoke list/read handlers return a clean ERROR envelope on LDAPError.

Previously the list/read handlers (LIST_OUS / LIST_USERS / LIST_GROUPS /
LDAP_LIST_USERS / LDAP_LIST_GROUPS) let ``ldap.LDAPError`` propagate; the
control plane catches it but via ``logger.exception``, dumping a 30-line
traceback PER CALL into the spoke log. A stale admin password (bind result 49
= ``INVALID_CREDENTIALS``) therefore spammed the log on every poll. These
handlers now catch ``LDAPError`` and return a targeted ERROR envelope — one
log line, and a "re-push LDAP_ADMIN_PW" hint for the common bind failure.

Self-contained: stubs python-ldap (not installed in dev) including
``INVALID_CREDENTIALS``, loads ldap_spoke as a synthetic namespace package
(mirrors test_install_cert.py's harness), and monkeypatches the manager's
list methods to raise.
"""
import asyncio
import importlib.util
import sys
import types
from pathlib import Path

_PXMX_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, "/Users/lbockenstedt/vscode/lm/core/src")

# Stub python-ldap just enough that ldap_manager + ldap_spoke import. Adds
# INVALID_CREDENTIALS (the bind-failure result 49) — the install_cert stub
# doesn't need it, but the error-envelope path does.
_ldap = types.ModuleType("ldap")
_ldap.SCOPE_SUBTREE = 2
_ldap.LDAPError = type("LDAPError", (Exception,), {})
_ldap.INVALID_CREDENTIALS = type("INVALID_CREDENTIALS", (_ldap.LDAPError,), {})
_ldap.MOD_ADD = 0
_ldap.MOD_DELETE = 1
_ldap.MOD_REPLACE = 2
_ldap.initialize = lambda url: None
_ldap.filter = types.ModuleType("ldap.filter")
_ldap.dn = types.ModuleType("ldap.dn")
_ldap.dn.escape_dn_chars = lambda v: v
sys.modules["ldap"] = _ldap
sys.modules["ldap.filter"] = _ldap.filter
sys.modules["ldap.dn"] = _ldap.dn

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
LDAPError = _ldap.LDAPError
INVALID_CREDENTIALS = _ldap.INVALID_CREDENTIALS


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


def _spoke():
    return LdapSpoke("ldap-1", {})


def test_list_ous_invalid_credentials_returns_clean_envelope():
    sp = _spoke()
    sp.manager.list_ous = lambda: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LIST_OUS", {}))
    assert res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"
    assert "LDAP_ADMIN_PW" in res["message"]


def test_ldap_list_users_invalid_credentials_returns_clean_envelope():
    sp = _spoke()
    sp.manager.list_users_scoped = lambda slug: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LDAP_LIST_USERS", {"tenant_slug": "lrb"}))
    assert res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"


def test_list_ous_does_not_raise_on_invalid_credentials():
    # The whole point: the handler must NOT raise (which would trigger the
    # control plane's logger.exception traceback dump). It returns a dict.
    sp = _spoke()
    sp.manager.list_ous = lambda: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LIST_OUS", {}))
    assert isinstance(res, dict) and "status" in res


def test_generic_ldap_error_envelope_has_type_and_message():
    sp = _spoke()
    sp.manager.list_groups = lambda: (_ for _ in ()).throw(
        LDAPError("server down"))
    res = _run(sp.handle_command("LIST_GROUPS", {}))
    assert res["status"] == "ERROR"
    assert "LDAPError" in res["message"]
    assert "server down" in res["message"]


def test_ldap_list_groups_invalid_credentials_returns_clean_envelope():
    sp = _spoke()
    sp.manager.list_groups_scoped = lambda slug: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LDAP_LIST_GROUPS", {"tenant_slug": "lrb"}))
    assert res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"


def test_list_users_invalid_credentials_returns_clean_envelope():
    sp = _spoke()
    sp.manager.list_users = lambda: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LIST_USERS", {}))
    assert res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"


def test_success_path_still_wraps_data():
    sp = _spoke()
    sp.manager.list_ous = lambda: [{"name": "users", "dn": "ou=users,dc=example,dc=org"}]
    res = _run(sp.handle_command("LIST_OUS", {}))
    assert res["status"] == "SUCCESS"
    assert res["data"][0]["name"] == "users"