"""LdapManager must call python-ldap with the shapes the real library accepts.

Regression: every ``add_s`` passed an attribute dict and group membership used
``modify_s(dn, op, list)``; real python-ldap rejects both with TypeError, so the
Directory spoke could not create OUs, users or groups (JIT provisioning failed
with "List_to_LDAPMods(): expected list of tuples").
"""
import importlib.util
import sys
import types
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_manager(monkeypatch):
    lm = types.ModuleType("ldap")
    lm.LDAPError = type("LDAPError", (Exception,), {})
    lm.ALREADY_EXISTS = type("ALREADY_EXISTS", (lm.LDAPError,), {})
    lm.INVALID_CREDENTIALS = type("INVALID_CREDENTIALS", (lm.LDAPError,), {})
    lm.SCOPE_SUBTREE, lm.SCOPE_BASE, lm.SCOPE_ONELEVEL = 2, 0, 1
    lm.MOD_ADD, lm.MOD_DELETE, lm.MOD_REPLACE = 0, 1, 2
    lm.filter = types.ModuleType("ldap.filter")
    lm.filter.escape_filter_chars = lambda v: v
    lm.dn = types.ModuleType("ldap.dn")
    lm.dn.escape_dn_chars = lambda v: v
    lm.modlist = types.ModuleType("ldap.modlist")
    lm.modlist.addModlist = lambda entry: [(k, v) for k, v in entry.items() if v]
    for name, mod in (("ldap", lm), ("ldap.filter", lm.filter),
                      ("ldap.dn", lm.dn), ("ldap.modlist", lm.modlist)):
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.syspath_prepend(str(ROOT / "src"))
    spec = importlib.util.spec_from_file_location("ldap_manager_calls_mgr",
                                                  ROOT / "src" / "ldap_manager.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _StrictConn:
    """Mimics python-ldap's argument checks."""

    def __init__(self):
        self.adds, self.mods = [], []

    def add_s(self, dn, modlist):
        if not (isinstance(modlist, list) and all(isinstance(t, tuple) for t in modlist)):
            raise TypeError("List_to_LDAPMods(): expected list of tuples")
        self.adds.append((dn, modlist))

    def modify_s(self, dn, modlist, *extra):
        if extra or not all(isinstance(t, tuple) and len(t) == 3 for t in modlist):
            raise TypeError("modify_s(dn, modlist) expects (op, attr, values) tuples")
        self.mods.append((dn, modlist))


def _manager(mod, conn):
    mgr = mod.LdapManager.__new__(mod.LdapManager)
    mgr.base_dn = "dc=orange-tme,dc=com"

    @contextmanager
    def _conn():
        yield conn
    mgr._conn = _conn
    mgr._get_connection = lambda: conn
    return mgr


def test_add_entry_converts_dict_to_modlist(monkeypatch):
    mod = _load_manager(monkeypatch)
    conn = _StrictConn()
    mod._add_entry(conn, "ou=default,dc=orange-tme,dc=com",
                   {"objectClass": [b"organizationalUnit"], "ou": [b"default"]})
    assert conn.adds == [("ou=default,dc=orange-tme,dc=com",
                          [("objectClass", [b"organizationalUnit"]), ("ou", [b"default"])])]


def test_group_membership_uses_modlist_tuples(monkeypatch):
    mod = _load_manager(monkeypatch)
    conn = _StrictConn()
    mgr = _manager(mod, conn)
    for fn in (mgr.add_user_to_group, mgr.remove_user_from_group):
        res = fn("uid=a,ou=users,dc=orange-tme,dc=com", "cn=g,ou=groups,dc=orange-tme,dc=com")
        assert res["status"] == "SUCCESS", res
    assert [m[1][0][0] for m in conn.mods] == [0, 1]
