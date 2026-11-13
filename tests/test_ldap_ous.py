"""OUs inside a tenant: users found in any OU, OU create/rename/delete, and
moving users between OUs of the same tenant with their group memberships kept.

Uses an in-memory fake directory so the tests check real outcomes (where an
entry ends up, which group values change) rather than call counts.
"""
import importlib.util
import os
import re
import sys
from contextlib import contextmanager

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from test_ldap_manager_calls import _load_manager  # noqa: E402

BASE = "dc=example,dc=com"
USERS = f"ou=users,ou=acme,{BASE}"
GROUPS = f"ou=groups,ou=acme,{BASE}"


def _ldap_dn():
    """Import the pure DN helpers straight from src."""
    path = os.path.join(os.path.dirname(__file__), "..", "src", "ldap_dn.py")
    spec = importlib.util.spec_from_file_location("ldap_dn_ous", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeDir:
    """A tiny directory: DN (lower-cased key) -> (DN, attrs). Supports the
    calls LdapManager makes, with python-ldap's argument shapes."""

    def __init__(self, ldap, entries):
        self.ldap = ldap
        self.e = {dn.lower(): (dn, attrs) for dn, attrs in entries.items()}

    def _under(self, dn, base, scope):
        """True when ``dn`` is in the search scope of ``base``."""
        d, b = dn.lower(), base.lower()
        if scope == self.ldap.SCOPE_BASE:
            return d == b
        if scope == self.ldap.SCOPE_ONELEVEL:
            return d.endswith("," + b) and "," not in d[: -len(b) - 1]
        return d == b or d.endswith("," + b)

    def search_s(self, base, scope, filt, attrs=None):
        if base.lower() not in self.e:
            raise self.ldap.NO_SUCH_OBJECT(base)
        f = filt.lower()
        # Object classes named in the filter (OR semantics is enough here).
        wanted = set(re.findall(r"objectclass=([\w*]+)", f))
        out = []
        for dn, a in self.e.values():
            if not self._under(dn, base, scope):
                continue
            classes = {c.decode().lower() for c in a.get("objectClass", [])}
            if "*" not in wanted and not (classes & wanted):
                continue
            for attr in ("uid", "member"):
                m = re.search(rf"\({attr}=([^)]*)\)", filt)
                if m and m.group(1).lower() not in [v.decode().lower() for v in a.get(attr, [])]:
                    break
            else:
                out.append((dn, a))
        return out

    def add_s(self, dn, modlist):
        parent = dn.split(",", 1)[1]
        if parent.lower() not in self.e:
            raise self.ldap.NO_SUCH_OBJECT(parent)
        if dn.lower() in self.e:
            raise self.ldap.ALREADY_EXISTS(dn)
        self.e[dn.lower()] = (dn, dict(modlist))

    def modify_s(self, dn, modlist):
        assert all(isinstance(t, tuple) and len(t) == 3 for t in modlist)
        _dn, a = self.e[dn.lower()]
        for op, attr, vals in modlist:
            cur = a.setdefault(attr, [])
            if op == self.ldap.MOD_ADD:
                cur.extend(vals)
            elif op == self.ldap.MOD_DELETE:
                a[attr] = [v for v in cur if v not in vals]
            else:
                a[attr] = list(vals)

    def rename_s(self, dn, newrdn, newsuperior=None, delold=1):
        if dn.lower() not in self.e:
            raise self.ldap.NO_SUCH_OBJECT(dn)
        parent = newsuperior or dn.split(",", 1)[1]
        if parent.lower() not in self.e:
            raise self.ldap.NO_SUCH_OBJECT(parent)
        new = f"{newrdn},{parent}"
        if new.lower() in self.e and new.lower() != dn.lower():
            raise self.ldap.ALREADY_EXISTS(new)
        # Move the entry and everything below it.
        for key in [k for k in self.e if k == dn.lower() or k.endswith("," + dn.lower())]:
            old_dn, a = self.e.pop(key)
            self.e[(old_dn[: len(old_dn) - len(dn)] + new).lower()] = (
                old_dn[: len(old_dn) - len(dn)] + new, a)

    def delete_s(self, dn):
        if any(k.endswith("," + dn.lower()) for k in self.e):
            raise self.ldap.LDAPError("not allowed on non-leaf")
        del self.e[dn.lower()]


def _ou(name):
    return {"objectClass": [b"organizationalUnit"], "ou": [name.encode()]}


def _user(uid):
    return {"objectClass": [b"person", b"inetOrgPerson"], "uid": [uid.encode()],
            "userPassword": [b"{SASL}" + uid.encode() + b"@corp.example"]}


@pytest.fixture
def env(monkeypatch):
    mod = _load_manager(monkeypatch)
    mod.ldap.NO_SUCH_OBJECT = type("NO_SUCH_OBJECT", (mod.ldap.LDAPError,), {})
    entries = {
        USERS: _ou("users"),
        GROUPS: _ou("groups"),
        f"ou=Eng,{USERS}": _ou("Eng"),
        f"ou=Lab,ou=Eng,{USERS}": _ou("Lab"),
        f"ou=Sales,{USERS}": _ou("Sales"),
        f"uid=alice,ou=Lab,ou=Eng,{USERS}": _user("alice"),
        f"uid=bob,{USERS}": _user("bob"),
        f"cn=staff,{GROUPS}": {"objectClass": [b"groupOfNames"],
                                "member": [BASE.encode(),
                                           f"uid=alice,ou=Lab,ou=Eng,{USERS}".encode()]},
    }
    fake = _FakeDir(mod.ldap, entries)
    mgr = mod.LdapManager.__new__(mod.LdapManager)
    mgr.base_dn = BASE

    @contextmanager
    def _conn():
        yield fake
    mgr._conn = _conn
    mgr._get_connection = lambda: fake
    return mgr, fake


def _members(fake):
    return [v.decode() for v in fake.e[f"cn=staff,{GROUPS}".lower()][1]["member"]]


# ---- ldap_dn helpers ---------------------------------------------------------

def test_ou_path_dn_and_back():
    d = _ldap_dn()
    dn = d.ou_path_dn(BASE, "ACME", ["Eng", "Lab"])
    assert dn == f"ou=Lab,ou=Eng,{USERS}"
    assert d.ou_path_of(f"uid=x,{dn}", USERS) == ["Eng", "Lab"]
    assert d.ou_path_of(USERS, USERS) is None
    assert d.ou_path_of(f"uid=x,ou=users,ou=other,{BASE}", USERS) is None


def test_parse_dn_handles_both_escape_forms():
    d = _ldap_dn()
    assert d.parse_dn(r"ou=R\2CD,ou=A\,B,dc=x") == [("ou", "R,D"), ("ou", "A,B"), ("dc", "x")]
    assert d.ou_path_of(r"uid=x,ou=R\2CD," + USERS, USERS) == ["R,D"]


def test_ou_names_are_validated():
    d = _ldap_dn()
    for bad in ("", "  ", "a/b", "x" * 65):
        with pytest.raises(ValueError):
            d.ou_path_dn(BASE, "acme", [bad])


def test_rebase_dn_counts_rdns_not_characters():
    d = _ldap_dn()
    assert (d.rebase_dn(r"uid=a\,b,OU=Lab,ou=Eng," + USERS, f"ou=lab,ou=eng,{USERS}",
                        f"ou=Labs,ou=Eng,{USERS}")
            == r"uid=a\,b,ou=Labs,ou=Eng," + USERS)


# ---- users found in any OU ---------------------------------------------------

def test_user_ops_find_users_in_nested_ous(env):
    mgr, fake = env
    assert mgr.update_user_scoped("alice", {"cn": "Alice"}, "acme")["dn"] == f"uid=alice,ou=Lab,ou=Eng,{USERS}"
    res = mgr.get_user_groups("alice", "acme")
    assert res["status"] == "SUCCESS" and [g["name"] for g in res["groups"]] == ["staff"]


def test_missing_user_is_an_error_not_success(env):
    mgr, _ = env
    assert mgr.update_user_scoped("nobody", {"cn": "x"}, "acme")["status"] == "ERROR"
    assert mgr.delete_user_scoped("nobody", "acme")["status"] == "ERROR"
    assert mgr.add_member_scoped("nobody", "staff", "acme")["status"] == "ERROR"


def test_create_user_in_ou_and_uid_unique_tenant_wide(env):
    mgr, fake = env
    res = mgr.create_user_scoped("carol", {}, "acme", "entra", "carol@corp.example",
                                 None, ["Sales"])
    assert res["status"] == "SUCCESS" and res["dn"] == f"uid=carol,ou=Sales,{USERS}"
    # alice lives in Eng/Lab; the same uid in another OU is refused.
    dup = mgr.create_user_scoped("alice", {}, "acme", "entra", "a@corp.example", None, ["Sales"])
    assert dup["status"] == "ERROR" and "already exists" in dup["message"]
    missing = mgr.create_user_scoped("dave", {}, "acme", "entra", "d@corp.example", None, ["Nope"])
    assert missing["status"] == "ERROR"


def test_list_users_reports_ou_path_and_upn(env):
    mgr, _ = env
    users = {u["username"]: u for u in mgr.list_users_scoped("acme")}
    assert users["alice"]["ou_path"] == ["Eng", "Lab"]
    assert users["bob"]["ou_path"] == []
    assert users["alice"]["upn"] == "alice@corp.example"


# ---- OU management -----------------------------------------------------------

def test_list_ous_tree_with_counts(env):
    mgr, _ = env
    res = mgr.list_ous_scoped("acme")
    assert [o["path"] for o in res["ous"]] == [["Eng"], ["Eng", "Lab"], ["Sales"]]
    assert {tuple(o["path"]): o["user_count"] for o in res["ous"]}[("Eng", "Lab")] == 1
    assert res["root_user_count"] == 1


def test_list_ous_empty_tenant(env):
    mgr, _ = env
    assert mgr.list_ous_scoped("newco") == {"status": "SUCCESS", "ous": [], "root_user_count": 0}


def test_create_ou_nested_and_errors(env):
    mgr, fake = env
    assert mgr.create_ou_scoped("Ops", ["Eng"], "acme")["status"] == "SUCCESS"
    assert f"ou=ops,ou=eng,{USERS}".lower() in fake.e
    assert mgr.create_ou_scoped("Ops", ["Eng"], "acme")["status"] == "ERROR"
    assert mgr.create_ou_scoped("X", ["Missing"], "acme")["status"] == "ERROR"
    assert mgr.create_ou_scoped("a/b", [], "acme")["status"] == "ERROR"


def test_delete_ou_only_when_empty_and_never_root(env):
    mgr, fake = env
    assert mgr.delete_ou_scoped(["Eng"], "acme")["status"] == "ERROR"
    assert mgr.delete_ou_scoped([], "acme")["status"] == "ERROR"
    assert mgr.delete_ou_scoped(["Sales"], "acme")["status"] == "SUCCESS"
    assert f"ou=sales,{USERS}".lower() not in fake.e
    assert mgr.delete_ou_scoped(["Sales"], "acme")["status"] == "ERROR"


def test_rename_ou_rewrites_group_members(env):
    mgr, fake = env
    res = mgr.rename_ou_scoped(["Eng"], "Engineering", "acme")
    assert res["status"] == "SUCCESS" and res["groups_updated"] == 1
    assert f"uid=alice,ou=Lab,ou=Engineering,{USERS}" in _members(fake)
    assert f"uid=alice,ou=Lab,ou=Eng,{USERS}" not in _members(fake)
    assert BASE in _members(fake)
    assert mgr.rename_ou_scoped([], "x", "acme")["status"] == "ERROR"


# ---- moving users within the tenant ------------------------------------------

def test_move_user_between_ous_keeps_groups(env):
    mgr, fake = env
    res = mgr.move_user_scoped("alice", ["Sales"], "acme")
    assert res["status"] == "SUCCESS" and res["dn"] == f"uid=alice,ou=Sales,{USERS}"
    assert f"uid=alice,ou=Sales,{USERS}".lower() in fake.e
    assert _members(fake) == [BASE, f"uid=alice,ou=Sales,{USERS}"]


def test_move_user_to_root_and_noop(env):
    mgr, fake = env
    assert mgr.move_user_scoped("alice", [], "acme")["dn"] == f"uid=alice,{USERS}"
    again = mgr.move_user_scoped("alice", [], "acme")
    assert again["status"] == "SUCCESS" and again["message"] == "already in that OU"


def test_move_user_stays_inside_its_tenant(env):
    mgr, fake = env
    # The target path is built from the same tenant slug: an OU name that looks
    # like another tenant's DN is escaped into a (missing) OU of this tenant.
    res = mgr.move_user_scoped("alice", [f"users,ou=other,{BASE}"], "acme")
    assert res["status"] == "ERROR"
    assert f"uid=alice,ou=Lab,ou=Eng,{USERS}".lower() in fake.e
    # A user of another tenant can't be found, so can't be moved.
    assert mgr.move_user_scoped("alice", [], "other")["status"] == "ERROR"


def test_move_user_with_escaped_comma_in_uid(env):
    mgr, fake = env
    # uid "a,b" is stored as uid=a\,b; the RDN must keep its escaped comma.
    fake.e[f"uid=a\\,b,{USERS}".lower()] = (f"uid=a\\,b,{USERS}", _user("a,b"))
    res = mgr.move_user_scoped("a,b", ["Sales"], "acme")
    assert res["status"] == "SUCCESS" and res["dn"] == f"uid=a\\,b,ou=Sales,{USERS}"
    assert f"uid=a\\,b,ou=Sales,{USERS}".lower() in fake.e


def test_failed_group_rewrite_rolls_back_move_and_rename(env, monkeypatch):
    mgr, fake = env
    real_modify = fake.modify_s
    calls = {"n": 0}

    def failing_modify(dn, modlist):
        # Fail the first group rewrite; let the rollback's modify through.
        calls["n"] += 1
        if calls["n"] == 1:
            raise fake.ldap.LDAPError("server busy")
        return real_modify(dn, modlist)
    monkeypatch.setattr(fake, "modify_s", failing_modify)
    before_members = _members(fake)
    # Move: the user goes back to its old OU and the group is unchanged.
    assert mgr.move_user_scoped("alice", ["Sales"], "acme")["status"] == "ERROR"
    assert f"uid=alice,ou=Lab,ou=Eng,{USERS}".lower() in fake.e
    assert f"uid=alice,ou=Sales,{USERS}".lower() not in fake.e
    assert _members(fake) == before_members
    # OU rename: the OU keeps its old name and the group is unchanged.
    calls["n"] = 0
    assert mgr.rename_ou_scoped(["Eng"], "Engineering", "acme")["status"] == "ERROR"
    assert f"ou=Eng,{USERS}".lower() in fake.e
    assert f"ou=Engineering,{USERS}".lower() not in fake.e
    assert _members(fake) == before_members


def test_failed_rollback_is_reported_as_partial(env, monkeypatch):
    mgr, fake = env
    real_rename = fake.rename_s
    renames = {"n": 0}

    def rename_once(*a):
        # The move's rename works; the rollback's rename fails.
        renames["n"] += 1
        if renames["n"] > 1:
            raise fake.ldap.LDAPError("server busy")
        return real_rename(*a)

    def failing_modify(dn, modlist):
        raise fake.ldap.LDAPError("group write refused")
    monkeypatch.setattr(fake, "rename_s", rename_once)
    monkeypatch.setattr(fake, "modify_s", failing_modify)
    res = mgr.move_user_scoped("alice", ["Sales"], "acme")
    assert res["status"] == "ERROR" and res["error"] == "PARTIAL_ROLLBACK"
    assert f"still at uid=alice,ou=Sales,{USERS}" in res["message"]
