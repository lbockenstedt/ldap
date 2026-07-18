"""Tests for the pure tenant-scoped DN builder (src/ldap_dn.py).

Dependency-free (no python-ldap), so it runs in the dev env. Covers RFC-4514
escaping (DN-injection guard), the tenant OU / users / groups / user / group DN
layout, base-level (no-slug) back-compat, slug validation, and — critically —
the CASE-INSENSITIVE tenant identity: "LRB", "lrb", "Lrb" must all resolve to
ONE canonical OU (lower-case), never three.
"""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
_spec = importlib.util.spec_from_file_location(
    "ldap_dn", os.path.join(os.path.dirname(__file__), "..", "src", "ldap_dn.py"))
ldap_dn = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ldap_dn)

import pytest

BASE = "dc=lm,dc=local"


# ── escaping (DN-injection guard) ───────────────────────────────────────────

def test_escape_specials():
    assert ldap_dn.escape_rdn_value("a,b") == "a\\,b"
    assert ldap_dn.escape_rdn_value("a+b") == "a\\+b"
    assert ldap_dn.escape_rdn_value('a"b') == 'a\\"b'
    assert ldap_dn.escape_rdn_value("a\\b") == "a\\\\b"
    assert ldap_dn.escape_rdn_value("a=b") == "a\\=b"


def test_escape_leading_hash_and_spaces():
    assert ldap_dn.escape_rdn_value("#x") == "\\#x"
    assert ldap_dn.escape_rdn_value(" x") == "\\ x"
    assert ldap_dn.escape_rdn_value("x ") == "x\\ "
    assert ldap_dn.escape_rdn_value("") == ""


def test_escape_injection_attempt():
    # A uid trying to reparent under ou=admins must be neutralised.
    esc = ldap_dn.escape_rdn_value("foo,ou=admins")
    assert esc == "foo\\,ou\\=admins"
    dn = ldap_dn.user_dn(BASE, "foo,ou=admins")
    assert dn == "uid=foo\\,ou\\=admins,ou=users," + BASE


# ── slug canonicalisation (case-insensitive tenant identity) ────────────────

def test_slug_canonical_is_lowercase():
    assert ldap_dn.canonical_slug("LRB") == "lrb"
    assert ldap_dn.canonical_slug("Lrb") == "lrb"
    assert ldap_dn.canonical_slug("lrb") == "lrb"
    assert ldap_dn.canonical_slug("  ACME  ") == "acme"


def test_case_insensitive_tenant_resolves_to_one_ou():
    dns = {ldap_dn.tenant_ou_dn(BASE, s) for s in ("LRB", "lrb", "Lrb", "lRb")}
    assert dns == {"ou=lrb," + BASE}  # exactly one entry, not four
    # users/groups containers + user/group DNs also collapse to one case.
    assert (ldap_dn.user_dn(BASE, "alice", "LRB")
            == ldap_dn.user_dn(BASE, "alice", "lrb")
            == "uid=alice,ou=users,ou=lrb," + BASE)


def test_slug_validation_rejects_bad_input():
    for bad in ("", "  ", None, "a,b", "a b", "-lead", "a/b", "a=b"):
        with pytest.raises(ValueError):
            ldap_dn.canonical_slug(bad)


def test_slug_allows_dot_dash_underscore():
    assert ldap_dn.canonical_slug("a.b-c_d") == "a.b-c_d"
    assert ldap_dn.canonical_slug("Site1") == "site1"


# ── DN layout ───────────────────────────────────────────────────────────────

def test_tenant_scoped_layout():
    assert ldap_dn.tenant_ou_dn(BASE, "acme") == "ou=acme," + BASE
    assert ldap_dn.users_container_dn(BASE, "acme") == "ou=users,ou=acme," + BASE
    assert ldap_dn.groups_container_dn(BASE, "acme") == "ou=groups,ou=acme," + BASE
    assert ldap_dn.user_dn(BASE, "bob", "acme") == "uid=bob,ou=users,ou=acme," + BASE
    assert ldap_dn.group_dn(BASE, "netadmins", "acme") == "cn=netadmins,ou=groups,ou=acme," + BASE


def test_base_level_layout_no_slug():
    assert ldap_dn.users_container_dn(BASE) == "ou=users," + BASE
    assert ldap_dn.groups_container_dn(BASE) == "ou=groups," + BASE
    assert ldap_dn.user_dn(BASE, "bob") == "uid=bob,ou=users," + BASE
    assert ldap_dn.group_dn(BASE, "admins") == "cn=admins,ou=groups," + BASE


def test_missing_base_or_id_raises():
    with pytest.raises(ValueError):
        ldap_dn.user_dn("", "bob", "acme")
    with pytest.raises(ValueError):
        ldap_dn.user_dn(BASE, "", "acme")
    with pytest.raises(ValueError):
        ldap_dn.group_dn(BASE, "", "acme")
