"""Tests for the base-structure LDIF templater (src/ldif_template.py)."""
import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "ldif_template", os.path.join(os.path.dirname(__file__), "..", "src", "ldif_template.py"))
ldif_template = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ldif_template)

import pytest

TEMPLATE = """dn: ou=users,@@BASE_DN@@
ou: users
objectClass: organizationalUnit

dn: ou=groups,@@BASE_DN@@
ou: groups
objectClass: organizationalUnit
"""


def test_substitutes_all_placeholders():
    out = ldif_template.render_base_structure(TEMPLATE, "dc=lm,dc=local")
    assert "@@BASE_DN@@" not in out
    assert "dn: ou=users,dc=lm,dc=local" in out
    assert "dn: ou=groups,dc=lm,dc=local" in out
    # exactly the two occurrences replaced
    assert out.count("dc=lm,dc=local") == 2


def test_empty_base_dn_raises():
    with pytest.raises(ValueError):
        ldif_template.render_base_structure(TEMPLATE, "")
    with pytest.raises(ValueError):
        ldif_template.render_base_structure(TEMPLATE, "   ")


def test_no_placeholder_is_passthrough():
    assert ldif_template.render_base_structure("no placeholder here", "dc=x") == "no placeholder here"


def test_matches_shipped_template_file():
    # The shipped base_structure.ldif must carry the placeholder (not a literal
    # example DN) so the installer can template it.
    path = os.path.join(os.path.dirname(__file__), "..", "base_structure.ldif")
    with open(path, "r", encoding="utf-8") as fh:
        shipped = fh.read()
    assert ldif_template.BASE_DN_PLACEHOLDER in shipped
    rendered = ldif_template.render_base_structure(shipped, "dc=lm,dc=local")
    assert ldif_template.BASE_DN_PLACEHOLDER not in rendered


def _acl_rules(base_dn):
    return [l.split(" ", 1)[1] for l in ldif_template.render_acl_ldif(base_dn).splitlines()
            if l.startswith("olcAccess: ")]


def test_acls_close_anonymous_read_and_password_self_write():
    rules = _acl_rules("dc=lab,dc=example")
    assert rules[0] == "{0}to attrs=userPassword by anonymous auth by * none"
    assert rules[-1] == "{2}to * by * none"
    assert not any("by * read" in r or "self write" in r or "anonymous read" in r for r in rules)


def test_acls_scope_reads_to_the_entry_top_level_ou():
    import re as _re
    rule = _acl_rules("dc=lab,dc=example")[1]
    what = _re.search(r'dn\.regex="([^"]+)"', rule).group(1)
    by = _re.search(r'dn\.subtree,expand="([^"]+)"', rule).group(1)
    # Every tenant entry (nested OUs included) maps to its own tenant OU.
    for dn, tenant in (("uid=a,ou=users,ou=t1,dc=lab,dc=example", "t1"),
                       ("uid=a,ou=sub,ou=users,ou=t.2,dc=lab,dc=example", "t.2"),
                       ("cn=g,ou=groups,ou=t1,dc=lab,dc=example", "t1"),
                       ("ou=t1,dc=lab,dc=example", "t1")):
        m = _re.fullmatch(what, dn)
        assert m and by.replace("$2", m.group(2)) == f"ou={tenant},dc=lab,dc=example"
    # Entries outside any top-level OU, or outside the base, aren't covered.
    for dn in ("cn=admin,dc=lab,dc=example", "dc=lab,dc=example", "ou=t1,dc=other,dc=example"):
        assert not _re.fullmatch(what, dn)


def test_acl_base_dn_is_normalised_and_validated():
    assert 'ou=$2,dc=lab,dc=ex-1"' in ldif_template.render_acl_ldif("DC=Lab , dc=Ex-1")
    for bad in ("", "o=Acme Inc", "dc=a.b", 'dc=x"y', "dc=x$"):
        with pytest.raises(ValueError):
            ldif_template.render_acl_ldif(bad)
