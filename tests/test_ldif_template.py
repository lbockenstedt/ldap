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
