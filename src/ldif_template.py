"""Render the base-structure LDIF for a chosen base DN.

``base_structure.ldif`` ships with the ``@@BASE_DN@@`` placeholder so the ONE
canonical base DN (chosen at install by ``--base-dn`` / derived from the host
domain) is substituted everywhere consistently. Kept dependency-free + pure so
it is unit-testable; also runnable as a module so the installer can render the
LDIF without hand-rolling ``sed``::

    python3 -m src.ldif_template "dc=lm,dc=local" base_structure.ldif > /tmp/base.ldif
"""
from __future__ import annotations

import sys

BASE_DN_PLACEHOLDER = "@@BASE_DN@@"


def render_base_structure(template_text: str, base_dn: str) -> str:
    """Substitute the base-DN placeholder in an LDIF template.

    Raises ValueError on an empty base DN (a blank substitution would produce
    invalid, silently-broken DNs)."""
    b = (base_dn or "").strip()
    if not b:
        raise ValueError("base_dn is required")
    return (template_text or "").replace(BASE_DN_PLACEHOLDER, b)


def _main(argv) -> int:
    if len(argv) < 2:
        sys.stderr.write(
            "usage: python3 -m src.ldif_template <base_dn> [template_path]\n")
        return 2
    base_dn = argv[1]
    template_path = argv[2] if len(argv) > 2 else "base_structure.ldif"
    with open(template_path, "r", encoding="utf-8") as fh:
        template_text = fh.read()
    sys.stdout.write(render_base_structure(template_text, base_dn))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
