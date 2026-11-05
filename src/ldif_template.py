"""Render the base-structure LDIF for a chosen base DN.

``base_structure.ldif`` ships with the ``@@BASE_DN@@`` placeholder so the ONE
canonical base DN (chosen at install by ``--base-dn`` / derived from the host
domain) is substituted everywhere consistently. Kept dependency-free + pure so
it is unit-testable; also runnable as a module so the installer can render the
LDIF without hand-rolling ``sed``::

    python3 -m src.ldif_template "dc=lm,dc=local" base_structure.ldif > /tmp/base.ldif
"""
# Allows modern type hints to be written as plain annotations.
from __future__ import annotations

# sys provides argv, stdout and stderr for the CLI entry point.
import sys

# Marker in base_structure.ldif replaced with the real base DN.
BASE_DN_PLACEHOLDER = "@@BASE_DN@@"


def render_base_structure(template_text: str, base_dn: str) -> str:
    """Substitute the base-DN placeholder in an LDIF template.

    Raises ValueError on an empty base DN (a blank substitution would produce
    invalid, silently-broken DNs)."""
    # Trim the base DN; an empty one would produce broken DNs.
    b = (base_dn or "").strip()
    if not b:
        raise ValueError("base_dn is required")
    # Replace every placeholder occurrence with the base DN.
    return (template_text or "").replace(BASE_DN_PLACEHOLDER, b)


def _main(argv) -> int:
    """CLI entrypoint to render base structure LDIF template to stdout."""
    # The base DN argument is mandatory; print usage and exit 2 without it.
    if len(argv) < 2:
        sys.stderr.write(
            "usage: python3 -m src.ldif_template <base_dn> [template_path]\n")
        return 2
    # Base DN from the first argument; template path from the second (or the default).
    base_dn = argv[1]
    template_path = argv[2] if len(argv) > 2 else "base_structure.ldif"
    # Read the template text.
    with open(template_path, "r", encoding="utf-8") as fh:
        template_text = fh.read()
    # Write the rendered LDIF to stdout and exit successfully.
    sys.stdout.write(render_base_structure(template_text, base_dn))
    return 0


if __name__ == "__main__":
    # Run the CLI and use its return value as the process exit code.
    raise SystemExit(_main(sys.argv))
