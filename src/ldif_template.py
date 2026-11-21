"""Render the base-structure LDIF for a chosen base DN.

``base_structure.ldif`` ships with the ``@@BASE_DN@@`` placeholder so the ONE
canonical base DN (chosen at install by ``--base-dn`` / derived from the host
domain) is substituted everywhere consistently. Kept dependency-free + pure so
it is unit-testable; also runnable as a module so the installer can render the
LDIF without hand-rolling ``sed``::

    python3 -m src.ldif_template "dc=lm,dc=local" base_structure.ldif > /tmp/base.ldif

It also renders the directory ACLs (``--acl``), see ``render_acl_ldif``.
"""
# Allows modern type hints to be written as plain annotations.
from __future__ import annotations

# re validates the base DN before it goes into an ACL regex.
import re
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


# The data database the installer provisions (it sets olcRootDN/olcRootPW there).
DATA_DB_DN = "olcDatabase={1}mdb,cn=config"

# A base DN the ACL regex can hold literally: attr=value RDNs of
# lower-case letters, digits and hyphens, so no character is a regex or
# slapd-quoting special.
_ACL_BASE_RE = re.compile(r"[a-z][a-z0-9-]*=[a-z0-9-]+(,[a-z][a-z0-9-]*=[a-z0-9-]+)*")


def render_acl_ldif(base_dn: str, db_dn: str = DATA_DB_DN) -> str:
    """LDIF that replaces the data database's olcAccess with tenant-scoped
    rules. Debian's default ("to * by * read", and "by self write" on
    userPassword) lets an anonymous client read every tenant, and lets a
    user replace a {SASL} password to skip Entra. The rules:

    0. userPassword: anonymous may use it to bind ("auth"); nobody,
       including the user, may read or write it. The spoke changes
       passwords as the rootDN, which ACLs don't restrict.
    1. An entry under a top-level OU (ou=<tenant>,<base>, and the legacy
       base-level ou=users / ou=groups) is readable only by a DN inside
       that same OU. ``dn.subtree,expand`` matches the expanded OU DN
       literally, so a slug can never widen it.
    2. Everything else: no access. The rootDN (the spoke, the hub's
       cluster setup and syncrepl all bind as it) is not limited by ACLs.

    The base DN is normalised the way slapd normalises DNs (lower case, no
    blanks around ',' or '='), since dn.regex matches the normalised DN.
    Raises ValueError for a base DN that cannot be put in the regex as is."""
    # Normalise like slapd, then refuse anything that isn't plain attr=value RDNs.
    base = re.sub(r"\s*([,=])\s*", r"\1", (base_dn or "").strip().lower())
    if not _ACL_BASE_RE.fullmatch(base):
        raise ValueError(f"base DN {base_dn!r} is not plain attr=value RDNs; cannot build ACLs")
    # One replace of the whole attribute, so a re-run converges.
    return (f"dn: {db_dn}\n"
            "changetype: modify\n"
            "replace: olcAccess\n"
            "olcAccess: {0}to attrs=userPassword by anonymous auth by * none\n"
            f'olcAccess: {{1}}to dn.regex="^(.+,)?ou=([^,]+),{base}$" '
            f'by dn.subtree,expand="ou=$2,{base}" read by * none\n'
            "olcAccess: {2}to * by * none\n")


def _main(argv) -> int:
    """CLI entrypoint: render the base-structure LDIF, or with ``--acl`` the
    ACL LDIF, to stdout."""
    # --acl <base_dn>: print the ACL LDIF; exit 1 on a base DN it can't use.
    if len(argv) == 3 and argv[1] == "--acl":
        try:
            sys.stdout.write(render_acl_ldif(argv[2]))
        except ValueError as e:
            sys.stderr.write(f"{e}\n")
            return 1
        return 0
    # The base DN argument is mandatory; print usage and exit 2 without it.
    if len(argv) < 2:
        sys.stderr.write(
            "usage: python3 -m src.ldif_template <base_dn> [template_path]\n"
            "       python3 -m src.ldif_template --acl <base_dn>\n")
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
