"""Pure DN-construction helpers for tenant-scoped LDAP entries.

Kept dependency-free (no ``python-ldap``) so the DN math + RFC-4514 escaping is
unit-testable in the dev environment (where ``python-ldap`` isn't installed).
``ldap_manager`` uses these to build tenant-scoped DNs; the escaping mirrors
``ldap.dn.escape_dn_chars`` so a hostile ``uid``/``slug`` can't reparent an
entry (DN injection — the spoke binds as admin, so this is security-critical).

Layout built here (``ou=users``/``ou=groups`` are the canonical containers,
matching ``base_structure.ldif`` and ``LDAP_PROVISION_TENANT_OU``):

    <base>
      ou=users                       ← base level (no slug)
      ou=groups
      ou=<slug>                      ← a tenant OU
        ou=users
        ou=groups
"""
from __future__ import annotations

import re
from typing import Optional

# A tenant slug is an operator-chosen short token (used as an OU RDN). Escaping
# already prevents DN injection, but we additionally constrain the shape so a
# slug can't smuggle DN metacharacters or whitespace — a slug is an identifier,
# not free text. Must start alphanumeric; then alphanumerics / dot / dash /
# underscore. This is validated, not silently mangled, so a bad slug surfaces.
_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# RFC-4514 special characters that must be backslash-escaped inside an RDN value.
# Superset of the strict RFC set (also escapes ``=``) to match python-ldap's
# ``escape_dn_chars`` behaviour so the two escapers never disagree.
_RDN_SPECIALS = set('"+,;<>=\\')


def escape_rdn_value(value: Optional[str]) -> str:
    """Escape a value for safe use as a DN RDN component (RFC 4514).

    Mirrors ``ldap.dn.escape_dn_chars``: backslash-escapes the special set,
    a leading ``#`` or space, a trailing space, and NUL. Prevents DN injection
    (e.g. a ``uid`` of ``foo,ou=admins`` reparenting the entry)."""
    s = "" if value is None else str(value)
    n = len(s)
    out = []
    for i, ch in enumerate(s):
        if ch == "\x00":
            out.append("\\00")
        elif ch in _RDN_SPECIALS:
            out.append("\\" + ch)
        elif ch == "#" and i == 0:
            out.append("\\#")
        elif ch == " " and (i == 0 or i == n - 1):
            out.append("\\ ")
        else:
            out.append(ch)
    return "".join(out)


def canonical_slug(tenant_slug: str) -> str:
    """Validate + canonicalise a tenant slug. Returns the CANONICAL form.

    The tenant/OU identity is CASE-INSENSITIVE and shared across systems (the
    LDAP OU, the LM tenant, and the NetBox tenant are the same thing — "LRB",
    "lrb", and "Lrb" are one tenant). LDAP's ``ou`` attribute already matches
    caseIgnoreMatch, but we make it explicit and deterministic here by choosing
    **lower-case as the canonical case**: every slug is folded to lower-case
    before it becomes an RDN, so exactly one OU entry exists per tenant
    regardless of the case the caller used.

    Defence-in-depth on top of escaping: a slug is an OU identifier, so it must
    match ``[A-Za-z0-9][A-Za-z0-9._-]*``. Empty/None/malformed slugs are a
    caller error, surfaced as ValueError (the manager maps it to an ERROR
    envelope) rather than producing a surprising DN."""
    s = (tenant_slug or "").strip()
    if not s or not _SLUG_RE.match(s):
        raise ValueError(
            f"invalid tenant_slug {tenant_slug!r}: must match "
            f"[A-Za-z0-9][A-Za-z0-9._-]*")
    return s.lower()


# Back-compat alias — ``validate_slug`` name kept for callers that only need the
# validation contract; it now also canonicalises (lower-cases).
validate_slug = canonical_slug


def _base(base_dn: str) -> str:
    b = (base_dn or "").strip()
    if not b:
        raise ValueError("base_dn is required")
    return b


def tenant_ou_dn(base_dn: str, tenant_slug: str) -> str:
    """``ou=<slug>,<base>`` — the tenant's top-level OU. The slug is
    canonicalised (lower-cased) so "LRB"/"lrb"/"Lrb" all resolve to one OU."""
    return f"ou={escape_rdn_value(canonical_slug(tenant_slug))},{_base(base_dn)}"


def users_container_dn(base_dn: str, tenant_slug: Optional[str] = None) -> str:
    """``ou=users`` container: under the tenant OU when ``tenant_slug`` is given,
    else directly under the base DN (back-compat base level)."""
    if tenant_slug:
        return f"ou=users,{tenant_ou_dn(base_dn, tenant_slug)}"
    return f"ou=users,{_base(base_dn)}"


def groups_container_dn(base_dn: str, tenant_slug: Optional[str] = None) -> str:
    """``ou=groups`` container (tenant-scoped or base level, as above)."""
    if tenant_slug:
        return f"ou=groups,{tenant_ou_dn(base_dn, tenant_slug)}"
    return f"ou=groups,{_base(base_dn)}"


def user_dn(base_dn: str, uid: str, tenant_slug: Optional[str] = None) -> str:
    """``uid=<uid>,ou=users,[ou=<slug>,]<base>``."""
    if not (uid or "").strip():
        raise ValueError("uid is required")
    return f"uid={escape_rdn_value(uid)},{users_container_dn(base_dn, tenant_slug)}"


def group_dn(base_dn: str, cn: str, tenant_slug: Optional[str] = None) -> str:
    """``cn=<cn>,ou=groups,[ou=<slug>,]<base>``."""
    if not (cn or "").strip():
        raise ValueError("group name (cn) is required")
    return f"cn={escape_rdn_value(cn)},{groups_container_dn(base_dn, tenant_slug)}"
