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
# Allows modern type hints to be written as plain annotations.
from __future__ import annotations

# re validates slug shape; Optional is a type hint.
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
    # Treat None as empty, and note the length to detect the last character.
    s = "" if value is None else str(value)
    n = len(s)
    # Build the escaped value one character at a time.
    out = []
    for i, ch in enumerate(s):
        # NUL is written as the hex escape \00.
        if ch == "\x00":
            out.append("\\00")
        # DN metacharacters get a leading backslash.
        elif ch in _RDN_SPECIALS:
            out.append("\\" + ch)
        # A leading "#" would otherwise mean "hex-encoded value".
        elif ch == "#" and i == 0:
            out.append("\\#")
        # Leading/trailing spaces would otherwise be trimmed by LDAP servers.
        elif ch == " " and (i == 0 or i == n - 1):
            out.append("\\ ")
        # Ordinary characters are copied unchanged.
        else:
            out.append(ch)
    # Join the pieces into the escaped string.
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
    # Trim whitespace, then reject empty or malformed slugs loudly.
    s = (tenant_slug or "").strip()
    if not s or not _SLUG_RE.match(s):
        raise ValueError(
            f"invalid tenant_slug {tenant_slug!r}: must match "
            f"[A-Za-z0-9][A-Za-z0-9._-]*")
    # Lower-case is the canonical form, so one tenant maps to exactly one OU.
    return s.lower()


# Back-compat alias — ``validate_slug`` name kept for callers that only need the
# validation contract; it now also canonicalises (lower-cases).
validate_slug = canonical_slug


def _base(base_dn: str) -> str:
    """Validate and return non-empty base DN string."""
    # Trim the base DN; an empty one cannot anchor any entry.
    b = (base_dn or "").strip()
    if not b:
        raise ValueError("base_dn is required")
    return b


def tenant_ou_dn(base_dn: str, tenant_slug: str) -> str:
    """``ou=<slug>,<base>`` — the tenant's top-level OU. The slug is
    canonicalised (lower-cased) so "LRB"/"lrb"/"Lrb" all resolve to one OU."""
    # Escape the canonical slug and append the base DN.
    return f"ou={escape_rdn_value(canonical_slug(tenant_slug))},{_base(base_dn)}"


def users_container_dn(base_dn: str, tenant_slug: Optional[str] = None) -> str:
    """``ou=users`` container: under the tenant OU when ``tenant_slug`` is given,
    else directly under the base DN (back-compat base level)."""
    # With a tenant, nest the container under the tenant OU.
    if tenant_slug:
        return f"ou=users,{tenant_ou_dn(base_dn, tenant_slug)}"
    # Otherwise use the base-level container.
    return f"ou=users,{_base(base_dn)}"


def groups_container_dn(base_dn: str, tenant_slug: Optional[str] = None) -> str:
    """``ou=groups`` container (tenant-scoped or base level, as above)."""
    # With a tenant, nest the container under the tenant OU.
    if tenant_slug:
        return f"ou=groups,{tenant_ou_dn(base_dn, tenant_slug)}"
    # Otherwise use the base-level container.
    return f"ou=groups,{_base(base_dn)}"


def user_dn(base_dn: str, uid: str, tenant_slug: Optional[str] = None,
            ou_path: Optional[list] = None) -> str:
    """``uid=<uid>,[ou=<OU>,...]ou=users,[ou=<slug>,]<base>``.

    ``ou_path`` places the user in an OU below ``ou=users`` (top down)."""
    # A blank uid would produce an invalid DN.
    if not (uid or "").strip():
        raise ValueError("uid is required")
    # Escape the uid and place it under the right users container or OU.
    parent = (ou_path_dn(base_dn, tenant_slug, ou_path) if ou_path
              else users_container_dn(base_dn, tenant_slug))
    return f"uid={escape_rdn_value(uid)},{parent}"


def clean_ou_name(name: Optional[str]) -> str:
    """Validate one OU (folder) name typed by a tenant admin.

    Escaping already makes any text safe inside a DN; this only rejects names
    that would confuse people: blank, padded, over 64 characters, or containing
    a "/" (the UI shows OU paths as ``Engineering/Lab``)."""
    # Trim and check the name; a bad name is a caller error.
    n = (name or "").strip()
    if not n or len(n) > 64 or "/" in n:
        raise ValueError(f"invalid OU name {name!r}: 1-64 characters, no '/'")
    return n


def ou_path_dn(base_dn: str, tenant_slug: str, path: Optional[list] = None) -> str:
    """DN of an OU inside a tenant's ``ou=users`` container.

    ``path`` lists OU names from the top down, so ``["Engineering", "Lab"]``
    gives ``ou=Lab,ou=Engineering,ou=users,ou=<slug>,<base>``. An empty path
    is the ``ou=users`` container itself."""
    # Start at the tenant's users container and add each OU on top of it.
    dn = users_container_dn(base_dn, tenant_slug)
    for name in path or []:
        dn = f"ou={escape_rdn_value(clean_ou_name(name))},{dn}"
    return dn


def parse_dn(dn: str) -> list:
    """Split a DN into ``[(attr, value), ...]`` with escapes removed.

    Handles both escape forms servers send back: ``\\,`` and the hex form
    ``\\2C``. Multi-valued RDNs (``a=1+b=2``) are not used in this directory
    and are returned as one value."""
    out = []
    for rdn in split_dn_raw(dn):
        attr, _, value = rdn.strip().partition("=")
        out.append((attr.strip().lower(), _unescape(value.strip())))
    return out


def _unescape(value: str) -> str:
    """Remove DN escaping (``\\,`` and hex ``\\2C``) from one RDN value."""
    # Collect bytes so multi-byte UTF-8 hex escapes decode correctly.
    raw, i = bytearray(), 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            pair = value[i + 1:i + 3]
            if len(pair) == 2 and all(c in "0123456789abcdefABCDEF" for c in pair):
                raw.append(int(pair, 16))
                i += 3
                continue
            raw.extend(value[i + 1].encode("utf-8"))
            i += 2
            continue
        raw.extend(ch.encode("utf-8"))
        i += 1
    return raw.decode("utf-8", "replace")


def ou_path_of(dn: str, container_dn: str) -> Optional[list]:
    """OU path of the entry ``dn`` relative to ``container_dn``.

    For a user ``uid=bob,ou=Lab,ou=Engineering,ou=users,...`` with the users
    container, returns ``["Engineering", "Lab"]`` (the OUs the user sits in).
    For an OU entry, the path includes the OU itself. Returns None when the
    entry is not under the container. Comparison is case-insensitive, like
    LDAP's own DN matching."""
    # Compare parsed RDNs so escaping differences do not matter.
    entry = parse_dn(dn)
    base = parse_dn(container_dn)
    if len(entry) <= len(base):
        return None
    tail = entry[len(entry) - len(base):]
    if [(a, v.lower()) for a, v in tail] != [(a, v.lower()) for a, v in base]:
        return None
    # The RDNs between the entry and the container are its OUs, bottom up.
    between = entry[:len(entry) - len(base)]
    names = [v for a, v in between if a == "ou"]
    # A user's own uid= RDN is not part of its path; an OU's own RDN is.
    return list(reversed(names))


def split_dn_raw(dn: str) -> list:
    """Split a DN on its unescaped commas, keeping each RDN's escaping as-is."""
    # Walk the DN, skipping the character after each backslash.
    parts, start, i = [], 0, 0
    while i < len(dn):
        if dn[i] == "\\":
            i += 2
            continue
        if dn[i] == ",":
            parts.append(dn[start:i])
            start = i + 1
        i += 1
    parts.append(dn[start:])
    return parts


def rebase_dn(dn: str, old_base: str, new_base: str) -> str:
    """Return ``dn`` with its ``old_base`` suffix replaced by ``new_base``.

    Used when an OU is renamed: every entry below it gets a new DN. The suffix
    is counted in RDNs, not characters, so it works however the server escaped
    or cased the DN it returned."""
    # Keep the RDNs above the old base and put them on the new base.
    raw = split_dn_raw(dn)
    keep = len(raw) - len(split_dn_raw(old_base))
    if keep < 0:
        raise ValueError(f"{dn!r} is not below {old_base!r}")
    return ",".join(raw[:keep] + [new_base])


def group_dn(base_dn: str, cn: str, tenant_slug: Optional[str] = None) -> str:
    """``cn=<cn>,ou=groups,[ou=<slug>,]<base>``."""
    # A blank group name would produce an invalid DN.
    if not (cn or "").strip():
        raise ValueError("group name (cn) is required")
    # Escape the name and place it under the right groups container.
    return f"cn={escape_rdn_value(cn)},{groups_container_dn(base_dn, tenant_slug)}"
