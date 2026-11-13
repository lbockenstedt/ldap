"""LDAP directory management for the LDAP spoke.

Wraps python-ldap with safe, tenant-aware helpers for organisational units,
users, groups, passwords and Entra-backed ({SASL}) accounts. Every public
method returns a status dictionary the spoke can relay to the hub.
"""
# python-ldap core API plus helpers for filter escaping, DN escaping and modlists.
import ldap
import ldap.filter
import ldap.dn
import ldap.modlist
# Type hints only.
from typing import Any, Dict, List, Optional
# base64/hashlib build {SSHA} password hashes; os supplies random salt.
import base64
import hashlib
# logging records LDAP errors.
import logging
import os
# secrets generates strong random passwords when none is supplied.
import secrets
import threading
# contextmanager turns _conn into a with-statement that always unbinds.
from contextlib import contextmanager

# Pure DN builders (dependency-free) — shared, tested tenant-scoped DN math.
# Package-relative import first; plain import when loaded outside the package.
try:
    from .ldap_dn import (canonical_slug, tenant_ou_dn, users_container_dn,
                          groups_container_dn, user_dn as build_user_dn,
                          group_dn as build_group_dn, clean_ou_name,
                          ou_path_dn, ou_path_of,
                          rebase_dn, split_dn_raw)
except ImportError:  # loaded outside the src package (tests / bare import)
    from ldap_dn import (canonical_slug, tenant_ou_dn, users_container_dn,
                         groups_container_dn, user_dn as build_user_dn,
                         group_dn as build_group_dn, clean_ou_name,
                         ou_path_dn, ou_path_of,
                         rebase_dn, split_dn_raw)

# One named logger for the LDAP manager.
logger = logging.getLogger("LdapManager")


def _add_entry(conn, dn: str, attrs: Dict[str, Any]) -> None:
    """``add_s`` with an attribute dict. python-ldap's ``add_s`` takes a list of
    ``(attr, values)`` tuples and rejects a dict with ``TypeError`` — so every
    add goes through ``ldap.modlist.addModlist``."""
    # Convert the dict into python-ldap's (attr, values) list and add the entry.
    conn.add_s(dn, ldap.modlist.addModlist(attrs))

# userPassword marker that routes a bind through Cyrus SASL → saslauthd → the
# Entra ROPC bridge (see src/entra_ropc_auth.py). An Entra-backed user's
# userPassword is ``{SASL}<upn>`` — it carries no local secret.
SASL_SCHEME = "{SASL}"

# Seconds to wait to connect to slapd, and for any one LDAP operation.
LDAP_CONNECT_TIMEOUT_S = 5
LDAP_OP_TIMEOUT_S = 15


class LdapBindError(Exception):
    """Raised by :meth:`LdapManager._bind` when the admin bind fails
    (``INVALID_CREDENTIALS`` / result 49). Carries an actionable message — the
    spoke's ``LDAP_ADMIN_PW`` doesn't match slapd's admin password — so callers
    and the spoke log surface the fix instead of the raw
    ``{'msgtype':97,'result':49,'desc':'Invalid credentials'}`` dict.

    Deliberately NOT an ``ldap.LDAPError`` subclass: the per-method
    ``except ldap.LDAPError`` blocks must NOT swallow a bind failure (they'd log
    the cryptic dict and return it); a bind error propagates past them to the
    spoke, which maps it to a clean ``INVALID_CREDENTIALS`` envelope. Operation
    errors (``add_s`` / ``modify_s`` / …) are still ``ldap.LDAPError`` and stay
    caught per-method as before."""


# Serialises the tenant-wide uid check with the add that follows it, so two
# creates in different OUs can't both pass the check (one spoke process per
# directory, so a process lock is enough).
_UID_LOCK = threading.Lock()


class PartialRollbackError(Exception):
    """A failed move/rename whose undo also failed: the directory is left
    partly changed, and the message lists what is still changed."""


class TenantNotProvisionedError(ValueError):
    """The tenant's ``ou=users`` container does not exist, so the tenant's
    directory was never provisioned. Kept apart from "user not found" and
    "OU not found" so a missing tenant is never reported as a missing user."""


def _not_provisioned_message(users_dn: str) -> str:
    """The one wording for a tenant whose ``ou=users`` is missing."""
    return f"this tenant's directory is not provisioned ({users_dn} is missing)"


def _error_reply(e: Exception) -> Dict[str, Any]:
    """ERROR envelope for a failed user command. A missing tenant also gets
    ``error: NOT_PROVISIONED``, the same code the OU commands return."""
    out = {"status": "ERROR", "message": str(e)}
    if isinstance(e, TenantNotProvisionedError):
        out["error"] = "NOT_PROVISIONED"
    return out


class LdapManager:
    """Synchronous LDAP CRUD wrapper over ``python-ldap``.

    Bound once at construction with admin creds + base DN + server URL and reused
    across commands. Read/list operations and the health check use the leak-free
    :meth:`_conn` context manager (bind + always-unbind); write operations
    (create/update/delete, group membership, set-password) still call
    :meth:`_get_connection`, which binds but does not explicitly unbind. All
    public methods return ``{"status": ..., ...}`` dicts ready for the spoke to
    relay to the hub. DN components are escaped via :meth:`_escape_rdn` and
    filter values are RFC-4515 escaped in :meth:`search` to prevent DN/filter
    injection (the spoke binds as admin, so this is security-critical)."""

    def __init__(self, admin_dn: str, admin_pw: str, base_dn: str, server_url: str = "ldap://localhost:389"):
        """Initialize LDAP directory manager with administrative bind credentials and base DN."""
        # Remember the admin credentials, search base and server URL for later binds.
        self.admin_dn = admin_dn
        self.admin_pw = admin_pw
        self.base_dn = base_dn
        self.server = server_url

    def _open(self):
        """New client handle with timeouts, so a slow or unreachable server fails
        fast instead of holding one of the spoke's few command slots for minutes."""
        conn = ldap.initialize(self.server)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, LDAP_CONNECT_TIMEOUT_S)
        conn.set_option(ldap.OPT_TIMEOUT, LDAP_OP_TIMEOUT_S)
        return conn

    def _get_connection(self):
        """Create and bind a new LDAP client connection using admin credentials."""
        # Open a client handle to the server and bind as admin.
        conn = self._open()
        self._bind(conn)
        # The caller owns the connection from here on.
        return conn

    def _bind(self, conn) -> None:
        """Bind as the admin DN. On ``INVALID_CREDENTIALS`` (result 49) raise
        :class:`LdapBindError` with an actionable message — the spoke's
        ``LDAP_ADMIN_PW`` doesn't match slapd's admin password — instead of
        letting the raw ``{'result':49,'desc':'Invalid credentials'}`` dict
        propagate. Callers' ``except ldap.LDAPError`` blocks don't catch this
        (it's not an ``LDAPError``), so a bind failure surfaces as a clean
        ``INVALID_CREDENTIALS`` envelope at the spoke, not a cryptic per-method
        log line or a control-plane traceback."""
        # Simple bind with the admin DN and password.
        try:
            conn.simple_bind_s(self.admin_dn, self.admin_pw)
        # Wrong password: raise an actionable error instead of the raw LDAP dict.
        except ldap.INVALID_CREDENTIALS as exc:
            raise LdapBindError(
                "LDAP bind failed: invalid credentials — the LDAP_ADMIN_PW in "
                "this spoke's config does not match slapd's admin password. "
                "Re-push the correct password via Setup → LDAP (UPDATE_CONFIG)."
            ) from exc

    @contextmanager
    def _conn(self):
        """Bound connection that is ALWAYS unbound afterwards — fixes the socket/FD
        leak from _get_connection (bound per call, never closed), which exhausted
        slapd's conn limit on a long-running spoke."""
        # Open a client handle; bind inside the try so it is unbound even if bind fails.
        conn = self._open()
        try:
            self._bind(conn)
            # Hand the bound connection to the with-block.
            yield conn
        # Always unbind to release the socket, ignoring errors during cleanup.
        finally:
            try:
                conn.unbind_s()
            except Exception:  # noqa: BLE001
                pass

    def check_connection(self) -> bool:
        """Health check that binds + unbinds (no leak). Raises on failure."""
        # Binding successfully is the health check; the context manager unbinds.
        with self._conn():
            return True

    @staticmethod
    def _escape_rdn(value: str) -> str:
        """Escape a value for safe use as a DN RDN component. Prevents DN
        injection — a name containing ``, + = \\ <`` (or a leading space) could
        otherwise reparent the entry (e.g. uid ``foo,ou=admins`` → placed under
        ``ou=admins``). The spoke binds as admin, so this is security-critical."""
        # Delegate to python-ldap's RFC 4514 escaper (None treated as empty).
        return ldap.dn.escape_dn_chars(value or "")

    @staticmethod
    def _ssha(password: str) -> bytes:
        """{SSHA} hash for ``userPassword``. slapd does NOT hash a plain add/modify
        of userPassword (only the Password-Modify ext-op does), so hash before
        storing to avoid cleartext passwords at rest."""
        # Four random salt bytes, SHA-1 over password+salt, then base64(digest+salt).
        salt = os.urandom(4)
        digest = hashlib.sha1(password.encode('utf-8') + salt).digest()
        return b'{SSHA}' + base64.b64encode(digest + salt)

    def list_ous(self) -> List[Dict[str, Any]]:
        """List all Organizational Unit entries located beneath the base DN."""
        # Search the whole subtree for OUs, then release the connection.
        with self._conn() as conn:
            results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(objectClass=organizationalUnit)", ['ou', 'description'])
        # Convert each result into {name, dn}.
        ous = []
        for dn, attrs in results:
            # Skip referral entries, which have no DN.
            if dn:
                # Use the ou attribute, or the first RDN value when the attribute is missing.
                ou_name = attrs.get('ou', [b''])[0].decode('utf-8') if attrs.get('ou') else dn.split(',')[0].split('=')[-1]
                ous.append({"name": ou_name, "dn": dn})
        # Return the OU list.
        return ous

    def create_ou(self, ou_name: str, parent_dn: str = None) -> Dict[str, Any]:
        """Create a new Organizational Unit entry with escaped RDN under the parent DN."""
        # Bind, then build the OU's DN (escaped name) under the parent or the base DN.
        conn = self._get_connection()
        dn = f"ou={self._escape_rdn(ou_name)},{parent_dn if parent_dn else self.base_dn}"
        # Minimal attributes for an organizationalUnit entry.
        attrs = {
            'objectClass': [b'organizationalUnit'],
            'ou': [ou_name.encode('utf-8')]
        }
        # Create the entry; LDAP errors are logged and returned as an ERROR result.
        try:
            _add_entry(conn, dn, attrs)
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            logger.error(f"Error creating OU {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def list_users(self) -> List[Dict[str, Any]]:
        """Search and return all person objects under the directory base DN."""
        # Search the whole subtree for person entries, then release the connection.
        with self._conn() as conn:
            results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(objectClass=person)", ['uid', 'cn', 'sn', 'givenName', 'mail'])
        # Convert each result into a user dictionary.
        users = []
        for dn, attrs in results:
            # Skip referral entries, which have no DN.
            if dn:
                # Decode each attribute, with sensible fallbacks when one is missing.
                uid = attrs.get('uid', [b''])[0].decode('utf-8') if attrs.get('uid') else dn.split(',')[0].split('=')[-1]
                cn = attrs.get('cn', [b''])[0].decode('utf-8') if attrs.get('cn') else ''
                sn = attrs.get('sn', [b''])[0].decode('utf-8') if attrs.get('sn') else ''
                given = attrs.get('givenName', [b''])[0].decode('utf-8') if attrs.get('givenName') else cn.split(' ')[0] if cn else ''
                mail = attrs.get('mail', [b''])[0].decode('utf-8') if attrs.get('mail') else ''
                # Add the normalised user.
                users.append({"username": uid, "cn": cn, "first_name": given, "last_name": sn, "email": mail, "dn": dn})
        # Return the user list.
        return users

    def create_user(self, username: str, first_name: str, last_name: str, email: str, ou_dn: str, password: Optional[str] = None) -> Dict[str, Any]:
        """Create an inetOrgPerson user entry with {SSHA}-hashed password."""
        # Bind, then build the user's DN (escaped uid) inside the given OU.
        conn = self._get_connection()
        dn = f"uid={self._escape_rdn(username)},{ou_dn}"
        # Use a caller-provided password, or generate a strong random one (never a hardcoded default).
        user_password = password or secrets.token_urlsafe(16)
        # inetOrgPerson attributes; the password is stored as an {SSHA} hash.
        attrs = {
            'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
            'cn': [f"{first_name} {last_name}".encode('utf-8')],
            'sn': [last_name.encode('utf-8')],
            'uid': [username.encode('utf-8')],
            'mail': [email.encode('utf-8')],
            'userPassword': [self._ssha(user_password)]  # {SSHA}, not cleartext
        }
        # Create the entry; LDAP errors are logged and returned as an ERROR result.
        try:
            _add_entry(conn, dn, attrs)
            # Return the generated/provided password so the operator can deliver it securely.
            return {"status": "SUCCESS", "dn": dn, "password": user_password}
        except ldap.LDAPError as e:
            logger.error(f"Error creating user {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def list_groups(self) -> List[Dict[str, Any]]:
        """List all groupOfNames and posixGroup entries with their members."""
        # Search the whole subtree for both group types, then release the connection.
        with self._conn() as conn:
            results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(|(objectClass=groupOfNames)(objectClass=posixGroup))", ['cn', 'member', 'memberUid', 'description'])
        # Convert each result into a group dictionary with its members.
        groups = []
        for dn, attrs in results:
            # Skip referral entries, which have no DN.
            if dn:
                # Group name and member DNs.
                cn = attrs.get('cn', [b''])[0].decode('utf-8') if attrs.get('cn') else ''
                members = [m.decode('utf-8') for m in attrs.get('member', [])]
                # Add the normalised group.
                groups.append({
                    "name": cn,
                    "dn": dn,
                    "member_count": len(members),
                    "members": members,
                })
        # Return the group list.
        return groups

    def create_group(self, group_name: str, ou_dn: str) -> Dict[str, Any]:
        """Create a new groupOfNames entry seeded with a base DN member."""
        # Bind, then build the group's DN (escaped name) inside the given OU.
        conn = self._get_connection()
        dn = f"cn={self._escape_rdn(group_name)},{ou_dn}"
        # groupOfNames attributes, seeded with a placeholder member.
        attrs = {
            'objectClass': [b'groupOfNames'],
            'cn': [group_name.encode('utf-8')],
            'member': [self.base_dn.encode('utf-8')] # groupOfNames requires at least one member
        }
        # Create the entry; LDAP errors are logged and returned as an ERROR result.
        try:
            _add_entry(conn, dn, attrs)
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            logger.error(f"Error creating group {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def add_user_to_group(self, user_dn: str, group_dn: str) -> Dict[str, Any]:
        """Add a member DN to the specified group entry."""
        # Bind, then add the user's DN to the group's member attribute.
        conn = self._get_connection()
        try:
            conn.modify_s(group_dn, [(ldap.MOD_ADD, 'member', [user_dn.encode('utf-8')])])
            return {"status": "SUCCESS"}
        # LDAP error (e.g. already a member): log and report it.
        except ldap.LDAPError as e:
            logger.error(f"Error adding user {user_dn} to group {group_dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def remove_user_from_group(self, user_dn: str, group_dn: str) -> Dict[str, Any]:
        """Remove a member DN from the specified group entry."""
        # Bind, then delete the user's DN from the group's member attribute.
        conn = self._get_connection()
        try:
            conn.modify_s(group_dn, [(ldap.MOD_DELETE, 'member', [user_dn.encode('utf-8')])])
            return {"status": "SUCCESS"}
        # LDAP error (e.g. not a member): log and report it.
        except ldap.LDAPError as e:
            logger.error(f"Error removing user {user_dn} from group {group_dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def set_password(self, user_dn: str, new_password: str) -> Dict[str, Any]:
        """Set or update password for user DN using Password-Modify or attribute replacement."""
        # Bind, then try the Password-Modify extended operation (the server hashes it).
        conn = self._get_connection()
        try:
            conn.passwd_s(user_dn, None, new_password.encode('utf-8'))
            return {"status": "SUCCESS"}
        except ldap.LDAPError:
            # Fallback: use modify with userPassword attribute
            try:
                conn.modify_s(user_dn, [(ldap.MOD_REPLACE, 'userPassword', [self._ssha(new_password)])])
                return {"status": "SUCCESS"}
            # Both methods failed: log and report the error.
            except ldap.LDAPError as e:
                logger.error(f"Error setting password for {user_dn}: {e}")
                return {"status": "ERROR", "message": str(e)}

    def delete_entity(self, dn: str) -> Dict[str, Any]:
        """Delete an LDAP entry by distinguished name."""
        # Bind, then delete the entry.
        conn = self._get_connection()
        try:
            conn.delete_s(dn)
            return {"status": "SUCCESS"}
        # LDAP error (e.g. entry has children): log and report it.
        except ldap.LDAPError as e:
            logger.error(f"Error deleting entity {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def _rename(self, conn, dn: str, new_rdn: str) -> None:
        """Rename an entry's RDN (modrdn). The old RDN value is deleted."""
        # Rename in place and drop the old RDN value from the entry.
        conn.rename_s(dn, new_rdn, delold=1)

    def migrate_tenant(self, source_base_dn: str, target_base_dn: str,
                       purge_source: bool = False) -> Dict[str, Any]:
        """Re-home every direct child of ``source_base_dn`` under
        ``target_base_dn`` (LDAP moddn with newsuperior — each child's own
        subtree moves with it). Used by cross-tenant migration when a tenant's
        ldap_base_dn changes. Optionally delete the now-empty source container.
        No-op when source == target or the source has no children. Returns the
        moved DNs; any per-entry error keeps the source (no purge)."""
        # Normalise both DNs; both are required.
        source_base_dn = (source_base_dn or "").strip()
        target_base_dn = (target_base_dn or "").strip()
        if not source_base_dn or not target_base_dn:
            return {"status": "ERROR", "message": "source and target base DN are required"}
        # Nothing to do when source and target are the same (case-insensitive).
        if source_base_dn.lower() == target_base_dn.lower():
            return {"status": "SUCCESS", "moved": [], "count": 0,
                    "message": "source and target base DN are the same"}
        # Track the DNs that moved and per-entry failures.
        moved: List[str] = []
        errors: Dict[str, str] = {}
        # One connection for the whole migration; it is always unbound.
        try:
            with self._conn() as conn:
                try:
                    # Find the source's direct children; a missing source means nothing to migrate.
                    children = conn.search_s(source_base_dn, ldap.SCOPE_ONELEVEL,
                                             "(objectClass=*)", ['dn'])
                except ldap.NO_SUCH_OBJECT:
                    return {"status": "SUCCESS", "moved": [], "count": 0,
                            "message": f"source '{source_base_dn}' not found — nothing to migrate"}
                # Move each child (and its subtree) under the target, keeping its RDN.
                for dn, _attrs in children:
                    rdn = dn.split(",", 1)[0]
                    try:
                        # newsuperior=target_base_dn moves the entry (and its
                        # subtree) under the target; delold=1 drops the old RDN val.
                        conn.rename_s(dn, rdn, target_base_dn, 1)
                        moved.append(dn)
                    except ldap.LDAPError as e:
                        # Record the failure and continue with the other children.
                        errors[dn] = str(e)
                # Delete the empty source container only when every move succeeded.
                if purge_source and not errors:
                    try:
                        conn.delete_s(source_base_dn)
                    except ldap.LDAPError as e:
                        # Record the failure; the source is kept.
                        errors["delete_source"] = str(e)
        except Exception as e:  # noqa: BLE001
            # Connection or bind failure: report it.
            return {"status": "ERROR", "message": str(e)}
        # PARTIAL when any entry failed, with a human-readable summary.
        status = "SUCCESS" if not errors else "PARTIAL"
        return {"status": status, "moved": moved, "count": len(moved), "errors": errors,
                "message": (f"moved {len(moved)} entry(ies) to '{target_base_dn}'"
                            + (f", {len(errors)} error(s)" if errors else ""))}

    # ── Tenant-scoped operations (TENANT == OU, 1:1) ───────────────────────
    # A tenant's entries live under ou=<slug>,<base> with child ou=users /
    # ou=groups. The slug is canonical-lower-cased (ldap_dn.canonical_slug) so
    # the tenant identity is CASE-INSENSITIVE and shared across LM/NetBox/LDAP
    # ("LRB" == "lrb"). All DN construction goes through the tested pure helpers.

    def _ensure_entry(self, conn, dn: str, attrs: Dict[str, Any]) -> None:
        """Add ``dn`` if absent; treat ALREADY_EXISTS as success (idempotent)."""
        # Try to add the entry.
        try:
            _add_entry(conn, dn, attrs)
        except ldap.ALREADY_EXISTS:
            # Already there: nothing to do.
            pass

    def _find_tenant_ou(self, conn, slug: str) -> Optional[str]:
        """Return the DN of an existing tenant OU for ``slug`` (case-insensitive),
        or None. ``ou`` uses caseIgnoreMatch, so a filter on the canonical slug
        matches an OU stored in ANY case ("LRB" finds "lrb")."""
        # Escape the slug for the filter, then search one level below the base for the OU.
        safe = ldap.filter.escape_filter_chars(slug)
        try:
            res = conn.search_s(self.base_dn, ldap.SCOPE_ONELEVEL,
                                f"(&(objectClass=organizationalUnit)(ou={safe}))", ['ou'])
        except ldap.NO_SUCH_OBJECT:
            # Base DN missing: no tenant OU.
            return None
        # Return the first real DN found, or None.
        for dn, _attrs in res:
            if dn:
                return dn
        return None

    def provision_tenant_ou(self, tenant_slug: str) -> Dict[str, Any]:
        """Idempotently create ``ou=<slug>,<base>`` + child ``ou=users`` /
        ``ou=groups``. Case-insensitive: if an OU already exists for this tenant
        in ANY case, reuse it (never create a second). Returns the OU DN."""
        # Normalise the tenant name to its canonical slug; reject invalid names.
        try:
            slug = canonical_slug(tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        # Reuse an existing OU in any case, otherwise create one with the canonical slug.
        try:
            with self._conn() as conn:
                existing = self._find_tenant_ou(conn, slug)
                ou_dn = existing or tenant_ou_dn(self.base_dn, slug)
                if not existing:
                    self._ensure_entry(conn, ou_dn, {
                        'objectClass': [b'organizationalUnit'],
                        'ou': [slug.encode('utf-8')],
                    })
                # Child containers (idempotent whether the OU is new or reused).
                for child in (users_container_dn(self.base_dn, slug),
                              groups_container_dn(self.base_dn, slug)):
                    child_ou = child.split(',', 1)[0].split('=', 1)[1]
                    self._ensure_entry(conn, child, {
                        'objectClass': [b'organizationalUnit'],
                        'ou': [child_ou.encode('utf-8')],
                    })
            return {"status": "SUCCESS", "dn": ou_dn}
        # LDAP error: log and report it.
        except ldap.LDAPError as e:
            logger.error(f"Error provisioning tenant OU '{tenant_slug}': {e}")
            return {"status": "ERROR", "message": str(e)}

    def _find_user_dn(self, conn, uid: str, tenant_slug: Optional[str]) -> Optional[str]:
        """Find a user's DN by ``uid`` anywhere under the tenant's ``ou=users``.

        Users can sit in any OU below ``ou=users``, so their DN can't be built
        from the uid alone. A uid is unique within a tenant (create enforces
        it); if two entries ever share one, raise rather than act on the wrong
        user. Returns None when no user has this uid; raises
        :class:`TenantNotProvisionedError` when the container itself is missing."""
        # A blank uid can never match.
        if not (uid or "").strip():
            raise ValueError("uid is required")
        # Search the whole users container for this uid.
        base = users_container_dn(self.base_dn, tenant_slug)
        safe = ldap.filter.escape_filter_chars(uid)
        try:
            res = conn.search_s(base, ldap.SCOPE_SUBTREE,
                                f"(&(objectClass=person)(uid={safe}))", ['uid'])
        except ldap.NO_SUCH_OBJECT:
            raise TenantNotProvisionedError(_not_provisioned_message(base))
        dns = [dn for dn, _a in res if dn]
        if len(dns) > 1:
            raise ValueError(f"uid {uid!r} is not unique in this tenant")
        return dns[0] if dns else None

    def _require_user_dn(self, conn, uid: str, tenant_slug: Optional[str]) -> str:
        """Like :meth:`_find_user_dn` but a missing user is an error."""
        dn = self._find_user_dn(conn, uid, tenant_slug)
        if not dn:
            raise ValueError(f"user not found: {uid}")
        return dn

    def _missing_ou_error(self, conn, tenant_slug: Optional[str], message: str) -> Dict[str, Any]:
        """Error reply for an OU command that hit NO_SUCH_OBJECT.

        That error can mean the tenant's ``ou=users`` is gone (never
        provisioned, or removed meanwhile) or only the named OU is missing.
        Probe the container on the same connection so the two are reported
        differently: NOT_PROVISIONED (as ``list_ous_scoped`` does) or
        ``message``. A failed probe raises LDAPError to the caller."""
        base = users_container_dn(self.base_dn, tenant_slug)
        try:
            conn.search_s(base, ldap.SCOPE_BASE, "(objectClass=*)", ['ou'])
        except ldap.NO_SUCH_OBJECT:
            return {"status": "ERROR", "error": "NOT_PROVISIONED",
                    "message": _not_provisioned_message(base)}
        return {"status": "ERROR", "message": message}

    def _rewrite_memberships(self, conn, tenant_slug: Optional[str],
                             moved: Dict[str, str], done: Optional[list] = None) -> int:
        """Point group ``member`` values at users' new DNs after a move/rename.

        ``moved`` maps old DN → new DN. groupOfNames stores members as DNs, so
        moving a user (or renaming the OU it sits in) leaves its groups pointing
        at a DN that no longer exists. slapd's refint overlay would fix this,
        but the spoke may manage a server it can't reconfigure, so the spoke
        does it: one search of the tenant's groups, then one modify per group
        that actually lists a moved user. Returns the number of groups changed;
        each applied change is appended to ``done`` so a caller can undo it."""
        # Nothing moved: nothing to rewrite.
        if not moved:
            return 0
        lower = {o.lower(): n for o, n in moved.items()}
        # Read every group in the tenant with its members.
        try:
            groups = conn.search_s(groups_container_dn(self.base_dn, tenant_slug),
                                   ldap.SCOPE_SUBTREE, "(objectClass=groupOfNames)",
                                   ['member'])
        # No groups container means the tenant has no groups, so no group can
        # list the moved users: 0 is the true count, not a failed read (any
        # other error propagates to the caller's rollback).
        except ldap.NO_SUCH_OBJECT:
            return 0
        changed = 0
        for gdn, attrs in groups:
            if not gdn:
                continue
            # Swap each moved member for its new DN; skip groups with none.
            old_vals, new_vals = [], []
            for raw in attrs.get('member', []):
                val = raw.decode('utf-8', 'replace')
                if val.lower() in lower:
                    old_vals.append(raw)
                    new_vals.append(lower[val.lower()].encode('utf-8'))
            if old_vals:
                # Add first, then delete, so a group is never left with no member.
                conn.modify_s(gdn, [(ldap.MOD_ADD, 'member', new_vals),
                                    (ldap.MOD_DELETE, 'member', old_vals)])
                changed += 1
                if done is not None:
                    done.append((gdn, old_vals, new_vals))
        return changed

    def create_user_scoped(self, uid: str, attrs: Optional[Dict[str, Any]] = None,
                           tenant_slug: Optional[str] = None,
                           auth_mode: str = "local", upn: Optional[str] = None,
                           password: Optional[str] = None,
                           ou_path: Optional[list] = None) -> Dict[str, Any]:
        """Create a user under a tenant's ``ou=users`` (or base level if no slug).

        ``ou_path`` places the user in an existing OU below ``ou=users`` (for
        example ``["Engineering"]``); empty means ``ou=users`` itself. The uid
        must be unique across the whole tenant, whatever OU it is in.

        ``auth_mode="entra"`` → ``userPassword: {SASL}<upn>`` (no local secret;
        binds are validated against Entra via the ROPC bridge); ``"local"`` →
        ``{SSHA}`` of ``password`` (generated if omitted, returned once)."""
        # Build the user's DN inside the chosen OU; reject invalid input.
        attrs = attrs or {}
        try:
            dn = build_user_dn(self.base_dn, uid, tenant_slug, ou_path)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        # cn and sn are required by inetOrgPerson; fall back to mail or uid.
        cn = attrs.get('cn') or attrs.get('mail') or uid
        sn = attrs.get('sn') or attrs.get('cn') or uid
        # Required inetOrgPerson attributes.
        entry: Dict[str, Any] = {
            'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
            'cn': [str(cn).encode('utf-8')],
            'sn': [str(sn).encode('utf-8')],
            'uid': [uid.encode('utf-8')],
        }
        # Copy the optional attributes that were supplied.
        for opt in ('givenName', 'mail', 'displayName', 'telephoneNumber', 'title'):
            if attrs.get(opt):
                entry[opt] = [str(attrs[opt]).encode('utf-8')]
        # Password: Entra users get a {SASL} marker, local users an {SSHA} hash.
        result_pw = None
        if auth_mode == "entra":
            entra_upn = upn or attrs.get('mail') or uid
            # {SASL}<upn> routes binds to saslauthd → Entra ROPC; no local pw.
            entry['userPassword'] = [f"{SASL_SCHEME}{entra_upn}".encode('utf-8')]
        else:
            # Local user: use the supplied password or generate one, then hash it.
            result_pw = password or secrets.token_urlsafe(16)
            entry['userPassword'] = [self._ssha(result_pw)]
        # Create the entry; return the password only for local users.
        try:
            with self._conn() as conn, _UID_LOCK:
                # One uid per tenant, whichever OU it lives in.
                if self._find_user_dn(conn, uid, tenant_slug):
                    return {"status": "ERROR",
                            "message": f"user {uid!r} already exists in this tenant"}
                try:
                    _add_entry(conn, dn, entry)
                except ldap.NO_SUCH_OBJECT:
                    # The parent is missing: either ou=users itself (removed
                    # since the check above) or the chosen OU.
                    return self._missing_ou_error(conn, tenant_slug,
                                                  "OU not found: " + "/".join(ou_path or []))
            out = {"status": "SUCCESS", "dn": dn, "auth_mode": auth_mode}
            if result_pw is not None:
                out["password"] = result_pw
            return out
        except ValueError as e:
            return _error_reply(e)
        except ldap.LDAPError as e:
            # LDAP error: log and report it.
            logger.error(f"Error creating user {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def update_user_scoped(self, uid: str, attrs: Optional[Dict[str, Any]] = None,
                           tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Replace supplied attributes on a tenant-scoped user (cn/sn/givenName/
        mail/displayName/...). Does not touch userPassword or the auth mode."""
        # Replace each supplied, non-None attribute.
        attrs = attrs or {}
        mods = []
        for key in ('cn', 'sn', 'givenName', 'mail', 'displayName',
                    'telephoneNumber', 'title'):
            if key in attrs and attrs[key] is not None:
                mods.append((ldap.MOD_REPLACE, key, [str(attrs[key]).encode('utf-8')]))
        # Find the user, then apply all changes in one modify.
        try:
            with self._conn() as conn:
                dn = self._require_user_dn(conn, uid, tenant_slug)
                # Nothing supplied: succeed without touching the directory.
                if not mods:
                    return {"status": "SUCCESS", "dn": dn, "message": "no attributes to update"}
                conn.modify_s(dn, mods)
            return {"status": "SUCCESS", "dn": dn}
        except ValueError as e:
            return _error_reply(e)
        except ldap.LDAPError as e:
            # LDAP error: log and report it.
            logger.error(f"Error updating user {uid}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def delete_user_scoped(self, uid: str, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Delete a tenant-scoped user by uid, from whichever OU it is in."""
        # Find the user, then delete it through the generic helper.
        try:
            with self._conn() as conn:
                dn = self._require_user_dn(conn, uid, tenant_slug)
        except ValueError as e:
            return _error_reply(e)
        except ldap.LDAPError as e:
            # Directory unreachable during the lookup: report it like the
            # other user commands do.
            logger.error(f"Error looking up user {uid} to delete: {e}")
            return {"status": "ERROR", "message": str(e)}
        return self.delete_entity(dn)

    def set_password_scoped(self, uid: str, new_password: str,
                            tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Set a LOCAL user's password. Refuses Entra-backed users (their
        userPassword is ``{SASL}<upn>`` — they have no local secret to set)."""
        # A new password is required.
        if not new_password:
            return {"status": "ERROR", "message": "password is required"}
        # Find the user and read its current userPassword to detect Entra-backed accounts.
        dn = uid
        try:
            with self._conn() as conn:
                dn = self._require_user_dn(conn, uid, tenant_slug)
                cur = conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ['userPassword'])
                # Refuse when any value is a {SASL} marker.
                for _d, a in cur:
                    for val in a.get('userPassword', []):
                        if val.decode('utf-8', 'replace').startswith(SASL_SCHEME):
                            return {"status": "ERROR",
                                    "message": "user is Entra-backed (SASL); has no "
                                               "local password to set"}
                # Local user: store the new password as an {SSHA} hash.
                conn.modify_s(dn, [(ldap.MOD_REPLACE, 'userPassword', [self._ssha(new_password)])])
            return {"status": "SUCCESS", "dn": dn}
        except ValueError as e:
            return _error_reply(e)
        except ldap.LDAPError as e:
            # LDAP error: log and report it.
            logger.error(f"Error setting password for {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def create_group_scoped(self, cn: str, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Create a ``groupOfNames`` under a tenant's ``ou=groups``. Seeded with
        the base DN as a placeholder member (groupOfNames requires ≥1)."""
        # Build the group's DN in the tenant's groups container; reject invalid input.
        try:
            dn = build_group_dn(self.base_dn, cn, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        # Create the group with the base DN as its placeholder member.
        try:
            with self._conn() as conn:
                _add_entry(conn, dn, {
                    'objectClass': [b'groupOfNames'],
                    'cn': [cn.encode('utf-8')],
                    'member': [self.base_dn.encode('utf-8')],
                })
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            # LDAP error: log and report it.
            logger.error(f"Error creating group {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def delete_group_scoped(self, cn: str, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Delete a tenant-scoped group by cn (under the tenant's ou=groups)."""
        # Build the group's DN and delete it through the generic helper.
        try:
            dn = build_group_dn(self.base_dn, cn, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        return self.delete_entity(dn)

    def add_member_scoped(self, uid: str, group_cn: str,
                          tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Add a tenant-scoped user to a tenant-scoped group."""
        # Find the user (in any OU), then reuse the generic membership helper.
        try:
            u_dn, g_dn = self._member_dns(uid, group_cn, tenant_slug)
        except (ValueError, ldap.LDAPError) as e:
            return _error_reply(e)
        return self.add_user_to_group(u_dn, g_dn)

    def _member_dns(self, uid: str, group_cn: str, tenant_slug: Optional[str]):
        """Return ``(user_dn, group_dn)`` for a membership change; raises
        ValueError when either name is invalid or the user does not exist."""
        g_dn = build_group_dn(self.base_dn, group_cn, tenant_slug)
        with self._conn() as conn:
            u_dn = self._require_user_dn(conn, uid, tenant_slug)
        return u_dn, g_dn

    def remove_member_scoped(self, uid: str, group_cn: str,
                             tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Remove a tenant-scoped user from a tenant-scoped group."""
        # Find the user (in any OU), then reuse the generic membership helper.
        try:
            u_dn, g_dn = self._member_dns(uid, group_cn, tenant_slug)
        except (ValueError, ldap.LDAPError) as e:
            return _error_reply(e)
        return self.remove_user_from_group(u_dn, g_dn)

    def list_users_scoped(self, tenant_slug: Optional[str] = None) -> List[Dict[str, Any]]:
        """List users under a tenant's ``ou=users`` (or base level if no slug).
        Raises :class:`TenantNotProvisionedError` when the container is missing."""
        # Resolve the tenant's users container; an invalid tenant yields an empty list.
        try:
            search_base = users_container_dn(self.base_dn, tenant_slug)
        except ValueError:
            return []
        # Search the container for person entries.
        try:
            with self._conn() as conn:
                results = conn.search_s(search_base, ldap.SCOPE_SUBTREE,
                                        "(objectClass=person)",
                                        ['uid', 'cn', 'sn', 'givenName', 'mail', 'userPassword'])
        # Container missing: the tenant was never provisioned, which is not
        # the same as a provisioned tenant with no users.
        except ldap.NO_SUCH_OBJECT:
            raise TenantNotProvisionedError(_not_provisioned_message(search_base))
        # Convert each result into a user dictionary.
        users = []
        for dn, attrs in results:
            # Skip referral entries, which have no DN.
            if not dn:
                continue
            def _d(k):
                """Return the first value of attribute k as text, or an empty string."""
                v = attrs.get(k, [b''])
                return v[0].decode('utf-8', 'replace') if v and v[0] else ''
            # Entra-backed users are recognised by the {SASL} password marker,
            # whose value is the Entra UPN they sign in with.
            pw = attrs.get('userPassword', [b''])
            pw0 = pw[0].decode('utf-8', 'replace') if pw and pw[0] else ''
            is_entra = pw0.startswith(SASL_SCHEME)
            # Add the normalised user, falling back to the RDN value for the username.
            users.append({
                "username": _d('uid') or dn.split(',')[0].split('=')[-1],
                "cn": _d('cn'), "first_name": _d('givenName'),
                "last_name": _d('sn'), "email": _d('mail'), "dn": dn,
                "auth_mode": "entra" if is_entra else "local",
                "upn": pw0[len(SASL_SCHEME):] if is_entra else "",
                "ou_path": ou_path_of(dn, search_base) or [],
            })
        # Return the user list.
        return users

    def list_groups_scoped(self, tenant_slug: Optional[str] = None) -> List[Dict[str, Any]]:
        """List groups under a tenant's ``ou=groups`` (or base level if no slug).
        Raises :class:`TenantNotProvisionedError` when ``ou=users`` is
        missing, and ``ldap.LDAPError`` when only ``ou=groups`` is."""
        # Resolve the tenant's containers; an invalid tenant yields an empty list.
        try:
            users_base = users_container_dn(self.base_dn, tenant_slug)
            search_base = groups_container_dn(self.base_dn, tenant_slug)
        except ValueError:
            return []
        # ou=users is what marks a tenant as provisioned (as for every other
        # command), so check it too: groups left behind without it are not a
        # provisioned tenant.
        with self._conn() as conn:
            try:
                conn.search_s(users_base, ldap.SCOPE_BASE, "(objectClass=*)", ['ou'])
            except ldap.NO_SUCH_OBJECT:
                raise TenantNotProvisionedError(_not_provisioned_message(users_base))
            # Search the groups container for both group types. A provisioned
            # tenant whose ou=groups is gone is a damaged directory: report it
            # as an error, neither "not provisioned" nor "no groups".
            try:
                results = conn.search_s(search_base, ldap.SCOPE_SUBTREE,
                                        "(|(objectClass=groupOfNames)(objectClass=posixGroup))",
                                        ['cn', 'member', 'memberUid'])
            except ldap.NO_SUCH_OBJECT:
                raise ldap.LDAPError(f"groups container missing: {search_base}")
        # Convert each result into a group dictionary.
        groups = []
        for dn, attrs in results:
            # Skip referral entries, which have no DN.
            if not dn:
                continue
            # Group name, plus its members without the base-DN placeholder.
            cn = attrs.get('cn', [b''])[0].decode('utf-8', 'replace') if attrs.get('cn') else ''
            members = [m.decode('utf-8', 'replace') for m in attrs.get('member', [])
                       if m.decode('utf-8', 'replace') != self.base_dn]
            # Add the normalised group.
            groups.append({"name": cn, "dn": dn, "member_count": len(members),
                           "members": members})
        # Return the group list.
        return groups

    def get_user_groups(self, uid: str, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Return a user's group memberships — for hub RBAC. Reads the user's
        ``memberOf`` (if the memberof overlay is enabled) AND searches groups by
        ``member=<user_dn>`` (works without the overlay); the union is returned."""
        # Check the names; the user's DN is looked up below (it may sit in any OU).
        u_dn = uid
        try:
            groups_base = groups_container_dn(self.base_dn, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        # Collect group DNs to names; a dict merges both lookups without duplicates.
        found: Dict[str, str] = {}  # dn -> cn
        # One connection for both lookups; it is always unbound.
        try:
            with self._conn() as conn:
                # Find the user wherever it lives under ou=users.
                try:
                    u_dn = self._find_user_dn(conn, uid, tenant_slug)
                except ValueError as e:
                    return _error_reply(e)
                if not u_dn:
                    return {"status": "ERROR", "message": f"user not found: {uid}"}
                # memberOf on the user entry (present only with the memberof overlay).
                ures = conn.search_s(u_dn, ldap.SCOPE_BASE, "(objectClass=*)", ['memberOf'])
                for _d, a in ures:
                    for g in a.get('memberOf', []):
                        found.setdefault(g.decode('utf-8', 'replace'), '')
                # Reverse search: groups that list this user as a member.
                safe = ldap.filter.escape_filter_chars(u_dn)
                try:
                    gres = conn.search_s(groups_base, ldap.SCOPE_SUBTREE,
                                         f"(&(objectClass=groupOfNames)(member={safe}))", ['cn'])
                    for gdn, a in gres:
                        if gdn:
                            cn = a.get('cn', [b''])[0].decode('utf-8', 'replace') if a.get('cn') else ''
                            found[gdn] = cn or found.get(gdn, '')
                # Groups container missing: only the memberOf results apply.
                except ldap.NO_SUCH_OBJECT:
                    pass
        # LDAP error: log and report it.
        except ldap.LDAPError as e:
            logger.error(f"Error getting groups for {u_dn}: {e}")
            return {"status": "ERROR", "message": str(e)}
        # Build the result, falling back to the RDN value when the name is unknown.
        groups = [{"dn": dn, "name": cn or dn.split(',')[0].split('=')[-1]}
                  for dn, cn in found.items()]
        return {"status": "SUCCESS", "dn": u_dn, "groups": groups,
                "group_dns": list(found.keys()), "count": len(groups)}

    # ---- OUs inside a tenant -------------------------------------------------
    # Tenant admins organise users into OUs (folders) below the tenant's
    # ``ou=users`` container. Every path is built from the caller's tenant slug,
    # so nothing here can reach outside the tenant: users move between OUs of
    # their own tenant, never to another tenant (owner decision). The
    # ``ou=users`` container itself (empty path) can't be renamed or deleted.

    def list_ous_scoped(self, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """List the OUs below a tenant's ``ou=users``, each with its path,
        name and user count. The container itself is not listed."""
        # Resolve the container; an invalid tenant is an error.
        try:
            base = users_container_dn(self.base_dn, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        # One subtree search returns both the OUs and the users in them.
        try:
            with self._conn() as conn:
                res = conn.search_s(base, ldap.SCOPE_SUBTREE,
                                    "(|(objectClass=organizationalUnit)(objectClass=person))",
                                    ['objectClass'])
        # No ou=users: the tenant was never provisioned, which is not the same
        # as a provisioned tenant with no OUs.
        except ldap.NO_SUCH_OBJECT:
            return {"status": "ERROR", "error": "NOT_PROVISIONED",
                    "message": _not_provisioned_message(base)}
        except ldap.LDAPError as e:
            logger.error(f"Error listing OUs under {base}: {e}")
            return {"status": "ERROR", "message": str(e)}
        # Split the results into OUs and per-OU user counts.
        ous: Dict[tuple, Dict[str, Any]] = {}
        counts: Dict[tuple, int] = {}
        for dn, attrs in res:
            path = ou_path_of(dn, base) if dn else None
            if path is None:
                continue
            classes = {c.decode('utf-8', 'replace').lower() for c in attrs.get('objectClass', [])}
            if 'person' in classes:
                counts[tuple(path)] = counts.get(tuple(path), 0) + 1
            elif path:
                ous[tuple(path)] = {"path": path, "name": path[-1]}
        # Attach the counts and sort by path so the UI can draw a tree.
        for key, ou in ous.items():
            ou["user_count"] = counts.get(key, 0)
        return {"status": "SUCCESS", "ous": [ous[k] for k in sorted(ous, key=lambda p: [s.lower() for s in p])],
                "root_user_count": counts.get((), 0)}

    def create_ou_scoped(self, name: str, parent_path: Optional[list] = None,
                         tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Create an OU called ``name`` under ``parent_path`` (empty = directly
        under ``ou=users``). The parent must already exist."""
        # Build the new OU's DN; reject a bad name or tenant.
        try:
            clean = clean_ou_name(name)
            dn = ou_path_dn(self.base_dn, tenant_slug, list(parent_path or []) + [clean])
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        # Create it; a missing tenant, a missing parent or an existing OU is a clear error.
        try:
            with self._conn() as conn:
                try:
                    _add_entry(conn, dn, {'objectClass': [b'organizationalUnit'],
                                          'ou': [clean.encode('utf-8')]})
                except ldap.NO_SUCH_OBJECT:
                    return self._missing_ou_error(
                        conn, tenant_slug, "parent OU not found: " + "/".join(parent_path or []))
            return {"status": "SUCCESS", "dn": dn, "path": list(parent_path or []) + [clean]}
        except ldap.ALREADY_EXISTS:
            return {"status": "ERROR", "message": f"OU already exists: {clean}"}
        except ldap.LDAPError as e:
            logger.error(f"Error creating OU {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def _move_entry(self, conn, old_dn: str, new_dn: str, moved: Dict[str, str],
                    tenant_slug: Optional[str]) -> int:
        """Rename ``old_dn`` to ``new_dn`` and repoint group memberships.

        If repointing fails, the group changes already made and the rename are
        undone before the error is re-raised, so a failed move or OU rename
        leaves the directory as it was. Returns the number of groups changed."""
        old_parts, new_parts = split_dn_raw(old_dn), split_dn_raw(new_dn)
        conn.rename_s(old_dn, new_parts[0], ",".join(new_parts[1:]), 1)
        done: list = []
        try:
            return self._rewrite_memberships(conn, tenant_slug, moved, done)
        except ldap.LDAPError as exc:
            # Undo the group changes (newest first), then the rename; note any
            # step that could not be undone.
            stuck = []
            for gdn, old_vals, new_vals in reversed(done):
                try:
                    conn.modify_s(gdn, [(ldap.MOD_ADD, 'member', old_vals),
                                        (ldap.MOD_DELETE, 'member', new_vals)])
                except ldap.LDAPError as e:
                    logger.error(f"Rollback of group {gdn} failed: {e}")
                    stuck.append(f"group {gdn}")
            try:
                conn.rename_s(new_dn, old_parts[0], ",".join(old_parts[1:]), 1)
            except ldap.LDAPError as e:
                logger.error(f"Rollback of move {new_dn} -> {old_dn} failed: {e}")
                # The entry stayed at its new place, so the groups that are
                # wrong now are exactly those still listing an old DN (put
                # back, refused the rewrite or not reached). A group whose
                # revert failed lists the new DN and is therefore correct.
                stuck = [f"entry is still at {new_dn}"]
                stuck.extend(self._groups_listing_old_dns(conn, tenant_slug, moved))
            # Clean undo: report the original error. Partial undo: say exactly
            # what was left changed, so it is never read as "nothing happened".
            if stuck:
                raise PartialRollbackError(
                    f"{exc}; the change could not be fully undone: " + "; ".join(stuck)) from exc
            # A group that vanished mid-rewrite raises NO_SUCH_OBJECT; callers
            # read that as "OU not found", so report it as a group error.
            if isinstance(exc, ldap.NO_SUCH_OBJECT):
                raise ldap.LDAPError(f"a group changed during the move: {exc}") from exc
            raise

    def _groups_listing_old_dns(self, conn, tenant_slug: Optional[str],
                                moved: Dict[str, str]) -> List[str]:
        """Describe each group that still lists one of ``moved``'s old DNs,
        for a partial-rollback report. If the groups can't be read, say so
        rather than report none."""
        old = {o.lower() for o in moved}
        try:
            groups = conn.search_s(groups_container_dn(self.base_dn, tenant_slug),
                                   ldap.SCOPE_SUBTREE, "(objectClass=groupOfNames)",
                                   ['member'])
        except ldap.NO_SUCH_OBJECT:
            return []
        except ldap.LDAPError as e:
            logger.error(f"Could not re-read groups after a failed rollback: {e}")
            return ["groups could not be checked for the old DN"]
        return [f"group {gdn} lists an old DN, which no longer exists"
                for gdn, attrs in groups
                if gdn and any(v.decode('utf-8', 'replace').lower() in old
                               for v in attrs.get('member', []))]

    def _users_below(self, conn, dn: str) -> List[str]:
        """DNs of every user at or below ``dn`` (empty when the entry is gone)."""
        try:
            res = conn.search_s(dn, ldap.SCOPE_SUBTREE, "(objectClass=person)", ['uid'])
        except ldap.NO_SUCH_OBJECT:
            return []
        return [d for d, _a in res if d]

    def rename_ou_scoped(self, path: list, new_name: str,
                         tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Rename the OU at ``path``. Users inside keep their place; their
        group memberships are rewritten to the new DNs."""
        # The users container itself can't be renamed. This is invalid input
        # for every tenant, so it is refused before the directory is asked
        # whether the tenant is provisioned (as a malformed name is).
        if not path:
            return {"status": "ERROR", "message": "the root users OU cannot be renamed"}
        # Build the old and new DNs; reject bad names.
        try:
            clean = clean_ou_name(new_name)
            old_dn = ou_path_dn(self.base_dn, tenant_slug, path)
            new_path = list(path[:-1]) + [clean]
            new_dn = ou_path_dn(self.base_dn, tenant_slug, new_path)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        # Note the users below, rename, then repoint their group memberships.
        try:
            with self._conn() as conn:
                try:
                    before = self._users_below(conn, old_dn)
                    moved = {d: rebase_dn(d, old_dn, new_dn) for d in before}
                    groups = self._move_entry(conn, old_dn, new_dn, moved, tenant_slug)
                except ldap.NO_SUCH_OBJECT:
                    return self._missing_ou_error(conn, tenant_slug, "OU not found: " + "/".join(path))
            return {"status": "SUCCESS", "dn": new_dn, "path": new_path,
                    "users_moved": len(moved), "groups_updated": groups}
        except ldap.ALREADY_EXISTS:
            return {"status": "ERROR", "message": f"OU already exists: {clean}"}
        except PartialRollbackError as e:
            return {"status": "ERROR", "error": "PARTIAL_ROLLBACK", "message": str(e)}
        except ldap.LDAPError as e:
            logger.error(f"Error renaming OU {old_dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def delete_ou_scoped(self, path: list, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Delete the OU at ``path`` only when it is empty (no users and no
        child OUs), so deleting a folder can never delete accounts."""
        # The users container itself can't be deleted. This is invalid input
        # for every tenant, so it is refused before the directory is asked
        # whether the tenant is provisioned (as a malformed name is).
        if not path:
            return {"status": "ERROR", "message": "the root users OU cannot be deleted"}
        try:
            dn = ou_path_dn(self.base_dn, tenant_slug, path)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        # Refuse when anything sits below the OU, then delete it.
        try:
            with self._conn() as conn:
                try:
                    children = conn.search_s(dn, ldap.SCOPE_ONELEVEL, "(objectClass=*)", ['objectClass'])
                    if [d for d, _a in children if d]:
                        return {"status": "ERROR",
                                "message": "OU is not empty: move or delete its users and OUs first"}
                    conn.delete_s(dn)
                except ldap.NO_SUCH_OBJECT:
                    return self._missing_ou_error(conn, tenant_slug, "OU not found: " + "/".join(path))
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            logger.error(f"Error deleting OU {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def move_user_scoped(self, uid: str, target_path: Optional[list] = None,
                         tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Move a user to another OU of the same tenant (empty path = straight
        under ``ou=users``) and repoint its group memberships.

        The target is built from the same tenant slug as the lookup, so a user
        can only move within its own tenant's OU tree."""
        # Build the target OU's DN; reject bad names.
        try:
            target_dn = ou_path_dn(self.base_dn, tenant_slug, target_path)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        try:
            with self._conn() as conn:
                # Find the user; already there means nothing to do.
                old_dn = self._require_user_dn(conn, uid, tenant_slug)
                rdn = split_dn_raw(old_dn)[0]
                new_dn = f"{rdn},{target_dn}"
                if old_dn.lower() == new_dn.lower():
                    return {"status": "SUCCESS", "dn": old_dn, "message": "already in that OU"}
                # Move, then repoint its group memberships (undone on failure).
                try:
                    groups = self._move_entry(conn, old_dn, new_dn, {old_dn: new_dn}, tenant_slug)
                except ldap.NO_SUCH_OBJECT:
                    # The rename's source or target is gone. The target OU
                    # still being there means the user was removed meanwhile.
                    try:
                        conn.search_s(target_dn, ldap.SCOPE_BASE, "(objectClass=*)", ['ou'])
                        return {"status": "ERROR", "message": f"user not found: {uid}"}
                    except ldap.NO_SUCH_OBJECT:
                        return self._missing_ou_error(
                            conn, tenant_slug, "OU not found: " + "/".join(target_path or []))
            return {"status": "SUCCESS", "dn": new_dn, "ou_path": list(target_path or []),
                    "groups_updated": groups}
        except ValueError as e:
            return _error_reply(e)
        except PartialRollbackError as e:
            return {"status": "ERROR", "error": "PARTIAL_ROLLBACK", "message": str(e)}
        except ldap.LDAPError as e:
            logger.error(f"Error moving user {uid}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def update_ou(self, dn: str, new_name: str) -> Dict[str, Any]:
        """Rename an OU. The new DN is derived from the new ou= RDN."""
        # A new name is required.
        if not new_name:
            return {"status": "ERROR", "message": "new_name is required"}
        # Bind, rename the RDN, then compute the new DN from the old parent.
        conn = self._get_connection()
        try:
            new_rdn = f"ou={self._escape_rdn(new_name)}"
            self._rename(conn, dn, new_rdn)
            parent = dn.split(',', 1)[1] if ',' in dn else ''
            new_dn = f"{new_rdn},{parent}" if parent else new_rdn
            return {"status": "SUCCESS", "dn": new_dn}
        # LDAP error: log and report it.
        except ldap.LDAPError as e:
            logger.error(f"Error renaming OU {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def update_user(self, dn: str, first_name: str = None, last_name: str = None,
                    email: str = None, username: str = None) -> Dict[str, Any]:
        """Update a user's attributes (cn/sn/givenName/mail) and optionally
        rename the uid RDN. None values are left untouched."""
        # Bind, then collect a replace modification for each supplied field.
        conn = self._get_connection()
        mods = []
        # cn is the full name, so it is updated only when both parts are given.
        if first_name is not None and last_name is not None:
            mods.append((ldap.MOD_REPLACE, 'cn', [f"{first_name} {last_name}".encode('utf-8')]))
        if first_name is not None:
            mods.append((ldap.MOD_REPLACE, 'givenName', [first_name.encode('utf-8')]))
        if last_name is not None:
            mods.append((ldap.MOD_REPLACE, 'sn', [last_name.encode('utf-8')]))
        if email is not None:
            mods.append((ldap.MOD_REPLACE, 'mail', [email.encode('utf-8')]))
        # Apply attribute changes first, then rename the uid if it changed.
        try:
            if mods:
                conn.modify_s(dn, mods)
            new_dn = dn
            if username:
                cur_uid = dn.split(',')[0].split('=', 1)[-1]
                if username != cur_uid:
                    euid = self._escape_rdn(username)
                    self._rename(conn, dn, f"uid={euid}")
                    parent = dn.split(',', 1)[1] if ',' in dn else ''
                    new_dn = f"uid={euid},{parent}" if parent else f"uid={euid}"
            return {"status": "SUCCESS", "dn": new_dn}
        # LDAP error: log and report it.
        except ldap.LDAPError as e:
            logger.error(f"Error updating user {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def update_group(self, dn: str, new_name: str) -> Dict[str, Any]:
        """Rename a group (cn RDN)."""
        # A new name is required.
        if not new_name:
            return {"status": "ERROR", "message": "new_name is required"}
        # Bind, rename the RDN, then compute the new DN from the old parent.
        conn = self._get_connection()
        try:
            new_rdn = f"cn={self._escape_rdn(new_name)}"
            self._rename(conn, dn, new_rdn)
            parent = dn.split(',', 1)[1] if ',' in dn else ''
            new_dn = f"{new_rdn},{parent}" if parent else new_rdn
            return {"status": "SUCCESS", "dn": new_dn}
        # LDAP error: log and report it.
        except ldap.LDAPError as e:
            logger.error(f"Error renaming group {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def search(self, query: str, tenant: Optional[str] = None,
               is_admin: bool = False) -> Dict[str, Any]:
        """Search LDAP for users and groups matching ``query``.

        Scope (spoke-enforced; the hub now allows non-admin directory search but
        expects the spoke to OU-scope it — ``TENANT == OU`` lowercase):
          * ``tenant`` present        → search only under ``ou=<slug>,<base>``
            (the tenant's OU, built via :func:`tenant_ou_dn` — never by hand).
            SUBTREE scope picks up the ``ou=users`` / ``ou=groups`` containers
            beneath it.
          * ``tenant`` absent + admin → unscoped, whole ``base_dn`` (legacy).
          * ``tenant`` absent + non-admin → EMPTY (never leak another tenant's
            users/groups).

        ``query`` is matched case-insensitively (LDAP ``caseIgnoreSubstringsMatch``
        on the relevant attributes) against ``cn`` / ``sAMAccountName`` / ``uid``
        / ``mail`` for users and ``cn`` / ``memberUid`` for groups. Users and
        groups are selected by objectClass (person/user/inetOrgPerson vs
        group/groupOfNames) in one combined filter.

        Each result dict carries at minimum ``source``, ``type``, ``name``,
        ``dn``; users also carry ``mail``. A bind failure raises
        :class:`LdapBindError` (NOT ``ldap.LDAPError``) and is deliberately NOT
        caught here — it bypasses the per-method catch and propagates to the
        spoke's ``_ldap_write``, which maps it to the clean
        ``INVALID_CREDENTIALS`` envelope (see memory
        ``ldap-bind-error-bypasses-per-method-catches``)."""
        # An empty query returns no results.
        q = (query or "").strip()
        if not q:
            return {"status": "SUCCESS", "results": [], "count": 0}

        # ── Compute the search base from the tenant slug (no hand-rolled DNs) ──
        # Admins are trusted to see every OU, so they always search the whole
        # base_dn — the tenant slug only narrows non-admins to their own OU.
        # Checking `tenant` first (the old order) made the admin branch
        # unreachable whenever a tenant slug was supplied, which hid users
        # living outside ou=<slug>,<base> (legacy users, other tenants' OUs)
        # and was the root cause of "search returns nothing" for admins.
        if is_admin:
            search_base = self.base_dn
        elif tenant:
            try:
                # tenant_ou_dn canonicalises (lower-cases) + escapes the slug;
                # a bad slug raises ValueError → clean ERROR, no DN injection.
                search_base = tenant_ou_dn(self.base_dn, tenant)
            except ValueError as e:
                logger.warning("LDAP search bad tenant slug %r: %s", tenant, e)
                return {"status": "ERROR", "message": str(e), "results": []}
        else:
            # Non-admin without a tenant scope gets nothing.
            return {"status": "SUCCESS", "results": [], "count": 0}

        # Bind and search; LDAP errors become an ERROR result.
        results: List[Dict[str, Any]] = []
        try:
            conn = self._get_connection()
            # RFC-4515 escape the substring filter value.
            safe_q = (q.replace("\\", "\\5c").replace("*", "\\2a")
                      .replace("(", "\\28").replace(")", "\\29"))
            # One combined filter: users (person/user/inetOrgPerson) on
            # cn/uid/mail/sAMAccountName OR groups (group/groupOfNames) on
            # cn/memberUid.
            ldap_filter = (
                "(|"
                f"(&(|(objectClass=person)(objectClass=user)(objectClass=inetOrgPerson))"
                f"(|(cn=*{safe_q}*)(uid=*{safe_q}*)(mail=*{safe_q}*)(sAMAccountName=*{safe_q}*)))"
                f"(&(|(objectClass=group)(objectClass=groupOfNames))"
                f"(|(cn=*{safe_q}*)(memberUid=*{safe_q}*)))"
                ")"
            )
            # Attributes needed to describe both users and groups.
            attrs = ['cn', 'uid', 'sn', 'givenName', 'mail', 'sAMAccountName',
                     'memberUid', 'member', 'description', 'objectClass']
            raw = conn.search_s(search_base, ldap.SCOPE_SUBTREE, ldap_filter, attrs)
            # Convert each result into a user or group dictionary.
            for dn, entry in raw:
                # Skip referral entries, which have no DN.
                if not dn:
                    continue
                # objectClass values as text, used to tell groups from users.
                obj_classes = [c.decode() if isinstance(c, bytes) else c
                               for c in entry.get('objectClass', [])]
                def _d(key: str) -> str:
                    """Return the first value of an attribute as text, or an empty string."""
                    v = entry.get(key, [b''])[0]
                    return (v.decode('utf-8') if isinstance(v, bytes) else v) if v else ''
                def _dl(key: str) -> List[str]:
                    """Return every value of an attribute as text."""
                    out = []
                    for v in entry.get(key, []):
                        out.append(v.decode('utf-8') if isinstance(v, bytes) else v)
                    return out
                # Groups: include both member DNs and memberUid values.
                is_group = any(oc in obj_classes for oc in ('group', 'groupOfNames'))
                if is_group:
                    members = _dl('member')
                    member_uids = _dl('memberUid')
                    results.append({
                        "source":       "ldap",
                        "type":         "group",
                        "id":           dn,
                        "name":         _d('cn'),
                        "dn":           dn,
                        "description":  _d('description'),
                        "members":      members,
                        "member_uids":  member_uids,
                        "member_count": len(members) + len(member_uids),
                    })
                else:
                    # Users: include name, username and mail fields.
                    results.append({
                        "source":     "ldap",
                        "type":       "user",
                        "id":         dn,
                        "name":       _d('cn') or _d('uid') or _d('sAMAccountName'),
                        "username":   _d('uid') or _d('sAMAccountName'),
                        "mail":       _d('mail'),
                        "email":      _d('mail'),
                        "dn":         dn,
                        "given_name": _d('givenName'),
                        "surname":    _d('sn'),
                    })
        except ldap.LDAPError as e:
            # LDAP error: log and report it.
            logger.error("LDAP search failed: %s", e)
            return {"status": "ERROR", "message": str(e), "results": []}
        # NOTE: LdapBindError intentionally NOT caught here — it propagates to
        # the spoke's _ldap_write → INVALID_CREDENTIALS envelope (bind error
        # bypasses per-method catches; catching it here would swallow the
        # actionable hint into a generic ERROR).
        return {"status": "SUCCESS", "results": results, "count": len(results)}
