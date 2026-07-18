import ldap
import ldap.filter
import ldap.dn
from typing import Any, Dict, List, Optional
import base64
import hashlib
import logging
import os
import secrets
from contextlib import contextmanager

# Pure DN builders (dependency-free) — shared, tested tenant-scoped DN math.
try:
    from .ldap_dn import (canonical_slug, tenant_ou_dn, users_container_dn,
                          groups_container_dn, user_dn as build_user_dn,
                          group_dn as build_group_dn)
except ImportError:  # loaded outside the src package (tests / bare import)
    from ldap_dn import (canonical_slug, tenant_ou_dn, users_container_dn,
                         groups_container_dn, user_dn as build_user_dn,
                         group_dn as build_group_dn)

logger = logging.getLogger("LdapManager")

# userPassword marker that routes a bind through Cyrus SASL → saslauthd → the
# Entra ROPC bridge (see src/entra_ropc_auth.py). An Entra-backed user's
# userPassword is ``{SASL}<upn>`` — it carries no local secret.
SASL_SCHEME = "{SASL}"

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
        self.admin_dn = admin_dn
        self.admin_pw = admin_pw
        self.base_dn = base_dn
        self.server = server_url

    def _get_connection(self):
        conn = ldap.initialize(self.server)
        conn.simple_bind_s(self.admin_dn, self.admin_pw)
        return conn

    @contextmanager
    def _conn(self):
        """Bound connection that is ALWAYS unbound afterwards — fixes the socket/FD
        leak from _get_connection (bound per call, never closed), which exhausted
        slapd's conn limit on a long-running spoke."""
        conn = ldap.initialize(self.server)
        try:
            conn.simple_bind_s(self.admin_dn, self.admin_pw)
            yield conn
        finally:
            try:
                conn.unbind_s()
            except Exception:  # noqa: BLE001
                pass

    def check_connection(self) -> bool:
        """Health check that binds + unbinds (no leak). Raises on failure."""
        with self._conn():
            return True

    @staticmethod
    def _escape_rdn(value: str) -> str:
        """Escape a value for safe use as a DN RDN component. Prevents DN
        injection — a name containing ``, + = \\ <`` (or a leading space) could
        otherwise reparent the entry (e.g. uid ``foo,ou=admins`` → placed under
        ``ou=admins``). The spoke binds as admin, so this is security-critical."""
        return ldap.dn.escape_dn_chars(value or "")

    @staticmethod
    def _ssha(password: str) -> bytes:
        """{SSHA} hash for ``userPassword``. slapd does NOT hash a plain add/modify
        of userPassword (only the Password-Modify ext-op does), so hash before
        storing to avoid cleartext passwords at rest."""
        salt = os.urandom(4)
        digest = hashlib.sha1(password.encode('utf-8') + salt).digest()
        return b'{SSHA}' + base64.b64encode(digest + salt)

    def list_ous(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(objectClass=organizationalUnit)", ['ou', 'description'])
        ous = []
        for dn, attrs in results:
            if dn:
                ou_name = attrs.get('ou', [b''])[0].decode('utf-8') if attrs.get('ou') else dn.split(',')[0].split('=')[-1]
                ous.append({"name": ou_name, "dn": dn})
        return ous

    def create_ou(self, ou_name: str, parent_dn: str = None) -> Dict[str, Any]:
        conn = self._get_connection()
        dn = f"ou={self._escape_rdn(ou_name)},{parent_dn if parent_dn else self.base_dn}"
        attrs = {
            'objectClass': [b'organizationalUnit'],
            'ou': [ou_name.encode('utf-8')]
        }
        try:
            conn.add_s(dn, attrs)
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            logger.error(f"Error creating OU {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def list_users(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(objectClass=person)", ['uid', 'cn', 'sn', 'givenName', 'mail'])
        users = []
        for dn, attrs in results:
            if dn:
                uid = attrs.get('uid', [b''])[0].decode('utf-8') if attrs.get('uid') else dn.split(',')[0].split('=')[-1]
                cn = attrs.get('cn', [b''])[0].decode('utf-8') if attrs.get('cn') else ''
                sn = attrs.get('sn', [b''])[0].decode('utf-8') if attrs.get('sn') else ''
                given = attrs.get('givenName', [b''])[0].decode('utf-8') if attrs.get('givenName') else cn.split(' ')[0] if cn else ''
                mail = attrs.get('mail', [b''])[0].decode('utf-8') if attrs.get('mail') else ''
                users.append({"username": uid, "cn": cn, "first_name": given, "last_name": sn, "email": mail, "dn": dn})
        return users

    def create_user(self, username: str, first_name: str, last_name: str, email: str, ou_dn: str, password: Optional[str] = None) -> Dict[str, Any]:
        conn = self._get_connection()
        dn = f"uid={self._escape_rdn(username)},{ou_dn}"
        # Use a caller-provided password, or generate a strong random one (never a hardcoded default).
        user_password = password or secrets.token_urlsafe(16)
        attrs = {
            'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
            'cn': [f"{first_name} {last_name}".encode('utf-8')],
            'sn': [last_name.encode('utf-8')],
            'uid': [username.encode('utf-8')],
            'mail': [email.encode('utf-8')],
            'userPassword': [self._ssha(user_password)]  # {SSHA}, not cleartext
        }
        try:
            conn.add_s(dn, attrs)
            # Return the generated/provided password so the operator can deliver it securely.
            return {"status": "SUCCESS", "dn": dn, "password": user_password}
        except ldap.LDAPError as e:
            logger.error(f"Error creating user {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def list_groups(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(|(objectClass=groupOfNames)(objectClass=posixGroup))", ['cn', 'member', 'memberUid', 'description'])
        groups = []
        for dn, attrs in results:
            if dn:
                cn = attrs.get('cn', [b''])[0].decode('utf-8') if attrs.get('cn') else ''
                members = [m.decode('utf-8') for m in attrs.get('member', [])]
                groups.append({
                    "name": cn,
                    "dn": dn,
                    "member_count": len(members),
                    "members": members,
                })
        return groups

    def create_group(self, group_name: str, ou_dn: str) -> Dict[str, Any]:
        conn = self._get_connection()
        dn = f"cn={self._escape_rdn(group_name)},{ou_dn}"
        attrs = {
            'objectClass': [b'groupOfNames'],
            'cn': [group_name.encode('utf-8')],
            'member': [self.base_dn.encode('utf-8')] # groupOfNames requires at least one member
        }
        try:
            conn.add_s(dn, attrs)
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            logger.error(f"Error creating group {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def add_user_to_group(self, user_dn: str, group_dn: str) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            conn.modify_s(group_dn, ldap.MOD_ADD, [('member', [user_dn.encode('utf-8')])])
            return {"status": "SUCCESS"}
        except ldap.LDAPError as e:
            logger.error(f"Error adding user {user_dn} to group {group_dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def remove_user_from_group(self, user_dn: str, group_dn: str) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            conn.modify_s(group_dn, ldap.MOD_DELETE, [('member', [user_dn.encode('utf-8')])])
            return {"status": "SUCCESS"}
        except ldap.LDAPError as e:
            logger.error(f"Error removing user {user_dn} from group {group_dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def set_password(self, user_dn: str, new_password: str) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            conn.passwd_s(user_dn, None, new_password.encode('utf-8'))
            return {"status": "SUCCESS"}
        except ldap.LDAPError:
            # Fallback: use modify with userPassword attribute
            try:
                conn.modify_s(user_dn, [(ldap.MOD_REPLACE, 'userPassword', [self._ssha(new_password)])])
                return {"status": "SUCCESS"}
            except ldap.LDAPError as e:
                logger.error(f"Error setting password for {user_dn}: {e}")
                return {"status": "ERROR", "message": str(e)}

    def delete_entity(self, dn: str) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            conn.delete_s(dn)
            return {"status": "SUCCESS"}
        except ldap.LDAPError as e:
            logger.error(f"Error deleting entity {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def _rename(self, conn, dn: str, new_rdn: str) -> None:
        """Rename an entry's RDN (modrdn). The old RDN value is deleted."""
        conn.rename_s(dn, new_rdn, delold=1)

    def migrate_tenant(self, source_base_dn: str, target_base_dn: str,
                       purge_source: bool = False) -> Dict[str, Any]:
        """Re-home every direct child of ``source_base_dn`` under
        ``target_base_dn`` (LDAP moddn with newsuperior — each child's own
        subtree moves with it). Used by cross-tenant migration when a tenant's
        ldap_base_dn changes. Optionally delete the now-empty source container.
        No-op when source == target or the source has no children. Returns the
        moved DNs; any per-entry error keeps the source (no purge)."""
        source_base_dn = (source_base_dn or "").strip()
        target_base_dn = (target_base_dn or "").strip()
        if not source_base_dn or not target_base_dn:
            return {"status": "ERROR", "message": "source and target base DN are required"}
        if source_base_dn.lower() == target_base_dn.lower():
            return {"status": "SUCCESS", "moved": [], "count": 0,
                    "message": "source and target base DN are the same"}
        moved: List[str] = []
        errors: Dict[str, str] = {}
        try:
            with self._conn() as conn:
                try:
                    children = conn.search_s(source_base_dn, ldap.SCOPE_ONELEVEL,
                                             "(objectClass=*)", ['dn'])
                except ldap.NO_SUCH_OBJECT:
                    return {"status": "SUCCESS", "moved": [], "count": 0,
                            "message": f"source '{source_base_dn}' not found — nothing to migrate"}
                for dn, _attrs in children:
                    rdn = dn.split(",", 1)[0]
                    try:
                        # newsuperior=target_base_dn moves the entry (and its
                        # subtree) under the target; delold=1 drops the old RDN val.
                        conn.rename_s(dn, rdn, target_base_dn, 1)
                        moved.append(dn)
                    except ldap.LDAPError as e:
                        errors[dn] = str(e)
                if purge_source and not errors:
                    try:
                        conn.delete_s(source_base_dn)
                    except ldap.LDAPError as e:
                        errors["delete_source"] = str(e)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}
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
        try:
            conn.add_s(dn, attrs)
        except ldap.ALREADY_EXISTS:
            pass

    def _find_tenant_ou(self, conn, slug: str) -> Optional[str]:
        """Return the DN of an existing tenant OU for ``slug`` (case-insensitive),
        or None. ``ou`` uses caseIgnoreMatch, so a filter on the canonical slug
        matches an OU stored in ANY case ("LRB" finds "lrb")."""
        safe = ldap.filter.escape_filter_chars(slug)
        try:
            res = conn.search_s(self.base_dn, ldap.SCOPE_ONELEVEL,
                                f"(&(objectClass=organizationalUnit)(ou={safe}))", ['ou'])
        except ldap.NO_SUCH_OBJECT:
            return None
        for dn, _attrs in res:
            if dn:
                return dn
        return None

    def provision_tenant_ou(self, tenant_slug: str) -> Dict[str, Any]:
        """Idempotently create ``ou=<slug>,<base>`` + child ``ou=users`` /
        ``ou=groups``. Case-insensitive: if an OU already exists for this tenant
        in ANY case, reuse it (never create a second). Returns the OU DN."""
        try:
            slug = canonical_slug(tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
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
        except ldap.LDAPError as e:
            logger.error(f"Error provisioning tenant OU '{tenant_slug}': {e}")
            return {"status": "ERROR", "message": str(e)}

    def create_user_scoped(self, uid: str, attrs: Optional[Dict[str, Any]] = None,
                           tenant_slug: Optional[str] = None,
                           auth_mode: str = "local", upn: Optional[str] = None,
                           password: Optional[str] = None) -> Dict[str, Any]:
        """Create a user under a tenant's ``ou=users`` (or base level if no slug).

        ``auth_mode="entra"`` → ``userPassword: {SASL}<upn>`` (no local secret;
        binds are validated against Entra via the ROPC bridge); ``"local"`` →
        ``{SSHA}`` of ``password`` (generated if omitted, returned once)."""
        attrs = attrs or {}
        try:
            dn = build_user_dn(self.base_dn, uid, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        cn = attrs.get('cn') or attrs.get('mail') or uid
        sn = attrs.get('sn') or attrs.get('cn') or uid
        entry: Dict[str, Any] = {
            'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
            'cn': [str(cn).encode('utf-8')],
            'sn': [str(sn).encode('utf-8')],
            'uid': [uid.encode('utf-8')],
        }
        for opt in ('givenName', 'mail', 'displayName', 'telephoneNumber', 'title'):
            if attrs.get(opt):
                entry[opt] = [str(attrs[opt]).encode('utf-8')]
        result_pw = None
        if auth_mode == "entra":
            entra_upn = upn or attrs.get('mail') or uid
            # {SASL}<upn> routes binds to saslauthd → Entra ROPC; no local pw.
            entry['userPassword'] = [f"{SASL_SCHEME}{entra_upn}".encode('utf-8')]
        else:
            result_pw = password or secrets.token_urlsafe(16)
            entry['userPassword'] = [self._ssha(result_pw)]
        try:
            with self._conn() as conn:
                conn.add_s(dn, entry)
            out = {"status": "SUCCESS", "dn": dn, "auth_mode": auth_mode}
            if result_pw is not None:
                out["password"] = result_pw
            return out
        except ldap.LDAPError as e:
            logger.error(f"Error creating user {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def update_user_scoped(self, uid: str, attrs: Optional[Dict[str, Any]] = None,
                           tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Replace supplied attributes on a tenant-scoped user (cn/sn/givenName/
        mail/displayName/...). Does not touch userPassword or the auth mode."""
        attrs = attrs or {}
        try:
            dn = build_user_dn(self.base_dn, uid, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        mods = []
        for key in ('cn', 'sn', 'givenName', 'mail', 'displayName',
                    'telephoneNumber', 'title'):
            if key in attrs and attrs[key] is not None:
                mods.append((ldap.MOD_REPLACE, key, [str(attrs[key]).encode('utf-8')]))
        if not mods:
            return {"status": "SUCCESS", "dn": dn, "message": "no attributes to update"}
        try:
            with self._conn() as conn:
                conn.modify_s(dn, mods)
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            logger.error(f"Error updating user {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def delete_user_scoped(self, uid: str, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Delete a tenant-scoped user by uid."""
        try:
            dn = build_user_dn(self.base_dn, uid, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        return self.delete_entity(dn)

    def set_password_scoped(self, uid: str, new_password: str,
                            tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Set a LOCAL user's password. Refuses Entra-backed users (their
        userPassword is ``{SASL}<upn>`` — they have no local secret to set)."""
        if not new_password:
            return {"status": "ERROR", "message": "password is required"}
        try:
            dn = build_user_dn(self.base_dn, uid, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        try:
            with self._conn() as conn:
                cur = conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ['userPassword'])
                for _d, a in cur:
                    for val in a.get('userPassword', []):
                        if val.decode('utf-8', 'replace').startswith(SASL_SCHEME):
                            return {"status": "ERROR",
                                    "message": "user is Entra-backed (SASL); has no "
                                               "local password to set"}
                conn.modify_s(dn, [(ldap.MOD_REPLACE, 'userPassword', [self._ssha(new_password)])])
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            logger.error(f"Error setting password for {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def create_group_scoped(self, cn: str, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Create a ``groupOfNames`` under a tenant's ``ou=groups``. Seeded with
        the base DN as a placeholder member (groupOfNames requires ≥1)."""
        try:
            dn = build_group_dn(self.base_dn, cn, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        try:
            with self._conn() as conn:
                conn.add_s(dn, {
                    'objectClass': [b'groupOfNames'],
                    'cn': [cn.encode('utf-8')],
                    'member': [self.base_dn.encode('utf-8')],
                })
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            logger.error(f"Error creating group {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def delete_group_scoped(self, cn: str, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Delete a tenant-scoped group by cn (under the tenant's ou=groups)."""
        try:
            dn = build_group_dn(self.base_dn, cn, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        return self.delete_entity(dn)

    def add_member_scoped(self, uid: str, group_cn: str,
                          tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Add a tenant-scoped user to a tenant-scoped group."""
        try:
            u_dn = build_user_dn(self.base_dn, uid, tenant_slug)
            g_dn = build_group_dn(self.base_dn, group_cn, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        return self.add_user_to_group(u_dn, g_dn)

    def remove_member_scoped(self, uid: str, group_cn: str,
                             tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Remove a tenant-scoped user from a tenant-scoped group."""
        try:
            u_dn = build_user_dn(self.base_dn, uid, tenant_slug)
            g_dn = build_group_dn(self.base_dn, group_cn, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        return self.remove_user_from_group(u_dn, g_dn)

    def list_users_scoped(self, tenant_slug: Optional[str] = None) -> List[Dict[str, Any]]:
        """List users under a tenant's ``ou=users`` (or base level if no slug)."""
        try:
            search_base = users_container_dn(self.base_dn, tenant_slug)
        except ValueError:
            return []
        try:
            with self._conn() as conn:
                results = conn.search_s(search_base, ldap.SCOPE_SUBTREE,
                                        "(objectClass=person)",
                                        ['uid', 'cn', 'sn', 'givenName', 'mail', 'userPassword'])
        except ldap.NO_SUCH_OBJECT:
            return []
        users = []
        for dn, attrs in results:
            if not dn:
                continue
            def _d(k):
                v = attrs.get(k, [b''])
                return v[0].decode('utf-8', 'replace') if v and v[0] else ''
            pw = attrs.get('userPassword', [b''])
            is_entra = bool(pw and pw[0].decode('utf-8', 'replace').startswith(SASL_SCHEME))
            users.append({
                "username": _d('uid') or dn.split(',')[0].split('=')[-1],
                "cn": _d('cn'), "first_name": _d('givenName'),
                "last_name": _d('sn'), "email": _d('mail'), "dn": dn,
                "auth_mode": "entra" if is_entra else "local",
            })
        return users

    def list_groups_scoped(self, tenant_slug: Optional[str] = None) -> List[Dict[str, Any]]:
        """List groups under a tenant's ``ou=groups`` (or base level if no slug)."""
        try:
            search_base = groups_container_dn(self.base_dn, tenant_slug)
        except ValueError:
            return []
        try:
            with self._conn() as conn:
                results = conn.search_s(search_base, ldap.SCOPE_SUBTREE,
                                        "(|(objectClass=groupOfNames)(objectClass=posixGroup))",
                                        ['cn', 'member', 'memberUid'])
        except ldap.NO_SUCH_OBJECT:
            return []
        groups = []
        for dn, attrs in results:
            if not dn:
                continue
            cn = attrs.get('cn', [b''])[0].decode('utf-8', 'replace') if attrs.get('cn') else ''
            members = [m.decode('utf-8', 'replace') for m in attrs.get('member', [])
                       if m.decode('utf-8', 'replace') != self.base_dn]
            groups.append({"name": cn, "dn": dn, "member_count": len(members),
                           "members": members})
        return groups

    def get_user_groups(self, uid: str, tenant_slug: Optional[str] = None) -> Dict[str, Any]:
        """Return a user's group memberships — for hub RBAC. Reads the user's
        ``memberOf`` (if the memberof overlay is enabled) AND searches groups by
        ``member=<user_dn>`` (works without the overlay); the union is returned."""
        try:
            u_dn = build_user_dn(self.base_dn, uid, tenant_slug)
            groups_base = groups_container_dn(self.base_dn, tenant_slug)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        found: Dict[str, str] = {}  # dn -> cn
        try:
            with self._conn() as conn:
                # memberOf on the user entry (present only with the memberof overlay).
                try:
                    ures = conn.search_s(u_dn, ldap.SCOPE_BASE, "(objectClass=*)", ['memberOf'])
                    for _d, a in ures:
                        for g in a.get('memberOf', []):
                            found.setdefault(g.decode('utf-8', 'replace'), '')
                except ldap.NO_SUCH_OBJECT:
                    return {"status": "ERROR", "message": f"user not found: {u_dn}"}
                # Reverse search: groups that list this user as a member.
                safe = ldap.filter.escape_filter_chars(u_dn)
                try:
                    gres = conn.search_s(groups_base, ldap.SCOPE_SUBTREE,
                                         f"(&(objectClass=groupOfNames)(member={safe}))", ['cn'])
                    for gdn, a in gres:
                        if gdn:
                            cn = a.get('cn', [b''])[0].decode('utf-8', 'replace') if a.get('cn') else ''
                            found[gdn] = cn or found.get(gdn, '')
                except ldap.NO_SUCH_OBJECT:
                    pass
        except ldap.LDAPError as e:
            logger.error(f"Error getting groups for {u_dn}: {e}")
            return {"status": "ERROR", "message": str(e)}
        groups = [{"dn": dn, "name": cn or dn.split(',')[0].split('=')[-1]}
                  for dn, cn in found.items()]
        return {"status": "SUCCESS", "dn": u_dn, "groups": groups,
                "group_dns": list(found.keys()), "count": len(groups)}

    def update_ou(self, dn: str, new_name: str) -> Dict[str, Any]:
        """Rename an OU. The new DN is derived from the new ou= RDN."""
        if not new_name:
            return {"status": "ERROR", "message": "new_name is required"}
        conn = self._get_connection()
        try:
            new_rdn = f"ou={self._escape_rdn(new_name)}"
            self._rename(conn, dn, new_rdn)
            parent = dn.split(',', 1)[1] if ',' in dn else ''
            new_dn = f"{new_rdn},{parent}" if parent else new_rdn
            return {"status": "SUCCESS", "dn": new_dn}
        except ldap.LDAPError as e:
            logger.error(f"Error renaming OU {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def update_user(self, dn: str, first_name: str = None, last_name: str = None,
                    email: str = None, username: str = None) -> Dict[str, Any]:
        """Update a user's attributes (cn/sn/givenName/mail) and optionally
        rename the uid RDN. None values are left untouched."""
        conn = self._get_connection()
        mods = []
        if first_name is not None and last_name is not None:
            mods.append((ldap.MOD_REPLACE, 'cn', [f"{first_name} {last_name}".encode('utf-8')]))
        if first_name is not None:
            mods.append((ldap.MOD_REPLACE, 'givenName', [first_name.encode('utf-8')]))
        if last_name is not None:
            mods.append((ldap.MOD_REPLACE, 'sn', [last_name.encode('utf-8')]))
        if email is not None:
            mods.append((ldap.MOD_REPLACE, 'mail', [email.encode('utf-8')]))
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
        except ldap.LDAPError as e:
            logger.error(f"Error updating user {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def update_group(self, dn: str, new_name: str) -> Dict[str, Any]:
        """Rename a group (cn RDN)."""
        if not new_name:
            return {"status": "ERROR", "message": "new_name is required"}
        conn = self._get_connection()
        try:
            new_rdn = f"cn={self._escape_rdn(new_name)}"
            self._rename(conn, dn, new_rdn)
            parent = dn.split(',', 1)[1] if ',' in dn else ''
            new_dn = f"{new_rdn},{parent}" if parent else new_rdn
            return {"status": "SUCCESS", "dn": new_dn}
        except ldap.LDAPError as e:
            logger.error(f"Error renaming group {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def search(self, query: str) -> Dict[str, Any]:
        """
        Search LDAP for users and computers matching a name, username, email, or hostname.
        Returns normalised results tagged source="ldap".
        """
        q = query.strip()
        results: List[Dict] = []
        try:
            conn = self._get_connection()
            # Escape special chars for LDAP filter
            safe_q = q.replace("\\", "\\5c").replace("*", "\\2a").replace("(", "\\28").replace(")", "\\29")
            ldap_filter = (
                f"(|"
                f"(uid=*{safe_q}*)"
                f"(cn=*{safe_q}*)"
                f"(mail=*{safe_q}*)"
                f"(sn=*{safe_q}*)"
                f"(givenName=*{safe_q}*)"
                f"(dNSHostName=*{safe_q}*)"
                f")"
            )
            attrs = ['uid', 'cn', 'sn', 'givenName', 'mail', 'objectClass', 'dNSHostName']
            raw = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, ldap_filter, attrs)
            for dn, entry in raw:
                if not dn:
                    continue
                obj_classes = [c.decode() if isinstance(c, bytes) else c
                               for c in entry.get('objectClass', [])]
                is_computer = 'computer' in obj_classes or 'device' in obj_classes
                def _d(key: str) -> str:
                    v = entry.get(key, [b''])[0]
                    return (v.decode('utf-8') if isinstance(v, bytes) else v) if v else ''
                results.append({
                    "source":   "ldap",
                    "type":     "computer" if is_computer else "user",
                    "name":     _d('cn') or _d('uid'),
                    "username": _d('uid'),
                    "email":    _d('mail'),
                    "dn":       dn,
                    "hostname": _d('dNSHostName'),
                    "id":       dn,
                })
        except Exception as e:
            logger.error(f"LDAP search failed: {e}")
            return {"status": "ERROR", "message": str(e), "results": []}
        return {"status": "SUCCESS", "results": results, "count": len(results)}
