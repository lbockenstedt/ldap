import ldap
import ldap.filter
from typing import Any, Dict, List, Optional
import logging
import secrets

logger = logging.getLogger("LdapManager")

class LdapManager:
    def __init__(self, admin_dn: str, admin_pw: str, base_dn: str, server_url: str = "ldap://localhost:389"):
        self.admin_dn = admin_dn
        self.admin_pw = admin_pw
        self.base_dn = base_dn
        self.server = server_url

    def _get_connection(self):
        conn = ldap.initialize(self.server)
        conn.simple_bind_s(self.admin_dn, self.admin_pw)
        return conn

    def list_ous(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(objectClass=organizationalUnit)", ['ou', 'description'])
        ous = []
        for dn, attrs in results:
            if dn:
                ou_name = attrs.get('ou', [b''])[0].decode('utf-8') if attrs.get('ou') else dn.split(',')[0].split('=')[-1]
                ous.append({"name": ou_name, "dn": dn})
        return ous

    def create_ou(self, ou_name: str, parent_dn: str = None) -> Dict[str, Any]:
        conn = self._get_connection()
        dn = f"ou={ou_name},{parent_dn if parent_dn else self.base_dn}"
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
        conn = self._get_connection()
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
        dn = f"uid={username},{ou_dn}"
        # Use a caller-provided password, or generate a strong random one (never a hardcoded default).
        user_password = password or secrets.token_urlsafe(16)
        attrs = {
            'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
            'cn': [f"{first_name} {last_name}".encode('utf-8')],
            'sn': [last_name.encode('utf-8')],
            'uid': [username.encode('utf-8')],
            'mail': [email.encode('utf-8')],
            'userPassword': [user_password.encode('utf-8')]
        }
        try:
            conn.add_s(dn, attrs)
            # Return the generated/provided password so the operator can deliver it securely.
            return {"status": "SUCCESS", "dn": dn, "password": user_password}
        except ldap.LDAPError as e:
            logger.error(f"Error creating user {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def list_groups(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
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
        dn = f"cn={group_name},{ou_dn}"
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
                conn.modify_s(user_dn, [(ldap.MOD_REPLACE, 'userPassword', [new_password.encode('utf-8')])])
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

    def update_ou(self, dn: str, new_name: str) -> Dict[str, Any]:
        """Rename an OU. The new DN is derived from the new ou= RDN."""
        if not new_name:
            return {"status": "ERROR", "message": "new_name is required"}
        conn = self._get_connection()
        try:
            new_rdn = f"ou={new_name}"
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
                    self._rename(conn, dn, f"uid={username}")
                    parent = dn.split(',', 1)[1] if ',' in dn else ''
                    new_dn = f"uid={username},{parent}" if parent else f"uid={username}"
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
            new_rdn = f"cn={new_name}"
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
