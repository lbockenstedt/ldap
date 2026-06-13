import ldap
import ldap.filter
from typing import Any, Dict, List, Optional
import logging

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
        search_filter = "(objectClass=organizationalUnit)"
        results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, search_filter, ['dn'])

        ous = []
        for dn, attrs in results:
            if dn:
                ous.append({"dn": dn})
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
        search_filter = "(objectClass=person)"
        results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, search_filter, ['dn', 'cn', 'sn', 'mail'])

        users = []
        for dn, attrs in results:
            if dn:
                user_info = {"dn": dn}
                for attr in ['cn', 'sn', 'mail']:
                    if attr in attrs:
                        user_info[attr] = attrs[attr][0].decode('utf-8')
                users.append(user_info)
        return users

    def create_user(self, username: str, first_name: str, last_name: str, email: str, ou_dn: str) -> Dict[str, Any]:
        conn = self._get_connection()
        dn = f"uid={username},{ou_dn}"
        attrs = {
            'objectClass': [b'top', b'person', b'organizationalPerson', b'inetOrgPerson'],
            'cn': [f"{first_name} {last_name}".encode('utf-8')],
            'sn': [last_name.encode('utf-8')],
            'uid': [username.encode('utf-8')],
            'mail': [email.encode('utf-8')],
            'userPassword': [b'password123'] # Default password, should be changed
        }
        try:
            conn.add_s(dn, attrs)
            return {"status": "SUCCESS", "dn": dn}
        except ldap.LDAPError as e:
            logger.error(f"Error creating user {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def list_groups(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        search_filter = "(objectClass=groupOfNames)"
        results = conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, search_filter, ['dn', 'cn', 'member'])

        groups = []
        for dn, attrs in results:
            if dn:
                group_info = {"dn": dn}
                if 'cn' in attrs:
                    group_info['cn'] = attrs['cn'][0].decode('utf-8')
                if 'member' in attrs:
                    group_info['members'] = [m.decode('utf-8') for m in attrs['member']]
                groups.append(group_info)
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

    def delete_entity(self, dn: str) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            conn.delete_s(dn)
            return {"status": "SUCCESS"}
        except ldap.LDAPError as e:
            logger.error(f"Error deleting entity {dn}: {e}")
            return {"status": "ERROR", "message": str(e)}
