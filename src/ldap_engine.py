import ldap3
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("LdapEngine")

class LdapEngine:
    """
    Low-level API interaction with an LDAP server using ldap3.
    """
    def __init__(self, url: str, bind_dn: str, password: str):
        self.url = url
        self.bind_dn = bind_dn
        self.password = password
        self.server = ldap3.Server(self.url, get_info=ldap3.ALL)
        self.conn = None

        # Attempt initial connection
        self._connect()

    def _connect(self):
        try:
            self.conn = ldap3.Connection(
                self.server,
                user=self.bind_dn,
                password=self.password,
                auto_bind=True
            )
            logger.info(f"Successfully bound to LDAP server at {self.url}")
        except Exception as e:
            logger.error(f"LDAP bind failed: {e}")
            self.conn = None

    def ensure_connection(self):
        if self.conn is None or not self.conn.bound:
            self._connect()
        return self.conn is not None

    def add_user(self, username: str, first_name: str, last_name: str, ou: str = "users") -> Dict[str, Any]:
        """
        Creates a new user entry in LDAP.
        """
        if not self.ensure_connection():
            return {"status": "ERROR", "message": "LDAP connection unavailable"}

        dn = f"uid={username},ou={ou},dc=lab,dc=local" # Example base DN
        attrs = {
            'cn': f"{first_name} {last_name}",
            'sn': last_name,
            'givenName': first_name,
            'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
            'userPassword': 'ChangeMe123!' # Default password
        }

        try:
            if self.conn.add(dn, attributes=attrs):
                logger.info(f"Added user {username} to LDAP")
                return {"status": "SUCCESS", "dn": dn}
            else:
                logger.error(f"Failed to add user {username}: {self.conn.result}")
                return {"status": "ERROR", "message": str(self.conn.result)}
        except Exception as e:
            logger.error(f"Exception adding user {username}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def add_group(self, group_name: str, members: list = None, ou: str = "groups") -> Dict[str, Any]:
        """
        Creates a new group in LDAP.
        """
        if not self.ensure_connection():
            return {"status": "ERROR", "message": "LDAP connection unavailable"}

        dn = f"cn={group_name},ou={ou},dc=lab,dc=local"
        attrs = {
            'objectClass': ['top', 'groupOfNames'],
            'member': members or []
        }

        try:
            if self.conn.add(dn, attributes=attrs):
                logger.info(f"Added group {group_name} to LDAP")
                return {"status": "SUCCESS", "dn": dn}
            else:
                logger.error(f"Failed to add group {group_name}: {self.conn.result}")
                return {"status": "ERROR", "message": str(self.conn.result)}
        except Exception as e:
            logger.error(f"Exception adding group {group_name}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def get_system_health(self) -> Dict[str, Any]:
        """Checks if LDAP server is reachable and bound."""
        try:
            if self.ensure_connection():
                return {"status": "SUCCESS", "reachable": True}
            return {"status": "ERROR", "message": "Could not bind to LDAP"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}
