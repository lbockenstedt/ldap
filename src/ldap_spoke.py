import asyncio
import logging
from typing import Any, Dict
try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

from .ldap_manager import LdapManager

logger = logging.getLogger("LdapSpoke")

class LdapSpoke(BaseSpoke):
    """
    LDAP integration spoke. Hosts the LDAP server and provides a management API.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any], control_plane=None):
        super().__init__(spoke_id, config)
        self.manager = LdapManager(
            admin_dn=self.config.get("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
            admin_pw=self.config.get("LDAP_ADMIN_PW", "admin"),
            base_dn=self.config.get("LDAP_BASE_DN", "dc=example,dc=org"),
            server_url=self.config.get("LDAP_SERVER_URL", "ldap://localhost:389")
        )

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        # Normalize command type to uppercase for case-insensitive matching
        normalized_cmd = command_type.upper()

        if normalized_cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if normalized_cmd == "UPDATE_CONFIG":
            logger.info(f"Updating LDAP configuration: {data}")
            self.config = data
            # Re-initialize manager with new config
            self.manager = LdapManager(
                admin_dn=self.config.get("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
                admin_pw=self.config.get("LDAP_ADMIN_PW", "admin"),
                base_dn=self.config.get("LDAP_BASE_DN", "dc=example,dc=org"),
                server_url=self.config.get("LDAP_SERVER_URL", "ldap://localhost:389")
            )
            return {"status": "SUCCESS", "message": "LDAP configuration updated"}

        # LDAP Management Commands
        if normalized_cmd == "LIST_OUS":
            return {"status": "SUCCESS", "data": self.manager.list_ous()}

        if normalized_cmd == "CREATE_OU":
            return self.manager.create_ou(data.get("name"), data.get("parent_dn"))

        if normalized_cmd == "LIST_USERS":
            return {"status": "SUCCESS", "data": self.manager.list_users()}

        if normalized_cmd == "CREATE_USER":
            return self.manager.create_user(
                data.get("username"),
                data.get("first_name"),
                data.get("last_name"),
                data.get("email"),
                data.get("ou_dn")
            )

        if normalized_cmd == "LIST_GROUPS":
            return {"status": "SUCCESS", "data": self.manager.list_groups()}

        if normalized_cmd == "CREATE_GROUP":
            return self.manager.create_group(data.get("name"), data.get("ou_dn"))

        if normalized_cmd == "ADD_USER_TO_GROUP":
            return self.manager.add_user_to_group(data.get("user_dn"), data.get("group_dn"))

        if normalized_cmd == "REMOVE_USER_FROM_GROUP":
            return self.manager.remove_user_from_group(data.get("user_dn"), data.get("group_dn"))

        if normalized_cmd == "DELETE_ENTITY":
            return self.manager.delete_entity(data.get("dn"))

        logger.warning(f"Unknown command received: {command_type}")
        return {"status": "ERROR", "message": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        """Reports LDAP server status."""
        try:
            # Simple check to see if we can connect
            self.manager._get_connection()
            return {"status": "HEALTHY", "server": "OpenLDAP Online"}
        except Exception as e:
            logger.error(f"LDAP server health check failed: {e}")
            return {"status": "UNHEALTHY", "error": str(e)}

    def get_version(self) -> str:
        """Returns the current version of the LDAP module."""
        return "1.0.0"
