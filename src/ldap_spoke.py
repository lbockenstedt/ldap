<<<<<<< HEAD
import asyncio
import logging
from typing import Any, Dict
try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

from .ldap_manager import LdapManager
=======
import logging
from typing import Dict, Any
from lm.hub.src.base_spoke import BaseSpoke
from .ldap_engine import LdapEngine
>>>>>>> 1b24d1f (Update LDAP module and configuration)

logger = logging.getLogger("LdapSpoke")

class LdapSpoke(BaseSpoke):
    """
<<<<<<< HEAD
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
=======
    LDAP Identity Management Spoke for Lab Manager.
    Translates Hub commands into LDAP directory operations.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        # Initialize Engine using config credentials
        self.engine = LdapEngine(
            url=config.get("ldap_url", "ldap://localhost"),
            bind_dn=config.get("bind_dn", "cn=admin,dc=lab,dc=local"),
            password=config.get("bind_password")
        )

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"Handling Ldap Command: {command_type} with data {data}")

>>>>>>> 1b24d1f (Update LDAP module and configuration)
        normalized_cmd = command_type.upper()

        if normalized_cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

<<<<<<< HEAD
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
=======
        if command_type == "LDAP_ADD_USER":
            # Data expected: {"username": "jdoe", "first_name": "John", "last_name": "Doe"}
            return self.engine.add_user(
                data.get("username"),
                data.get("first_name"),
                data.get("last_name")
            )


        elif command_type == "LDAP_ADD_GROUP":
            # Data expected: {"group_name": "admins", "members": ["uid=jdoe,..."]}
            return self.engine.add_group(
                data.get("group_name"),
                data.get("members")
            )

        else:
            logger.warning(f"Unknown Ldap command type: {command_type}")
            return {"status": "ERROR", "message": f"Command {command_type} not supported by ldap module"}

    async def get_status(self) -> Dict[str, Any]:
        """Native LM status report for the LDAP instance."""
        health = self.engine.get_system_health()
        return {
            "spoke_id": self.spoke_id,
            "module": "ldap-mgmt",
            "api_health": health,
            "connection": "CONNECTED" if health.get("status") == "SUCCESS" else "DISCONNECTED"
        }

    def get_version(self) -> str:
        """Returns the current version of the Ldap module."""
>>>>>>> 1b24d1f (Update LDAP module and configuration)
        return "1.0.0"
