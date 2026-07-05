# Dependency self-heal — MUST run before the third-party imports below. A skewed
# auto-update / partial install can leave the venv missing a declared dep, which
# would hard-crash at import and crash-loop the unit under Restart=always.
# dep_guard is stdlib-only; it find_spec-checks requirements.txt and pip-installs
# any missing. Best-effort — an unavailable dep_guard is skipped, never fatal.
import os as _os
try:
    try:
        from core.src.dep_guard import ensure_requirements as _ensure_requirements
    except ImportError:
        from dep_guard import ensure_requirements as _ensure_requirements
    _ensure_requirements(_os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "requirements.txt"))
except Exception:
    pass

import asyncio
import json
import logging
import argparse
import os
from typing import Any, Dict, Optional
try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane
from src.ldap_spoke import LdapSpoke
from dotenv import load_dotenv

# Shared logging setup (standard format + LOG_LEVEL env + line buffering) so
# every module logs identically; falls back to an equivalent inline config when
# lm core isn't importable. See logging-observability-contract.md (normalization).
try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=logging.INFO, *, log_file=None, **_):
            handlers = ([logging.FileHandler(log_file), logging.StreamHandler()]
                        if log_file else None)
            logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
configure_logging()
logger = logging.getLogger("LdapControlPlane")

class LdapControlPlane(BaseControlPlane):
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self.module_type = "directory"

        # Load config from .env if present
        load_dotenv()
        self.config = {
            "LDAP_ADMIN_DN": os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
            "LDAP_ADMIN_PW": os.getenv("LDAP_ADMIN_PW", ""),
            "LDAP_BASE_DN": os.getenv("LDAP_BASE_DN", "dc=example,dc=org"),
            "LDAP_SERVER_URL": os.getenv("LDAP_SERVER_URL", "ldap://localhost:389"),
        }
        if not self.config["LDAP_ADMIN_PW"]:
            logger.warning(
                "LDAP_ADMIN_PW is not set. The spoke cannot bind to the LDAP server "
                "until it is configured in .env (must match your slapd admin password)."
            )

    def register_module(self, name: str, module_instance: Any):
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    def get_service_name(self) -> str:
        """Systemd service name the Hub restarts on self-update."""
        return "lm-ldap"

    async def run(self):
        """Native LM Spoke behavior."""
        logger.info(f"Starting LDAP Module in HUB MODE -> {self.hub_url}")

        # Create and register the LDAP module
        ldap_spoke = LdapSpoke(self.spoke_id, self.config)
        self.register_module("ldap", ldap_spoke)

        await super().run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Spoke ID")
    parser.add_argument("--secret", default=os.getenv("SPOKE_SECRET", ""),
                        help="Authentication secret (omit for zero-touch provisioning)")
    parser.add_argument("--hub-secret", nargs='?', default="", const="", help="Hub authentication secret for mutual auth")
    parser.add_argument("--hub", required=True, help="Hub WebSocket URL")
    args = parser.parse_args()

    cp = LdapControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
