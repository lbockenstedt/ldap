"""Entry point that connects the LDAP directory spoke to the Lab Manager hub.

Loads LDAP and Entra settings from the environment / .env, builds the
LdapSpoke command handler and runs the shared hub WebSocket control plane.
"""
# Dependency self-heal — MUST run before the third-party imports below. A skewed
# auto-update / partial install can leave the venv missing a declared dep, which
# would hard-crash at import and crash-loop the unit under Restart=always.
# dep_guard is stdlib-only; it find_spec-checks requirements.txt and pip-installs
# any missing. Best-effort — an unavailable dep_guard is skipped, never fatal.
# Imported under a private alias so it does not clash with the normal imports below.
import os as _os
# Best-effort: make sure every package in requirements.txt is installed before importing it.
try:
    # Prefer the shared core package path; fall back to a flat install layout.
    try:
        from core.src.dep_guard import ensure_requirements as _ensure_requirements
    except ImportError:
        from dep_guard import ensure_requirements as _ensure_requirements
    # requirements.txt sits one directory above this file (the repo root).
    _ensure_requirements(_os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "requirements.txt"))
# Self-heal is optional; never stop the spoke from starting because of it.
except Exception:
    pass

# asyncio runs the hub loop; logging/argparse/os handle logs, CLI and settings.
import asyncio
import logging
import argparse
import os
# Type hint only.
from typing import Any
# Shared hub-link base class; the import path differs between layouts.
try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane
# The LDAP command handler and the .env loader.
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
        # Log line format and timestamp format used by every spoke.
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=logging.INFO, *, log_file=None, **_):
            """Fallback logging setup: console output, plus a log file when one is given."""
            # Log to both a file and the console only when a log file was requested.
            handlers = ([logging.FileHandler(log_file), logging.StreamHandler()]
                        if log_file else None)
            # force=True replaces any handlers configured earlier.
            logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
# Configure logging before anything else logs, then get this module's logger.
configure_logging()
logger = logging.getLogger("LdapControlPlane")

class LdapControlPlane(BaseControlPlane):
    """Control plane for the LDAP directory spoke (module_type "directory")."""
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        """Set up hub identity and load LDAP/Entra settings from the environment.

        Args:
            spoke_id: This spoke's identity at the hub.
            secret: Shared secret used to authenticate with the hub.
            hub_secret: Optional hub secret for mutual authentication.
            hub_url: WebSocket URL of the hub.
        """
        # Let the base class set up identity, secrets and the hub URL.
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        # The hub treats this spoke as a directory service.
        self.module_type = "directory"

        # Load config from .env if present
        load_dotenv()
        # Settings passed to LdapSpoke, each with a safe default when unset.
        self.config = {
            "LDAP_ADMIN_DN": os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
            "LDAP_ADMIN_PW": os.getenv("LDAP_ADMIN_PW", ""),
            "LDAP_BASE_DN": os.getenv("LDAP_BASE_DN", "dc=example,dc=org"),
            "LDAP_SERVER_URL": os.getenv("LDAP_SERVER_URL", "ldap://localhost:389"),
            # 2-node syncrepl mirror-mode (int 1|2 + JSON list of peer URLs).
            "LDAP_SERVER_ID": os.getenv("LDAP_SERVER_ID", ""),
            "LDAP_MIRROR_PEERS": os.getenv("LDAP_MIRROR_PEERS", ""),
            # Entra ROPC pass-through (cert-based confidential client).
            "ENTRA_TENANT_ID": os.getenv("ENTRA_TENANT_ID", ""),
            "ENTRA_CLIENT_ID": os.getenv("ENTRA_CLIENT_ID", ""),
            "ENTRA_CLIENT_CERT": os.getenv("ENTRA_CLIENT_CERT", ""),
            "ENTRA_CLIENT_KEY": os.getenv("ENTRA_CLIENT_KEY", ""),
            "ENTRA_ROPC_SCOPE": os.getenv("ENTRA_ROPC_SCOPE", "openid"),
        }
        # Without the admin password no LDAP operation can succeed; warn loudly.
        if not self.config["LDAP_ADMIN_PW"]:
            logger.warning(
                "LDAP_ADMIN_PW is not set. The spoke cannot bind to the LDAP server "
                "until it is configured in .env (must match your slapd admin password)."
            )

    def register_module(self, name: str, module_instance: Any):
        """Register a spoke module so hub commands addressed to `name` reach it."""
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    def get_service_name(self) -> str:
        """Systemd service name the Hub restarts on self-update."""
        return "lm-ldap"

    async def run(self):
        """Native LM Spoke behavior."""
        # Announce which hub this spoke is connecting to.
        logger.info(f"Starting LDAP Module in HUB MODE -> {self.hub_url}")

        # Create and register the LDAP module
        ldap_spoke = LdapSpoke(self.spoke_id, self.config)
        self.register_module("ldap", ldap_spoke)

        # Hand over to the base class connection/heartbeat/dispatch loop.
        await super().run()

if __name__ == "__main__":
    # Command-line flags: spoke identity, secrets and the hub URL.
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Spoke ID")
    parser.add_argument("--secret", default=os.getenv("SPOKE_SECRET", ""),
                        help="Authentication secret (omit for zero-touch provisioning)")
    parser.add_argument("--hub-secret", nargs='?', default="", const="", help="Hub authentication secret for mutual auth")
    parser.add_argument("--hub", required=True, help="Hub WebSocket URL")
    # Read the flags the user passed.
    args = parser.parse_args()

    # Build the control plane and run it until the process is stopped.
    cp = LdapControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
