import asyncio
import json
import logging
import argparse
import os
import threading
import subprocess
import git
from typing import Any, Dict, Optional
from core.src.messaging.control_plane import BaseControlPlane
from src.ldap_spoke import LdapSpoke
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LdapControlPlane")

def get_version():
    try:
        with open("VERSION", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "unknown"

version = get_version()

def check_for_updates():
    try:
        self_repo = git.Repo(os.getcwd())
        old_commit = self_repo.head.commit.hexsha
        self_repo.remotes.origin.pull()
        new_commit = self_repo.head.commit.hexsha
        if old_commit != new_commit:
            logger.info(f"New version detected! {old_commit[:7]} -> {new_commit[:7]}. Triggering restart...")
            subprocess.Popen(["sudo", "systemctl", "restart", "lm-ldap"])
            return True
        return False
    except Exception as e:
        logger.warning(f"Self-update check failed: {e}")
        return False

def updater_worker():
    while True:
        try:
            logger.info("Checking for self-updates...")
            check_for_updates()
        except Exception as e:
            logger.error(f"Updater worker error: {e}")
        time.sleep(3600)

class LdapControlPlane(BaseControlPlane):
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        super().__init__(spoke_id, secret, hub_secret, hub_url)

        # Load config from .env if present
        load_dotenv()
        self.config = {
            "LDAP_ADMIN_DN": os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
            "LDAP_ADMIN_PW": os.getenv("LDAP_ADMIN_PW", "admin"),
            "LDAP_BASE_DN": os.getenv("LDAP_BASE_DN", "dc=example,dc=org"),
            "LDAP_SERVER_URL": os.getenv("LDAP_SERVER_URL", "ldap://localhost:389"),
        }

    def register_module(self, name: str, module_instance: Any):
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    async def run(self):
        """Native LM Spoke behavior."""
        logger.info(f"Initializing module version: {version}")
        logger.info(f"Starting LDAP Module in HUB MODE -> {self.hub_url}")

        # Start update worker
        threading.Thread(target=updater_worker, daemon=True).start()

        # Create and register the LDAP module
        ldap_spoke = LdapSpoke(self.spoke_id, self.config)
        self.register_module("ldap", ldap_spoke)

        await super().run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Spoke ID")
    parser.add_argument("--secret", required=True, help="Authentication secret")
    parser.add_argument("--hub-secret", help="Hub authentication secret for mutual auth")
    parser.add_argument("--hub", required=True, help="Hub WebSocket URL")
    args = parser.parse_args()

    cp = LdapControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
