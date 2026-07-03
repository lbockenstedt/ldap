import asyncio
import logging
import os
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple
try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

from .ldap_manager import LdapManager

logger = logging.getLogger("LdapSpoke")


class _CertInstallError(Exception):
    """A failed cert-install step (ldapmodify / slapd restart). Raised inside
    install_cert so it maps to a single ERROR result with a clear message."""

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

        if normalized_cmd == "UPDATE_OU":
            return self.manager.update_ou(data.get("dn"), data.get("name"))

        if normalized_cmd == "LIST_USERS":
            return {"status": "SUCCESS", "data": self.manager.list_users()}

        if normalized_cmd == "CREATE_USER":
            return self.manager.create_user(
                data.get("username"),
                data.get("first_name"),
                data.get("last_name"),
                data.get("email"),
                data.get("ou_dn"),
                password=data.get("password")
            )

        if normalized_cmd == "UPDATE_USER":
            return self.manager.update_user(
                data.get("dn"),
                data.get("first_name"),
                data.get("last_name"),
                data.get("email"),
                data.get("username"),
            )

        if normalized_cmd == "LIST_GROUPS":
            return {"status": "SUCCESS", "data": self.manager.list_groups()}

        if normalized_cmd == "CREATE_GROUP":
            return self.manager.create_group(data.get("name"), data.get("ou_dn"))

        if normalized_cmd == "UPDATE_GROUP":
            return self.manager.update_group(data.get("dn"), data.get("name"))

        if normalized_cmd == "ADD_USER_TO_GROUP":
            return self.manager.add_user_to_group(data.get("user_dn"), data.get("group_dn"))

        if normalized_cmd == "REMOVE_USER_FROM_GROUP":
            return self.manager.remove_user_from_group(data.get("user_dn"), data.get("group_dn"))

        if normalized_cmd == "SET_PASSWORD":
            user_dn = data.get("user_dn") or data.get("dn")
            password = data.get("password") or data.get("new_password")
            if not user_dn or not password:
                return {"status": "ERROR", "message": "Missing user_dn or password"}
            return self.manager.set_password(user_dn, password)

        if normalized_cmd == "DELETE_ENTITY":
            return self.manager.delete_entity(data.get("dn"))

        if normalized_cmd == "SEARCH_USERS":
            return self.manager.search(data.get("q", ""))

        if normalized_cmd == "INSTALL_CERT":
            # Hub-brokered Let's Encrypt cert install. The le spoke issued/
            # renewed a cert and the hub pushes the PEM here; we write the
            # leaf/CA/key to /etc/ldap/tls, point slapd's olcTLS* at them via
            # `ldapmodify -Y EXTERNAL -H ldapi:///` on cn=config, and restart
            # slapd so the new SSL context takes effect. The spoke runs as root
            # (install_ldap.sh User=root) — EXTERNAL over ldapi maps root to
            # cn=config write, and the restart needs root. `ca` (the chain) is
            # appended to the CA bundle; intermediates already in fullchain are
            # split out so the leaf goes to olcTLSCertificateFile alone.
            return await self.install_cert(
                data.get("fullchain", ""), data.get("privkey", ""),
                ca_pem=data.get("chain", ""))

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
        """Returns the current version of the LDAP module (from the VERSION file)."""
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"

    # ── TLS certificate install (hub-brokered, INSTALL_CERT) ───────────────
    # slapd reads its TLS cert/key/CA from FILE PATHS (no inline PEM), so we
    # write the PEM to /etc/ldap/tls and point olcTLSCertificateFile /
    # olcTLSCertificateKeyFile / olcTLSCACertificateFile (global attrs on
    # cn=config) at them via `ldapmodify -Y EXTERNAL -H ldapi:///` with
    # `replace:`, then restart slapd — the new SSL context only reliably takes
    # effect on restart (OpenLDAP ITS#6135). The key must be readable by the
    # slapd user (Debian: openldap) or slapd errors with opaque "error 80".

    @staticmethod
    def _split_chain(fullchain: str) -> Tuple[str, List[str]]:
        """Split a PEM fullchain into (leaf, [intermediate/root blocks]).

        The leaf (first CERTIFICATE block) goes to olcTLSCertificateFile; the
        remaining blocks go to the CA bundle (olcTLSCACertificateFile). Order
        in the CA bundle is not significant per the OpenLDAP admin guide."""
        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            (fullchain or "").strip(), re.DOTALL)
        if not blocks:
            return "", []
        return blocks[0] + "\n", [b + "\n" for b in blocks[1:]]

    @staticmethod
    def _build_tls_ldif(cert_path: str, key_path: str,
                        ca_path: Optional[str] = None) -> str:
        """LDIF to replace slapd's olcTLS* file paths on cn=config. Uses
        ``replace:`` (idempotent — works whether or not the attrs already
        exist; ``add:`` would fail with 'Type or value exists' on a renew)."""
        blocks = [
            "dn: cn=config",
            "changetype: modify",
            "replace: olcTLSCertificateFile",
            f"olcTLSCertificateFile: {cert_path}",
            "-",
            "replace: olcTLSCertificateKeyFile",
            f"olcTLSCertificateKeyFile: {key_path}",
        ]
        if ca_path:
            blocks += ["-", "replace: olcTLSCACertificateFile",
                       f"olcTLSCACertificateFile: {ca_path}"]
        return "\n".join(blocks) + "\n"

    async def install_cert(self, fullchain: str, privkey: str,
                           ca_pem: str = "") -> Dict[str, Any]:
        """Install a Let's Encrypt cert as slapd's TLS server cert.

        Writes the leaf to the cert file (0644), intermediates (+ any supplied
        ``ca`` chain) to the CA bundle (0644), and the key to the key file
        (0600, chowned to the slapd user), then runs ldapmodify against cn=config
        and restarts slapd. The private key is written to a 0600 file slapd
        reads — it is never logged. Paths/owner/restart are configurable via
        LDAP_TLS_DIR / LDAP_TLS_CERT / LDAP_TLS_KEY / LDAP_TLS_CA /
        LDAP_SLAPD_USER / LDAP_TLS_RESTART."""
        fullchain = (fullchain or "").strip()
        privkey = (privkey or "").strip()
        if not fullchain or "BEGIN CERTIFICATE" not in fullchain:
            return {"status": "ERROR", "message": "missing or invalid fullchain PEM"}
        if not privkey or "PRIVATE KEY" not in privkey:
            return {"status": "ERROR", "message": "missing or invalid private key PEM"}

        cfg = self.config or {}
        cert_dir = cfg.get("LDAP_TLS_DIR", "/etc/ldap/tls")
        cert_path = cfg.get("LDAP_TLS_CERT", f"{cert_dir}/slapd-cert.pem")
        key_path = cfg.get("LDAP_TLS_KEY", f"{cert_dir}/slapd-key.pem")
        slapd_user = cfg.get("LDAP_SLAPD_USER", "openldap")
        do_restart = cfg.get("LDAP_TLS_RESTART", True)
        leaf, cas = self._split_chain(fullchain)
        ca_blocks = cas + ([ca_pem.strip()] if ca_pem and ca_pem.strip() else [])
        ca_path = cfg.get("LDAP_TLS_CA", f"{cert_dir}/slapd-ca.pem") if ca_blocks else None

        try:
            os.makedirs(cert_dir, exist_ok=True)
            self._write_pem(cert_path, leaf, 0o644)
            if ca_path:
                self._write_pem(ca_path, "".join(ca_blocks), 0o644)
            self._write_pem(key_path, privkey, 0o600)
            # Key must be readable by the slapd user or slapd errors with the
            # opaque "implementation specific error (80)". Best-effort: a
            # missing/non-standard user logs a warning and proceeds (ldapmodify
            # will then surface the read failure as error 80).
            try:
                shutil.chown(key_path, user=slapd_user)
            except (LookupError, PermissionError, OSError) as e:
                logger.warning("INSTALL_CERT: could not chown key to '%s' (%s); "
                               "slapd may fail to read it (error 80)", slapd_user, e)

            ldif = self._build_tls_ldif(cert_path, key_path, ca_path)
            await self._ldapmodify(ldif)

            if do_restart:
                await self._restart_slapd()
            logger.info("INSTALL_CERT: slapd TLS cert installed (cert=%s)", cert_path)
            return {"status": "SUCCESS",
                    "message": f"slapd TLS cert installed ({cert_path})"}
        except _CertInstallError as e:
            return {"status": "ERROR", "message": str(e)}
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"install_cert failed: {str(e)[:300]}"}

    @staticmethod
    def _write_pem(path: str, content: str, mode: int) -> None:
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)

    async def _ldapmodify(self, ldif: str) -> None:
        """Apply an LDIF to cn=config via SASL EXTERNAL over ldapi:/// (root
        peer-cred → cn=config write). Raises _CertInstallError on failure."""
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=ldif.encode()), timeout=30)
        if proc.returncode != 0:
            err = (stderr.decode().strip() or stdout.decode().strip()
                   or f"ldapmodify exited {proc.returncode}")
            raise _CertInstallError(f"ldapmodify failed: {err[:300]}")

    async def _restart_slapd(self) -> None:
        """Restart slapd so the new TLS context takes effect (OpenLDAP ITS#6135:
        global TLS settings via cn=config only reliably apply on restart)."""
        proc = await asyncio.create_subprocess_exec(
            "systemctl", "restart", "slapd",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
        if proc.returncode != 0:
            err = stderr.decode().strip() or f"systemctl exited {proc.returncode}"
            raise _CertInstallError(f"slapd restart failed: {err[:300]}")