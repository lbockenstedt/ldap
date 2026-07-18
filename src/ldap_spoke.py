import asyncio
import json
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

from .ldap_manager import LdapManager
try:
    from . import replication
except ImportError:  # loaded outside the src package
    import replication

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
        """Dispatch a hub command to the matching ``LdapManager`` method.

        Command type is matched case-insensitively. The blocking
        ``python-ldap`` calls run via :func:`asyncio.to_thread` so a slow or
        unreachable slapd cannot stall the event loop (which would freeze this
        spoke's heartbeats and get it disconnected). ``GET_VERSION`` and
        ``UPDATE_CONFIG`` are handled inline; ``INSTALL_CERT`` is async-native
        (subprocess + filesystem writes). Returns ``{"status": "SUCCESS"|"ERROR", ...}``."""
        # Normalize command type to uppercase for case-insensitive matching
        normalized_cmd = command_type.upper()

        if normalized_cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if normalized_cmd == "UPDATE_CONFIG":
            # Redact secrets before logging (admin pw, entra client key/cert path
            # are sensitive-ish; the admin pw certainly).
            logger.info("Updating LDAP configuration (keys: %s)", sorted(data.keys()))
            self.config = data
            # Re-initialize manager with new config
            self.manager = LdapManager(
                admin_dn=self.config.get("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
                admin_pw=self.config.get("LDAP_ADMIN_PW", "admin"),
                base_dn=self.config.get("LDAP_BASE_DN", "dc=example,dc=org"),
                server_url=self.config.get("LDAP_SERVER_URL", "ldap://localhost:389")
            )
            notes = []
            # Entra ROPC config changes: persist to .env so the pam_exec ROPC
            # bridge (src/entra_ropc_auth.py) picks them up on the next bind. No
            # slapd restart needed (the script reads .env live per-bind).
            if any(k.startswith("ENTRA_") for k in data) or "LDAP_BASE_DN" in data:
                try:
                    self._persist_env(data)
                    notes.append("entra .env persisted")
                except Exception as e:  # noqa: BLE001
                    logger.warning("UPDATE_CONFIG: could not persist .env: %s", e)
                    notes.append(f"env persist failed: {str(e)[:120]}")
            # Mirror-mode replication changes: re-apply cn=config idempotently.
            # Best-effort (only works when co-located on the slapd host as root);
            # a failure is logged + surfaced but does not fail the config update.
            if data.get("LDAP_SERVER_ID") and data.get("LDAP_MIRROR_PEERS"):
                repl = await self._apply_replication_config(data)
                notes.append(repl)
            return {"status": "SUCCESS", "message": "LDAP configuration updated",
                    "notes": notes}

        # LDAP Management Commands. The python-ldap calls are SYNC + blocking, so
        # run each in a worker thread — a slow/unreachable slapd must not stall the
        # asyncio event loop, which would freeze this spoke's heartbeats and get it
        # disconnected by the hub (and queue every other command behind it).
        if normalized_cmd == "LIST_OUS":
            return {"status": "SUCCESS", "data": await asyncio.to_thread(self.manager.list_ous)}

        if normalized_cmd == "CREATE_OU":
            return await asyncio.to_thread(self.manager.create_ou, data.get("name"), data.get("parent_dn"))

        if normalized_cmd == "UPDATE_OU":
            return await asyncio.to_thread(self.manager.update_ou, data.get("dn"), data.get("name"))

        if normalized_cmd == "LIST_USERS":
            return {"status": "SUCCESS", "data": await asyncio.to_thread(self.manager.list_users)}

        if normalized_cmd == "CREATE_USER":
            return await asyncio.to_thread(
                self.manager.create_user,
                data.get("username"), data.get("first_name"), data.get("last_name"),
                data.get("email"), data.get("ou_dn"), data.get("password"))

        if normalized_cmd == "UPDATE_USER":
            return await asyncio.to_thread(
                self.manager.update_user,
                data.get("dn"), data.get("first_name"), data.get("last_name"),
                data.get("email"), data.get("username"))

        if normalized_cmd == "LIST_GROUPS":
            return {"status": "SUCCESS", "data": await asyncio.to_thread(self.manager.list_groups)}

        if normalized_cmd == "CREATE_GROUP":
            return await asyncio.to_thread(self.manager.create_group, data.get("name"), data.get("ou_dn"))

        if normalized_cmd == "UPDATE_GROUP":
            return await asyncio.to_thread(self.manager.update_group, data.get("dn"), data.get("name"))

        if normalized_cmd == "ADD_USER_TO_GROUP":
            return await asyncio.to_thread(self.manager.add_user_to_group, data.get("user_dn"), data.get("group_dn"))

        if normalized_cmd == "REMOVE_USER_FROM_GROUP":
            return await asyncio.to_thread(self.manager.remove_user_from_group, data.get("user_dn"), data.get("group_dn"))

        if normalized_cmd == "SET_PASSWORD":
            user_dn = data.get("user_dn") or data.get("dn")
            password = data.get("password") or data.get("new_password")
            if not user_dn or not password:
                return {"status": "ERROR", "message": "Missing user_dn or password"}
            return await asyncio.to_thread(self.manager.set_password, user_dn, password)

        if normalized_cmd == "DELETE_ENTITY":
            return await asyncio.to_thread(self.manager.delete_entity, data.get("dn"))

        if normalized_cmd == "SEARCH_USERS":
            return await asyncio.to_thread(self.manager.search, data.get("q", ""))

        if normalized_cmd == "LDAP_MIGRATE_TENANT":
            # Cross-tenant migration: re-home entries from source_base_dn to
            # target_base_dn (a tenant's ldap_base_dn changed).
            return await asyncio.to_thread(
                self.manager.migrate_tenant,
                data.get("source_base_dn", ""), data.get("target_base_dn", ""),
                bool(data.get("purge_source", False)))

        # ── Tenant-scoped commands (LDAP_* contract; TENANT == OU 1:1) ─────
        # All accept an optional tenant_slug; absent = base level (back-compat).
        if normalized_cmd == "LDAP_PROVISION_TENANT_OU":
            return await asyncio.to_thread(
                self.manager.provision_tenant_ou, data.get("tenant_slug"))

        if normalized_cmd == "LDAP_CREATE_USER":
            return await asyncio.to_thread(
                self.manager.create_user_scoped,
                data.get("uid"), data.get("attrs") or {}, data.get("tenant_slug"),
                data.get("auth_mode", "local"), data.get("upn"), data.get("password"))

        if normalized_cmd == "LDAP_UPDATE_USER":
            return await asyncio.to_thread(
                self.manager.update_user_scoped,
                data.get("uid"), data.get("attrs") or {}, data.get("tenant_slug"))

        if normalized_cmd == "LDAP_DELETE_USER":
            return await asyncio.to_thread(
                self.manager.delete_user_scoped,
                data.get("uid"), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_SET_PASSWORD":
            return await asyncio.to_thread(
                self.manager.set_password_scoped,
                data.get("uid"), data.get("password"), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_CREATE_GROUP":
            return await asyncio.to_thread(
                self.manager.create_group_scoped,
                data.get("cn") or data.get("name"), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_ADD_MEMBER":
            return await asyncio.to_thread(
                self.manager.add_member_scoped,
                data.get("uid"), data.get("group") or data.get("cn"),
                data.get("tenant_slug"))

        if normalized_cmd == "LDAP_REMOVE_MEMBER":
            return await asyncio.to_thread(
                self.manager.remove_member_scoped,
                data.get("uid"), data.get("group") or data.get("cn"),
                data.get("tenant_slug"))

        if normalized_cmd == "LDAP_LIST_USERS":
            return {"status": "SUCCESS", "data": await asyncio.to_thread(
                self.manager.list_users_scoped, data.get("tenant_slug"))}

        if normalized_cmd == "LDAP_LIST_GROUPS":
            return {"status": "SUCCESS", "data": await asyncio.to_thread(
                self.manager.list_groups_scoped, data.get("tenant_slug"))}

        if normalized_cmd == "LDAP_GET_USER_GROUPS":
            return await asyncio.to_thread(
                self.manager.get_user_groups,
                data.get("uid"), data.get("tenant_slug"))

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
            # Leak-free connectivity check (binds + unbinds), off the event loop.
            await asyncio.to_thread(self.manager.check_connection)
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
        # Atomic + correct-mode-from-creation: create the temp file with `mode` so
        # a 0600 key is never briefly world-readable, then os.replace (a crash
        # mid-write leaves the old file intact, not a truncated cert/key).
        tmp = f"{path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.chmod(tmp, mode)  # os.open honors umask; enforce the exact mode
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

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

    # ── UPDATE_CONFIG re-apply helpers (Entra .env + mirror-mode) ──────────

    # Keys persisted to .env so the standalone pam_exec ROPC bridge (which reads
    # .env, not this process's memory) sees Entra config pushed via UPDATE_CONFIG.
    _ENV_PERSIST_KEYS = (
        "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_CERT",
        "ENTRA_CLIENT_KEY", "ENTRA_ROPC_SCOPE", "LDAP_BASE_DN",
        "LDAP_ADMIN_DN", "LDAP_SERVER_ID", "LDAP_MIRROR_PEERS",
    )

    def _env_path(self) -> str:
        return os.environ.get("LDAP_ENV_PATH") or str(Path(__file__).parent.parent / ".env")

    def _persist_env(self, data: Dict[str, Any]) -> None:
        """Merge the persist-worthy keys from ``data`` into the module ``.env``
        (preserving all other lines), then re-chmod 0600. Only keys present in
        ``data`` are updated; ``LDAP_MIRROR_PEERS`` is JSON-serialised if a list."""
        path = self._env_path()
        updates = {}
        for k in self._ENV_PERSIST_KEYS:
            if k in data and data[k] is not None:
                v = data[k]
                if k == "LDAP_MIRROR_PEERS" and isinstance(v, (list, tuple)):
                    v = json.dumps(list(v))
                updates[k] = str(v)
        if not updates:
            return
        lines = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        seen = set()
        out = []
        for line in lines:
            key = line.split("=", 1)[0].strip() if "=" in line else ""
            if key in updates:
                out.append(f"{key}={updates[key]}")
                seen.add(key)
            else:
                out.append(line)
        for k, v in updates.items():
            if k not in seen:
                out.append(f"{k}={v}")
        tmp = f"{path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(out) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    async def _ldapmodify_tolerant(self, ldif: str, tolerate: str = "") -> Optional[str]:
        """Like ``_ldapmodify`` but returns an error string instead of raising,
        and treats an error whose text contains ``tolerate`` (e.g. "already
        exists") as success (returns None)."""
        try:
            await self._ldapmodify(ldif)
            return None
        except _CertInstallError as e:
            msg = str(e)
            if tolerate and tolerate.lower() in msg.lower():
                return None
            return msg

    async def _apply_replication_config(self, data: Dict[str, Any]) -> str:
        """Re-apply syncrepl mirror-mode to cn=config idempotently (best-effort;
        requires co-location on the slapd host as root via ldapi EXTERNAL).
        Returns a short human-readable note for the UPDATE_CONFIG response."""
        try:
            server_id = int(data.get("LDAP_SERVER_ID"))
            peers = data.get("LDAP_MIRROR_PEERS")
            if isinstance(peers, str):
                peers = json.loads(peers) if peers.strip().startswith("[") else [peers]
            base_dn = data.get("LDAP_BASE_DN", "")
            admin_dn = data.get("LDAP_ADMIN_DN", "")
            admin_pw = data.get("LDAP_ADMIN_PW", "")
            overlay = replication.build_syncprov_overlay_ldif()
            mirror = replication.build_full_mirror_ldif(
                server_id, peers, base_dn, admin_dn, admin_pw)
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            return f"replication config invalid: {str(e)[:120]}"
        # syncprov overlay: tolerate "already exists" so re-runs are idempotent.
        err = await self._ldapmodify_tolerant(overlay, tolerate="already exists")
        if err:
            return f"replication syncprov apply failed: {err[:160]}"
        err = await self._ldapmodify_tolerant(mirror)
        if err:
            return f"replication mirror apply failed: {err[:160]}"
        logger.info("UPDATE_CONFIG: mirror-mode replication re-applied (serverID=%s)", server_id)
        return "mirror-mode replication re-applied"