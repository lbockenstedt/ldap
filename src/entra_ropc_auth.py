#!/usr/bin/env python3
"""Entra ID ROPC pass-through authenticator for slapd {SASL} binds.

Invoked by ``pam_exec.so`` (from ``/etc/pam.d/slapd``) when slapd routes a bind
against a user whose ``userPassword`` is ``{SASL}<upn>`` through Cyrus SASL →
saslauthd (``-a pam``) → PAM → this script. The username (the UPN, i.e. the part
after ``{SASL}``) arrives in ``$PAM_USER``; the bind password arrives on **stdin**
(pam_exec ``expose_authtok``). We run the OAuth 2.0 Resource-Owner-Password-
Credentials (ROPC) grant against Entra and exit 0 iff Entra returns a token.

This is the "hybrid" model: users with a local ``{SSHA}`` password bind normally
inside slapd and never reach this script; only ``{SASL}``-marked (Entra-backed)
users are validated here against Entra.

Client authentication to Entra reuses the hub's cert-based confidential-client
approach (a signed ``client_assertion`` JWT, no client secret) but is
implemented locally (cryptography + PyJWT + requests) because this module is
standalone. Config is read from the module ``.env``.

Security + robustness:
  * The password is read from stdin, used once, and NEVER logged (redacted).
  * Hard HTTP timeout (never hangs a bind); any error → non-zero exit (deny).
  * Logs to the module log so failures are diagnosable.
"""
# Allows modern type hints to be written as plain annotations.
from __future__ import annotations

# logging records decisions; os/sys read env, files and stdin.
import logging
import os
import sys
# time stamps the JWT; uuid gives each JWT a unique id (jti).
import time
import uuid
# Type hints only.
from typing import Callable, Dict, Optional, Tuple

# One named logger for this authenticator.
logger = logging.getLogger("EntraRopc")

# Entra v2.0 token endpoint template; {tenant} is filled with the tenant id.
_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
# Standard OAuth value saying the client authenticates with a signed JWT.
_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# Hard limit on the Entra request so a slow network never hangs an LDAP bind.
_HTTP_TIMEOUT_S = 15.0
# Log file location (overridable via ENTRA_ROPC_LOG).
_LOG_FILE = os.environ.get("ENTRA_ROPC_LOG", "/var/log/lm/entra-ropc.log")


# ── config ──────────────────────────────────────────────────────────────────

def load_config(env_path: Optional[str] = None) -> Dict[str, str]:
    """Load Entra ROPC config from the module ``.env`` (+ process env override).

    Env vars win over the file so an operator can override without editing
    ``.env``. Returns a dict with the contract keys; missing keys are empty
    strings and surface as a clear "not configured" failure at auth time."""
    # Values read from the .env file; it lives one directory above this script.
    values: Dict[str, str] = {}
    path = env_path or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    # Parse KEY=VALUE lines, skipping blanks, comments and non-assignments.
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                # Split on the first "=" and strip whitespace and optional quotes.
                k, _, v = line.partition("=")
                values[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass  # no .env — rely purely on process env
    # Build the config, letting environment variables override the file.
    return {
        "tenant_id": os.environ.get("ENTRA_TENANT_ID") or values.get("ENTRA_TENANT_ID", ""),
        "client_id": os.environ.get("ENTRA_CLIENT_ID") or values.get("ENTRA_CLIENT_ID", ""),
        "cert_path": os.environ.get("ENTRA_CLIENT_CERT") or values.get("ENTRA_CLIENT_CERT", ""),
        "key_path": os.environ.get("ENTRA_CLIENT_KEY") or values.get("ENTRA_CLIENT_KEY", ""),
        "scope": os.environ.get("ENTRA_ROPC_SCOPE") or values.get("ENTRA_ROPC_SCOPE", "") or "openid",
    }


# ── credential parsing (pure, unit-tested) ──────────────────────────────────

def read_credentials(argv, environ, stdin_bytes: bytes) -> Tuple[str, str]:
    """Extract (username, password) from the pam_exec invocation.

    Username: ``$PAM_USER`` (pam_exec's canonical channel), falling back to the
    first CLI arg (so the script is testable/runnable by hand). Password: the
    first line of stdin (pam_exec ``expose_authtok`` writes the authtok followed
    by a NUL/newline). We take everything up to the first NUL or newline so a
    trailing terminator isn't folded into the password."""
    # Prefer PAM_USER; fall back to the first CLI argument for manual runs.
    username = (environ.get("PAM_USER") or "").strip()
    if not username and len(argv) > 1:
        username = (argv[1] or "").strip()
    # Raw stdin bytes (empty when nothing was provided).
    data = stdin_bytes or b""
    # pam_exec terminates the authtok with a NUL; strip at the first NUL, then
    # the first newline, so neither terminator becomes part of the password.
    if b"\x00" in data:
        data = data.split(b"\x00", 1)[0]
    if b"\n" in data:
        data = data.split(b"\n", 1)[0]
    # Decode as UTF-8; replace undecodable bytes rather than failing the bind outright.
    try:
        password = data.decode("utf-8")
    except UnicodeDecodeError:
        password = data.decode("utf-8", "replace")
    # Return the parsed credentials.
    return username, password


# ── token-response → decision (pure, unit-tested) ───────────────────────────

def token_ok(status_code: int, payload: Optional[dict]) -> bool:
    """Decide auth success from the Entra token response: HTTP 200 AND an
    ``access_token`` (or ``id_token``) present. Anything else denies."""
    # Anything other than HTTP 200 with a JSON object is a denial.
    if status_code != 200 or not isinstance(payload, dict):
        return False
    # Success only when Entra issued an access or ID token.
    return bool(payload.get("access_token") or payload.get("id_token"))


# ── cert-based client assertion (reuses the hub's oidc.py approach) ──────────

def _cert_thumbprint_x5t(cert_pem: bytes) -> str:
    """``x5t`` header Entra requires: base64url(SHA-1(DER(cert))). Without it
    Entra rejects the assertion (AADSTS700027)."""
    # Imported lazily so the module loads (and unit-tests run) without cryptography.
    import base64
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    # Parse the certificate and get its DER encoding.
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    # SHA-1 of the DER, base64url-encoded without padding.
    return base64.urlsafe_b64encode(hashlib.sha1(der).digest()).rstrip(b"=").decode()


def build_client_assertion(cfg: Dict[str, str], token_endpoint: str) -> str:
    """RS256 JWT ``client_assertion`` signed by the Entra app cert's private key
    (no client secret). ``iss==sub==client_id``, ``aud`` = token endpoint, with
    the cert thumbprint in the ``x5t`` header."""
    # PyJWT signs the token; serialization loads the private key (lazy imports).
    import jwt
    from cryptography.hazmat.primitives import serialization
    # Load the app's private key and its certificate from the configured paths.
    with open(cfg["key_path"], "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    with open(cfg["cert_path"], "rb") as fh:
        cert_pem = fh.read()
    # Claims: issuer/subject are the app, audience is the token endpoint, valid 5 minutes.
    now = int(time.time())
    payload = {
        "iss": cfg["client_id"],
        "sub": cfg["client_id"],
        "aud": token_endpoint,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    # Include the certificate thumbprint so Entra can find the matching public key.
    headers = {"x5t": _cert_thumbprint_x5t(cert_pem)}
    # Sign with RS256 and return the compact JWT string.
    return jwt.encode(payload, key, algorithm="RS256", headers=headers)


# ── HTTP token request (network; injectable for tests) ──────────────────────

def _default_post(url: str, data: Dict[str, str]) -> Tuple[int, dict]:
    """POST the token request with a hard timeout; return (status, json)."""
    # Imported lazily; only the real network path needs requests.
    import requests
    # Send the form-encoded token request with the hard timeout.
    resp = requests.post(url, data=data, timeout=_HTTP_TIMEOUT_S)
    # Decode the JSON body; a non-JSON body becomes an empty dict.
    try:
        body = resp.json()
    except ValueError:
        body = {}
    # Return the HTTP status and body.
    return resp.status_code, body


def request_token(cfg: Dict[str, str], username: str, password: str, *,
                  post: Callable[[str, Dict[str, str]], Tuple[int, dict]] = _default_post,
                  assertion_builder: Callable[[Dict[str, str], str], str] = build_client_assertion,
                  ) -> Tuple[int, dict]:
    """Run the ROPC grant against Entra. ``post`` / ``assertion_builder`` are
    injectable so the flow is unit-testable without a network or a real key."""
    # Token endpoint URL for this tenant.
    token_endpoint = _TOKEN_URL.format(tenant=cfg["tenant_id"])
    # ROPC form body: user credentials plus the signed client assertion.
    data = {
        "grant_type": "password",
        "client_id": cfg["client_id"],
        "username": username,
        "password": password,
        "scope": cfg["scope"],
        "client_assertion_type": _ASSERTION_TYPE,
        "client_assertion": assertion_builder(cfg, token_endpoint),
    }
    # Send the request and return (status, body).
    return post(token_endpoint, data)


def authenticate(cfg: Dict[str, str], username: str, password: str, **kw) -> bool:
    """True iff Entra returns a token for (username, password). Never raises —
    any failure logs (redacted) and denies."""
    # Every config item is required; deny with a clear log when any is missing.
    if not (cfg.get("tenant_id") and cfg.get("client_id")
            and cfg.get("cert_path") and cfg.get("key_path")):
        logger.error("Entra ROPC not configured (missing tenant/client/cert/key) "
                     "— denying %s", username or "<no-user>")
        return False
    # Empty username or password is always denied.
    if not username or not password:
        logger.warning("Entra ROPC: missing username or password — denying")
        return False
    # Ask Entra for a token; any exception denies rather than crashing PAM.
    try:
        status, body = request_token(cfg, username, password, **kw)
    except Exception as e:  # noqa: BLE001 — never propagate; deny on any error
        logger.error("Entra ROPC token request failed for %s: %s", username, e)
        return False
    # Token issued: the password is correct.
    if token_ok(status, body):
        logger.info("Entra ROPC: authenticated %s", username)
        return True
    # Log the Entra error code (safe — no secret material) but never the password.
    # Extract Entra's short error code (if any) for the denial log.
    detail = ""
    if isinstance(body, dict):
        detail = str(body.get("error") or "")[:100]
    logger.warning("Entra ROPC: denied %s (HTTP %s%s)", username, status,
                   f", {detail}" if detail else "")
    return False


def _configure_logging() -> None:
    """Set up stderr and optional file logging for Entra ROPC events."""
    # Always log to stderr; also to the log file when its directory can be created.
    handlers = [logging.StreamHandler(sys.stderr)]
    try:
        os.makedirs(os.path.dirname(_LOG_FILE), exist_ok=True)
        handlers.append(logging.FileHandler(_LOG_FILE))
    # Log directory not writable: stderr only.
    except OSError:
        pass
    # Apply the handlers with the standard LM log format.
    logging.basicConfig(
        level=logging.INFO, force=True, handlers=handlers,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")


def main(argv=None, environ=None, stdin=None) -> int:
    """pam_exec entrypoint. Exit 0 = allow, non-zero = deny."""
    # Set up logging first so every later step is recorded.
    _configure_logging()
    # Use the real process argv/env/stdin unless tests inject replacements.
    argv = sys.argv if argv is None else argv
    environ = os.environ if environ is None else environ
    stdin_bytes = (sys.stdin.buffer.read() if stdin is None else stdin)
    # Parse the credentials and load the Entra config.
    username, password = read_credentials(argv, environ, stdin_bytes)
    cfg = load_config()
    # Exit 0 allows the bind, 1 denies it.
    return 0 if authenticate(cfg, username, password) else 1


if __name__ == "__main__":
    # Run main() and use its return value as the process exit code.
    raise SystemExit(main())
