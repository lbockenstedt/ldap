"""Build cn=config LDIF for 2-node syncrepl MIRROR-MODE replication.

Pure LDIF-string builders (no ``python-ldap``) so the config math is
unit-testable and shared by BOTH the installer (``python3 -m src.replication ...``)
and the spoke's ``UPDATE_CONFIG`` re-apply path — one source of truth for the
replication config, no bash/python drift.

Mirror-mode = multi-master limited to a 2-node active/active pair: each node is
both a syncrepl consumer of the other AND a provider (``syncprov`` overlay), and
``olcMirrorMode: TRUE`` lets a node accept writes despite being a consumer. Each
node carries a distinct ``olcServerID`` (1 or 2) so change sequence numbers
(CSNs) are attributable and loops are broken.

The applied LDIF is idempotent by construction: ``olcServerID`` /
``olcMirrorMode`` use ``replace:`` (works whether or not the attr exists), the
``syncprov`` module load / overlay add tolerate "already exists", and
``olcSyncrepl`` uses ``replace:`` so re-running with changed peers converges
rather than accreting stale ``rid`` entries (and the very first run works —
``delete:`` of a missing attribute is rejected by slapd).
"""
# Allows modern type hints to be written as plain annotations.
from __future__ import annotations

# base64 encodes non-ASCII LDIF values; os reads the CLI password from the
# environment; sys provides argv/stdout/stderr; typing is for hints only.
import base64
import os
import sys
from typing import List, Optional

# Default DB DN for the primary MDB backend on a stock Debian/Ubuntu slapd.
DEFAULT_DB_DN = "olcDatabase={1}mdb,cn=config"


def _clean_peers(peers) -> List[str]:
    """Filter and clean list of peer LDAP URLs, removing empty or whitespace items."""
    # Keep each non-empty peer URL with surrounding whitespace removed.
    out = []
    for p in peers or []:
        p = (p or "").strip()
        if p:
            out.append(p)
    # Return the cleaned list.
    return out


def _slapd_quote(value: str, field: str) -> str:
    """Return ``value`` as a double-quoted slapd config token.

    olcSyncrepl is one string that slapd splits on whitespace, honouring
    double quotes and backslash escapes. A raw ``"`` in a password or DN would
    end the quoted value early and let the rest be parsed as extra syncrepl
    keywords, and a newline would end the LDIF line so the text after it
    became a further change to cn=config, applied as root. So escape ``\\``
    and ``"``, and refuse control characters outright."""
    text = str(value)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise ValueError(f"{field} must not contain control characters")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ldif_attr(name: str, value: str) -> str:
    """Return one LDIF ``attr: value`` line, base64-encoded (``attr::``) when
    the value is not a plain ASCII SAFE-STRING (RFC 2849), e.g. a password
    with non-ASCII characters."""
    if value.isascii() and value[:1] not in (" ", ":", "<") and not value.endswith(" "):
        return f"{name}: {value}"
    return f"{name}:: " + base64.b64encode(value.encode("utf-8")).decode("ascii")


def _transport_opts(peer: str) -> str:
    """syncrepl TLS options for one peer URL.

    A plain ``ldap://`` peer gets ``starttls=critical tls_reqcert=allow``:
    the admin bind and the replicated entries always go over TLS, and if the
    peer can't do StartTLS replication stops rather than falling back to
    plaintext (``yes`` would send the rootDN password in the clear). Every
    node the installer builds has at least a self-signed cert, and the
    installer refuses mirror mode when it could not configure one.
    ``allow`` accepts that self-signed cert, so this stops passive capture
    but not an active man-in-the-middle. An ``ldaps://`` peer is already TLS
    and keeps the library defaults."""
    if peer.lower().startswith("ldap://"):
        return " starttls=critical tls_reqcert=allow"
    return ""


def build_serverid_ldif(server_id: int) -> str:
    """``cn=config`` LDIF setting ``olcServerID`` (replace: idempotent)."""
    # Server IDs must be positive integers.
    sid = int(server_id)
    if sid < 1:
        raise ValueError("server_id must be a positive integer (1 or 2)")
    # One LDIF modify record replacing olcServerID on cn=config.
    return "\n".join([
        "dn: cn=config",
        "changetype: modify",
        "replace: olcServerID",
        f"olcServerID: {sid}",
    ]) + "\n"


def build_syncprov_module_ldif() -> str:
    """Load the ``syncprov`` module (Debian's slapd ships it as a module that
    is NOT loaded by default, so the overlay add fails without this). The
    caller ignores "value already exists" (20) on re-runs."""
    # One LDIF modify record adding syncprov to the module list.
    return "\n".join([
        "dn: cn=module{0},cn=config",
        "changetype: modify",
        "add: olcModuleLoad",
        "olcModuleLoad: syncprov",
    ]) + "\n"


def build_syncprov_overlay_ldif(db_dn: str = DEFAULT_DB_DN) -> str:
    """Add the ``syncprov`` overlay to the DB so this node can PROVIDE updates to
    its peer. Applied with ``changetype: add``; the caller ignores an
    "already exists" (68) result to stay idempotent."""
    # One LDIF add record creating the syncprov overlay with checkpoint/session-log tuning.
    return "\n".join([
        f"dn: olcOverlay=syncprov,{db_dn}",
        "changetype: add",
        "objectClass: olcOverlayConfig",
        "objectClass: olcSyncProvConfig",
        "olcOverlay: syncprov",
        "olcSpCheckpoint: 100 10",
        "olcSpSessionLog: 100",
    ]) + "\n"


def build_syncrepl_ldif(server_id: int, peers, base_dn: str,
                        admin_dn: str, admin_pw: str,
                        db_dn: str = DEFAULT_DB_DN) -> str:
    """Replace the DB's ``olcSyncrepl`` with one consumer block per peer.

    ``replace:`` so re-running converges (no stale rids) and the first run
    works when no ``olcSyncrepl`` exists yet. Each block uses
    ``refreshAndPersist`` (live change stream) with simple-bind creds. The
    ``rid`` is derived from this node's ``server_id`` and the peer index so the
    two nodes never collide on a rid. ``retry`` keeps a downed peer re-trying
    without operator action."""
    # Validate the server id, peers, base DN and admin DN before building anything.
    sid = int(server_id)
    if sid < 1:
        raise ValueError("server_id must be a positive integer (1 or 2)")
    peers = _clean_peers(peers)
    base_dn = (base_dn or "").strip()
    admin_dn = (admin_dn or "").strip()
    if not base_dn or not admin_dn:
        raise ValueError("base_dn and admin_dn are required")
    if not peers:
        raise ValueError("at least one peer is required for mirror-mode")

    # Header of the modify record that replaces all existing olcSyncrepl values.
    lines = [f"dn: {db_dn}", "changetype: modify",
             "replace: olcSyncrepl"]
    # Quote every caller-supplied value so none can add syncrepl keywords or
    # LDIF lines (see _slapd_quote).
    q_base = _slapd_quote(base_dn, "base_dn")
    q_dn = _slapd_quote(admin_dn, "admin_dn")
    q_pw = _slapd_quote(admin_pw or "", "admin_pw")
    # Add one syncrepl consumer definition per peer.
    for idx, peer in enumerate(peers):
        # rid must be unique per node and stable per peer; keep it small (<=999,
        # slapd's rid limit). e.g. node 1 → rid 101,102...; node 2 → 201,202...
        rid = sid * 100 + idx + 1
        # Consumer settings: provider URL, live replication, retry every 30s forever,
        # the subtree to replicate, TLS for a plain ldap:// peer and simple-bind
        # credentials for the peer.
        block = (
            f"rid={rid:03d} "
            f"provider={_slapd_quote(peer, 'peer')} "
            'type=refreshAndPersist '
            'retry="30 +" '
            f"searchbase={q_base} "
            'scope=sub schemachecking=on '
            'bindmethod=simple'
            f"{_transport_opts(peer)} "
            f"binddn={q_dn} "
            f"credentials={q_pw}"
        )
        # Append the block as another olcSyncrepl value.
        lines.append(_ldif_attr("olcSyncrepl", block))
    # Join the record lines into LDIF text.
    return "\n".join(lines) + "\n"


def build_mirrormode_ldif(enabled: bool, db_dn: str = DEFAULT_DB_DN) -> str:
    """Set ``olcMirrorMode`` TRUE/FALSE on the DB (replace: idempotent)."""
    # One LDIF modify record replacing olcMirrorMode with TRUE or FALSE.
    return "\n".join([
        f"dn: {db_dn}",
        "changetype: modify",
        "replace: olcMirrorMode",
        f"olcMirrorMode: {'TRUE' if enabled else 'FALSE'}",
    ]) + "\n"


def build_full_mirror_ldif(server_id: int, peers, base_dn: str,
                           admin_dn: str, admin_pw: str,
                           db_dn: str = DEFAULT_DB_DN) -> str:
    """Convenience: the serverID + syncrepl + mirrormode LDIF documents joined
    by ``\\n`` (the syncprov overlay is applied separately because its
    "already exists" result must be tolerated independently). Suitable for a
    single ``ldapmodify`` invocation."""
    # Join the three records, separated by blank lines as LDIF requires.
    return "\n".join([
        build_serverid_ldif(server_id).rstrip("\n"),
        "",
        build_syncrepl_ldif(server_id, peers, base_dn, admin_dn, admin_pw, db_dn).rstrip("\n"),
        "",
        build_mirrormode_ldif(True, db_dn).rstrip("\n"),
    ]) + "\n"


def _main(argv) -> int:
    """CLI for the installer: emit LDIF on stdout.

    Usage:
      python3 -m src.replication serverid <id>
      python3 -m src.replication syncprov-module
      python3 -m src.replication syncprov [db_dn]
      LDAP_ADMIN_PW=... python3 -m src.replication syncrepl <id> <base_dn> <admin_dn> <peer> [peer...]
      python3 -m src.replication mirrormode <true|false> [db_dn]

    The syncrepl admin password comes from the LDAP_ADMIN_PW environment
    variable, not argv, so it never shows in ps or /proc/<pid>/cmdline.
    """
    # Without a subcommand, print the usage text (this docstring) and exit 2.
    if len(argv) < 2:
        sys.stderr.write(_main.__doc__ or "")
        return 2
    # Dispatch on the subcommand; bad or missing arguments are reported below.
    cmd = argv[1]
    try:
        if cmd == "serverid":
            # serverid <id>: set this node's server id.
            sys.stdout.write(build_serverid_ldif(int(argv[2])))
        elif cmd == "syncprov-module":
            # syncprov-module: load the syncprov module.
            sys.stdout.write(build_syncprov_module_ldif())
        elif cmd == "syncprov":
            # syncprov [db_dn]: add the overlay, optionally to a non-default database.
            sys.stdout.write(build_syncprov_overlay_ldif(*(argv[2:3] or [])))
        elif cmd == "syncrepl":
            # syncrepl: positional id, base DN, admin DN, then peer URLs; the
            # password is read from the environment so it stays off argv.
            sid, base_dn, admin_dn = argv[2], argv[3], argv[4]
            peers = argv[5:]
            admin_pw = os.environ.get("LDAP_ADMIN_PW", "")
            if not admin_pw:
                raise ValueError("LDAP_ADMIN_PW is not set in the environment")
            sys.stdout.write(build_syncrepl_ldif(int(sid), peers, base_dn, admin_dn, admin_pw))
        elif cmd == "mirrormode":
            # mirrormode <true|false> [db_dn]: accept common truthy spellings.
            enabled = str(argv[2]).strip().lower() in ("1", "true", "yes", "on")
            sys.stdout.write(build_mirrormode_ldif(enabled, *(argv[3:4] or [])))
        else:
            # Unknown subcommand: report and exit 2.
            sys.stderr.write(f"unknown subcommand: {cmd}\n")
            return 2
    except (IndexError, ValueError) as e:
        # Missing/invalid arguments: report and exit 2.
        sys.stderr.write(f"error: {e}\n")
        return 2
    # LDIF written successfully.
    return 0


if __name__ == "__main__":
    # Run the CLI and use its return value as the process exit code.
    raise SystemExit(_main(sys.argv))
