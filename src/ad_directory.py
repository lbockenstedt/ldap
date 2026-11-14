"""Active Directory as a Directory source (read-only stub).

Phase D of the Directory accounts work (lm/docs/directory-accounts.md): LM
shows LDAP, Entra and AD accounts in one view. This module only *reads* AD so
far: it finds which domain controller to talk to, binds, and searches users.
Create/update/move in AD come later.

Which server to use, in order (owner direction: "lookup the global catalogs in
AD and find the DC to use", with a primary and backup server at a minimum):

1. DNS SRV discovery, when ``discover`` is on. AD registers its servers in DNS:
   - global catalogs (forest-wide, read-only, ports 3268/3269):
     ``_gc._tcp.<site>._sites.<forest>`` then ``_gc._tcp.<forest>``;
   - domain controllers (full domain, ports 389/636):
     ``_ldap._tcp.<site>._sites.dc._msdcs.<domain>`` then
     ``_ldap._tcp.dc._msdcs.<domain>``.
   Servers in the spoke's own AD site come first (they are the closest).
   Within one SRV answer, lower priority wins, then higher weight.
2. The configured ``servers`` list (primary first, then backup). These are
   always tried after the discovered ones, so AD still works when the spoke
   can't reach AD's DNS.

Each candidate gets a short connect timeout, and the first one that binds is
used. The SRV lookup uses only the standard library (a small DNS client), so
the spoke needs no extra DNS package (fleet rule 8.3, few dependencies).

Config: the ``ad`` field of each AD_* command. The hub keeps one AD
connection per tenant (Setup, ``ad_connections``) and sends it with every
command, filling ``bind_password`` from the Credential Vault at send time, so
the spoke never stores the password:

    domain              corp.example.com   (required)
    forest              forest root domain; defaults to ``domain``
    site                AD site of the spoke, optional
    discover            look servers up in DNS (default True)
    use_global_catalog  search the GC instead of a DC (default True)
    use_ssl             LDAPS: 636 / 3269 (default True); when off, 389 / 3268
                        with StartTLS, never a cleartext bind
    dns_servers         DNS servers for discovery; empty = system resolver
    servers             ["dc1.corp.example.com", "dc2:636"] primary, backup
    bind_user           user@corp.example.com or a DN
    bind_password       secret; never logged
    base_dn             search base; defaults to DC=corp,DC=example,DC=com
    timeout             seconds per server (default 3)
"""
import logging
import random
import socket
import struct
from typing import Any, Dict, List, Optional

import ldap
import ldap.filter
logger = logging.getLogger("AdDirectory")

# SRV record type and the EDNS0 OPT type (lets UDP answers exceed 512 bytes;
# a domain with many DCs easily does).
_TYPE_SRV = 33
_TYPE_OPT = 41
_EDNS_UDP_SIZE = 4096

# AD's well-known ports: plain / TLS.
_LDAP_PORTS = (389, 636)
_GC_PORTS = (3268, 3269)


# ---- DNS SRV lookup (standard library only) -----------------------------------

def build_srv_query(name: str, qid: int) -> bytes:
    """Build a DNS query packet asking for the SRV records of ``name``."""
    # Header: id, flags (recursion desired), 1 question, 0 answers, 0 authority,
    # 1 additional (the EDNS0 OPT record).
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    # Question: the name as length-prefixed labels, then type SRV, class IN.
    qname = b"".join(bytes([len(p)]) + p.encode("idna")
                     for p in name.strip(".").split(".") if p) + b"\x00"
    question = qname + struct.pack("!HH", _TYPE_SRV, 1)
    # EDNS0 OPT: root name, type OPT, "class" = our UDP buffer size.
    opt = b"\x00" + struct.pack("!HHIH", _TYPE_OPT, _EDNS_UDP_SIZE, 0, 0)
    return header + question + opt


def _read_name(msg: bytes, pos: int) -> tuple:
    """Read a (possibly compressed) DNS name at ``pos``.

    Returns ``(name, position after the name)``. Compression pointers jump
    elsewhere in the message; a hop limit stops a malicious pointer loop."""
    labels, end, hops = [], None, 0
    while True:
        length = msg[pos]
        # A pointer: the rest of the name is elsewhere in the message.
        if length & 0xC0 == 0xC0:
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            hops += 1
            if hops > 32:
                raise ValueError("DNS name pointer loop")
            continue
        # The root label ends the name.
        if length == 0:
            return ".".join(labels), (end if end is not None else pos + 1)
        labels.append(msg[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length


def parse_srv_response(msg: bytes, qid: int) -> Dict[str, Any]:
    """Parse a DNS answer to an SRV query.

    Returns ``{"truncated": bool, "records": [{priority, weight, port, target}]}``.
    A name that does not exist (NXDOMAIN) is an empty list, not an error; any
    other DNS failure raises ValueError, so "no servers" and "couldn't ask"
    stay different things."""
    # Check the header: our id, a response, and the result code.
    if len(msg) < 12:
        raise ValueError("short DNS response")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid or not flags & 0x8000:
        raise ValueError("DNS response does not match the query")
    truncated = bool(flags & 0x0200)
    rcode = flags & 0x000F
    if rcode == 3:
        return {"truncated": truncated, "records": []}
    if rcode != 0:
        raise ValueError(f"DNS error rcode={rcode}")
    # Skip the question section.
    pos = 12
    for _ in range(qd):
        _n, pos = _read_name(msg, pos)
        pos += 4
    # Read the answers and keep the SRV records.
    records = []
    for _ in range(an):
        _n, pos = _read_name(msg, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
        pos += 10
        if rtype == _TYPE_SRV:
            prio, weight, port = struct.unpack("!HHH", msg[pos:pos + 6])
            target, _ = _read_name(msg, pos + 6)
            # A target of "." means "no service here" (RFC 2782).
            if target:
                records.append({"priority": prio, "weight": weight,
                                "port": port, "target": target.lower()})
        pos += rdlen
    return {"truncated": truncated, "records": records}


def system_dns_servers(path: str = "/etc/resolv.conf") -> List[str]:
    """Nameservers from resolv.conf (the system resolver), in file order."""
    servers = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return servers


def _ask(server: str, packet: bytes, timeout: float, tcp: bool) -> bytes:
    """Send one DNS query to ``server`` port 53 over UDP or TCP."""
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    if not tcp:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            # connect() makes the kernel drop replies from any other address.
            s.connect((server, 53))
            s.send(packet)
            return s.recv(65535)
    # TCP: each message carries a 2-byte length prefix.
    with socket.create_connection((server, 53), timeout=timeout) as s:
        s.sendall(struct.pack("!H", len(packet)) + packet)
        size = struct.unpack("!H", _recv_exact(s, 2))[0]
        return _recv_exact(s, size)


def _recv_exact(sock, size: int) -> bytes:
    """Read exactly ``size`` bytes from a TCP socket."""
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ValueError("DNS TCP connection closed early")
        buf += chunk
    return buf


def query_srv(name: str, dns_servers: Optional[List[str]] = None,
              timeout: float = 2.0) -> List[Dict[str, Any]]:
    """Look up the SRV records of ``name``, sorted best first.

    Tries each DNS server in turn and returns the first answer (an empty list
    when the name does not exist). Retries over TCP when the UDP answer was
    truncated. Raises ValueError when no DNS server answered."""
    servers = list(dns_servers or []) or system_dns_servers()
    if not servers:
        raise ValueError("no DNS server to ask")
    last_err = None
    for server in servers:
        qid = random.randint(0, 0xFFFF)
        packet = build_srv_query(name, qid)
        try:
            res = parse_srv_response(_ask(server, packet, timeout, tcp=False), qid)
            if res["truncated"]:
                res = parse_srv_response(_ask(server, packet, timeout, tcp=True), qid)
            # Lower priority first; within a priority, higher weight first.
            return sorted(res["records"], key=lambda r: (r["priority"], -r["weight"], r["target"]))
        except (OSError, ValueError, struct.error, IndexError) as exc:
            last_err = exc
            logger.debug("SRV %s via %s failed: %s", name, server, exc)
    raise ValueError(f"SRV lookup for {name} failed: {last_err}")


# ---- Picking the server --------------------------------------------------------

def srv_names(cfg: Dict[str, Any]) -> List[str]:
    """The SRV names to look up for this config, best first (own site first)."""
    domain = (cfg.get("domain") or "").strip(".").lower()
    forest = (cfg.get("forest") or domain).strip(".").lower()
    site = (cfg.get("site") or "").strip()
    names = []
    if _flag(cfg.get("use_global_catalog"), True):
        if site:
            names.append(f"_gc._tcp.{site}._sites.{forest}")
        names.append(f"_gc._tcp.{forest}")
    else:
        if site:
            names.append(f"_ldap._tcp.{site}._sites.dc._msdcs.{domain}")
        names.append(f"_ldap._tcp.dc._msdcs.{domain}")
    return names


def _split_host(entry: str, default_port: int) -> tuple:
    """``"dc1:636"`` → ``("dc1", 636)``; no port → ``default_port``.
    ``"[fd00::1]:636"`` is IPv6 with a port; a bare IPv6 address has none."""
    entry = entry.strip()
    if entry.startswith("[") and "]" in entry:
        host, _, rest = entry[1:].partition("]")
        port = rest.lstrip(":")
        return host.lower(), int(port) if port.isdigit() else default_port
    host, sep, port = entry.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host.lower(), int(port)
    return entry.lower(), default_port


def _flag(value, default: bool) -> bool:
    """Read a config switch that may arrive as a bool or a string ("false")."""
    if value is None or value == "":
        return default
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def candidate_servers(cfg: Dict[str, Any], lookup=query_srv) -> Dict[str, Any]:
    """Ordered list of servers to try, plus any discovery errors.

    Returns ``{"servers": [{host, port, ssl, source}], "errors": [...]}``.
    Discovered servers come first, then the configured primary and backup.
    Duplicates are dropped (first place wins). ``lookup`` is injectable so
    tests don't need DNS."""
    use_ssl = _flag(cfg.get("use_ssl"), True)
    gc = _flag(cfg.get("use_global_catalog"), True)
    plain, tls = _GC_PORTS if gc else _LDAP_PORTS
    port = tls if use_ssl else plain
    out, seen, errors = [], set(), []

    # Add one server unless it is already listed.
    def add(host, p, source):
        """Append a server once, keeping the first source that named it."""
        if host and (host, p) not in seen:
            seen.add((host, p))
            # A well-known LDAPS port always means LDAPS, whatever use_ssl says.
            out.append({"host": host, "port": p, "ssl": use_ssl or p in (636, 3269),
                        "source": source})

    # 1. DNS discovery. SRV records carry the plain port; LDAPS uses the
    #    matching TLS port on the same host.
    if _flag(cfg.get("discover"), True) and cfg.get("domain"):
        for name in srv_names(cfg):
            try:
                for rec in lookup(name, cfg.get("dns_servers") or None):
                    p = port if rec["port"] in (plain, tls) else rec["port"]
                    add(rec["target"], p, f"dns:{name}")
            except ValueError as exc:
                errors.append(str(exc))
    # 2. Configured servers: primary first, then backup(s).
    for i, entry in enumerate(cfg.get("servers") or []):
        host, p = _split_host(str(entry), port)
        add(host, p, "primary" if i == 0 else "backup")
    return {"servers": out, "errors": errors}


def base_dn_for(domain: str) -> str:
    """``corp.example.com`` → ``DC=corp,DC=example,DC=com``."""
    return ",".join(f"DC={p}" for p in domain.strip(".").split(".") if p)


# ---- Reading AD ----------------------------------------------------------------

class NoCredentials(ValueError):
    """The connection has no bind user or password (e.g. a vault miss on the
    hub): the operation never ran, so it is not an AD outage."""


def _close(conn) -> None:
    """Drop a connection (after a failed bind or a finished operation);
    errors here don't matter and never change the operation's result."""
    if conn is None:
        return
    try:
        conn.unbind_s()
    except Exception:  # noqa: BLE001 - best-effort cleanup of a dead handle
        pass


class AdDirectory:
    """Read-only access to one AD domain, with server discovery and failover."""

    def __init__(self, cfg: Dict[str, Any], lookup=query_srv, connect=None):
        """``cfg`` is the ``ad`` connection from the command. ``lookup`` and ``connect`` are
        injectable for tests (DNS lookup, and ``ldap.initialize``)."""
        self.cfg = dict(cfg or {})
        self._lookup = lookup
        self._connect = connect or ldap.initialize
        self.active_server: Optional[Dict[str, Any]] = None

    def configured(self) -> bool:
        """True when there is enough config to try AD at all."""
        return bool(self.cfg.get("domain") and
                    (_flag(self.cfg.get("discover"), True) or self.cfg.get("servers")))

    def discover(self) -> Dict[str, Any]:
        """List the servers that would be tried, in order, without binding."""
        if not self.configured():
            return {"status": "ERROR", "error": "NOT_CONFIGURED",
                    "message": "AD is not configured (domain and servers)"}
        res = candidate_servers(self.cfg, self._lookup)
        # No server to try is a failure, not an empty success; the lookup
        # errors (if any) say why. Errors next to usable servers are warnings.
        if not res["servers"]:
            return {"status": "ERROR", "message": "no AD server found: " +
                    "; ".join(res["errors"] or ["none configured"]), **res}
        return {"status": "SUCCESS", **res}

    def _bind(self):
        """Bind to the first server that answers; remember which one it was.

        Returns ``(conn, attempts)``. A wrong password is not retried on the
        next server (it would fail the same way and could lock the account).
        An empty password is refused up front: AD treats it as an anonymous
        bind and "succeeds", which would look like a working login."""
        if not (self.cfg.get("bind_user") and self.cfg.get("bind_password")):
            raise NoCredentials("AD bind user and password are required")
        cand = candidate_servers(self.cfg, self._lookup)
        if not cand["servers"]:
            raise ValueError("no AD server found: " + "; ".join(cand["errors"] or ["none configured"]))
        timeout = float(self.cfg.get("timeout") or 3)
        attempts = []
        for srv in cand["servers"]:
            # IPv6 literals need brackets inside a URL.
            host = f"[{srv['host']}]" if ":" in srv["host"] else srv["host"]
            uri = f"{'ldaps' if srv['ssl'] else 'ldap'}://{host}:{srv['port']}"
            conn = None
            try:
                conn = self._connect(uri)
                conn.set_option(ldap.OPT_NETWORK_TIMEOUT, timeout)
                conn.set_option(ldap.OPT_TIMEOUT, timeout)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                # Never send the password in clear: without LDAPS, upgrade the
                # connection with StartTLS first. A server that can't do TLS
                # fails here and the next server is tried.
                if not srv["ssl"]:
                    conn.start_tls_s()
                conn.simple_bind_s(self.cfg.get("bind_user") or "",
                                   self.cfg.get("bind_password") or "")
                self.active_server = srv
                attempts.append({"server": uri, "ok": True})
                return conn, attempts
            except ldap.INVALID_CREDENTIALS:
                attempts.append({"server": uri, "ok": False, "error": "invalid credentials"})
                _close(conn)
                raise
            except ldap.LDAPError as exc:
                # Down, unreachable or no TLS: log it and try the next server.
                logger.warning("AD server %s failed: %s", uri, type(exc).__name__)
                attempts.append({"server": uri, "ok": False, "error": type(exc).__name__})
                _close(conn)
        raise ValueError("no AD server answered: " +
                         ", ".join(a["server"] for a in attempts))

    def test(self) -> Dict[str, Any]:
        """Bind and report which server answered (for the WebUI's Test button)."""
        try:
            conn, attempts = self._bind()
            _close(conn)
            return {"status": "SUCCESS", "server": self.active_server, "attempts": attempts}
        except ldap.INVALID_CREDENTIALS:
            return {"status": "ERROR", "error": "INVALID_CREDENTIALS",
                    "message": "AD rejected the bind user or password"}
        except NoCredentials as exc:
            return {"status": "ERROR", "error": "NO_CREDENTIALS", "message": str(exc)}
        except (ValueError, ldap.LDAPError) as exc:
            return {"status": "ERROR", "message": str(exc)}

    def search_users(self, query: str = "", limit: int = 200) -> Dict[str, Any]:
        """Find enabled and disabled user accounts by name, login or UPN.

        Read-only. ``query`` empty lists the first ``limit`` users."""
        # Build a filter for person accounts; escape the user's text.
        q = ldap.filter.escape_filter_chars(query.strip()) if query else ""
        match = (f"(|(sAMAccountName={q}*)(userPrincipalName={q}*)"
                 f"(displayName={q}*)(mail={q}*))") if q else ""
        filt = f"(&(objectCategory=person)(objectClass=user){match})"
        base = self.cfg.get("base_dn") or base_dn_for(self.cfg.get("domain") or "")
        attrs = ["sAMAccountName", "userPrincipalName", "displayName", "mail",
                 "userAccountControl"]
        try:
            conn, _ = self._bind()
            try:
                res, truncated = self._search(conn, base, filt, attrs,
                                              max(1, min(int(limit), 1000)))
            finally:
                _close(conn)
        except ldap.INVALID_CREDENTIALS:
            return {"status": "ERROR", "error": "INVALID_CREDENTIALS",
                    "message": "AD rejected the bind user or password"}
        except NoCredentials as exc:
            return {"status": "ERROR", "error": "NO_CREDENTIALS", "message": str(exc)}
        except (ValueError, ldap.LDAPError) as exc:
            return {"status": "ERROR", "message": str(exc)}
        # Convert the entries; skip referrals (no DN).
        users = []
        for dn, a in res:
            if not dn or not isinstance(a, dict):
                continue

            def first(k):
                """First value of attribute k as text."""
                v = a.get(k) or [b""]
                return v[0].decode("utf-8", "replace")
            # No readable userAccountControl means "unknown" (None), not enabled.
            uac = first("userAccountControl")
            enabled = (not int(uac) & 0x2) if uac.isdigit() else None
            users.append({"username": first("sAMAccountName"), "upn": first("userPrincipalName"),
                          "display_name": first("displayName"), "email": first("mail"),
                          "dn": dn, "enabled": enabled, "location": "ad"})
        return {"status": "SUCCESS", "data": users, "truncated": truncated,
                "server": self.active_server}

    @staticmethod
    def _search(conn, base: str, filt: str, attrs: list, limit: int) -> tuple:
        """Search up to ``limit`` entries, keeping what arrived before a size
        limit hit. ``search_ext_s`` throws those entries away, which would
        turn "more than N users" into "no users". Returns ``(entries, truncated)``."""
        msgid = conn.search_ext(base, ldap.SCOPE_SUBTREE, filt, attrs, sizelimit=limit)
        entries = []
        try:
            # Read one result at a time until the search-done message.
            while True:
                rtype, rdata = conn.result3(msgid, all=0)[:2]
                if rtype == ldap.RES_SEARCH_RESULT:
                    return entries, False
                if rtype == ldap.RES_SEARCH_ENTRY:
                    entries.extend(rdata)
        except ldap.SIZELIMIT_EXCEEDED:
            return entries, True
