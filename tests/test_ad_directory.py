"""Active Directory stub: SRV discovery (stdlib DNS client), server order
(own site, then forest/domain, then configured primary/backup), failover on a
down server, and read-only user search."""
import importlib.util
import struct
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def ad(monkeypatch):
    """Load ad_directory with a stub python-ldap."""
    lm = types.ModuleType("ldap")
    lm.LDAPError = type("LDAPError", (Exception,), {})
    lm.INVALID_CREDENTIALS = type("INVALID_CREDENTIALS", (lm.LDAPError,), {})
    lm.SERVER_DOWN = type("SERVER_DOWN", (lm.LDAPError,), {})
    lm.SIZELIMIT_EXCEEDED = type("SIZELIMIT_EXCEEDED", (lm.LDAPError,), {})
    lm.SCOPE_SUBTREE = 2
    lm.OPT_NETWORK_TIMEOUT, lm.OPT_TIMEOUT, lm.OPT_REFERRALS = 1, 2, 3
    lm.RES_SEARCH_ENTRY, lm.RES_SEARCH_RESULT = 100, 101
    lm.initialize = lambda uri: None
    lm.filter = types.ModuleType("ldap.filter")
    lm.filter.escape_filter_chars = lambda v: v.replace("*", r"\2a")
    monkeypatch.setitem(sys.modules, "ldap", lm)
    monkeypatch.setitem(sys.modules, "ldap.filter", lm.filter)
    spec = importlib.util.spec_from_file_location("ad_directory_t", ROOT / "src" / "ad_directory.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def _srv_answer(qid, qname, records, rcode=0, tc=False):
    """A DNS response; record targets after the first use compression
    pointers back to the question name's domain, like real servers do."""
    flags = 0x8180 | rcode | (0x0200 if tc else 0)
    msg = struct.pack("!HHHHHH", qid, flags, 1, len(records), 0, 0)
    msg += _name(qname) + struct.pack("!HH", 33, 1)
    for prio, weight, port, target in records:
        rdata = struct.pack("!HHH", prio, weight, port) + _name(target)
        msg += b"\xc0\x0c" + struct.pack("!HHIH", 33, 1, 300, len(rdata)) + rdata
    return msg


# ---- DNS packet handling -------------------------------------------------------

def test_query_packet_shape(ad):
    pkt = ad.build_srv_query("_gc._tcp.corp.example.com", 0x1234)
    assert pkt[:2] == b"\x12\x34"
    assert _name("_gc._tcp.corp.example.com") + struct.pack("!HH", 33, 1) in pkt
    assert pkt.endswith(b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00")


def test_parse_srv_records(ad):
    msg = _srv_answer(7, "_gc._tcp.corp.example.com",
                      [(0, 100, 3268, "DC1.corp.example.com"), (10, 0, 3268, "dc2.corp.example.com")])
    res = ad.parse_srv_response(msg, 7)
    assert [r["target"] for r in res["records"]] == ["dc1.corp.example.com", "dc2.corp.example.com"]
    assert res["records"][0]["port"] == 3268 and not res["truncated"]


def test_parse_compressed_target(ad):
    # Target "dc9" + pointer to "corp.example.com" inside the question name.
    q = "_gc._tcp.corp.example.com"
    msg = bytearray(_srv_answer(1, q, []))
    struct.pack_into("!H", msg, 6, 1)
    offset = 12 + len("_gc") + 1 + len("_tcp") + 1
    rdata = struct.pack("!HHH", 0, 0, 3268) + b"\x03dc9" + struct.pack("!H", 0xC000 | offset)
    msg += b"\xc0\x0c" + struct.pack("!HHIH", 33, 1, 60, len(rdata)) + rdata
    assert ad.parse_srv_response(bytes(msg), 1)["records"][0]["target"] == "dc9.corp.example.com"


def test_parse_nxdomain_is_empty_and_errors_raise(ad):
    assert ad.parse_srv_response(_srv_answer(3, "x.y", [], rcode=3), 3)["records"] == []
    with pytest.raises(ValueError):
        ad.parse_srv_response(_srv_answer(3, "x.y", [], rcode=2), 3)
    with pytest.raises(ValueError):
        ad.parse_srv_response(_srv_answer(3, "x.y", []), 4)


def test_pointer_loop_is_rejected(ad):
    msg = struct.pack("!HHHHHH", 5, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"
    with pytest.raises(ValueError):
        ad.parse_srv_response(msg, 5)


def test_query_srv_retries_tcp_when_truncated(ad, monkeypatch):
    calls = []

    def fake_ask(server, packet, timeout, tcp):
        calls.append(tcp)
        qid = struct.unpack("!H", packet[:2])[0]
        recs = [(5, 0, 389, "b.corp"), (0, 10, 389, "a.corp"), (0, 50, 389, "c.corp")]
        return _srv_answer(qid, "_ldap._tcp.corp", recs if tcp else [], tc=not tcp)
    monkeypatch.setattr(ad, "_ask", fake_ask)
    res = ad.query_srv("_ldap._tcp.corp", ["10.0.0.53"])
    assert calls == [False, True]
    # Priority ascending, then weight descending.
    assert [r["target"] for r in res] == ["c.corp", "a.corp", "b.corp"]


def test_query_srv_tries_next_dns_server_then_fails(ad, monkeypatch):
    def down(server, packet, timeout, tcp):
        raise OSError("timed out")
    monkeypatch.setattr(ad, "_ask", down)
    with pytest.raises(ValueError):
        ad.query_srv("_gc._tcp.corp", ["10.0.0.1", "10.0.0.2"])


# ---- Server order --------------------------------------------------------------

def _lookup(table):
    def lookup(name, dns_servers=None):
        if name not in table:
            raise ValueError(f"SRV lookup for {name} failed")
        return table[name]
    return lookup


def test_gc_order_site_then_forest_then_configured(ad):
    cfg = {"domain": "child.corp.com", "forest": "corp.com", "site": "Lab",
           "servers": ["dc1.corp.com", "dc9.corp.com:3269"]}
    table = {"_gc._tcp.Lab._sites.corp.com": [{"target": "gc-lab.corp.com", "port": 3268}],
             "_gc._tcp.corp.com": [{"target": "gc-hq.corp.com", "port": 3268},
                                   {"target": "gc-lab.corp.com", "port": 3268}]}
    res = ad.candidate_servers(cfg, _lookup(table))
    assert [(s["host"], s["port"], s["source"]) for s in res["servers"]] == [
        ("gc-lab.corp.com", 3269, "dns:_gc._tcp.Lab._sites.corp.com"),
        ("gc-hq.corp.com", 3269, "dns:_gc._tcp.corp.com"),
        ("dc1.corp.com", 3269, "primary"),
        ("dc9.corp.com", 3269, "backup"),
    ]
    assert res["errors"] == []


def test_dc_mode_plain_ports_and_dns_failure_falls_back(ad):
    cfg = {"domain": "corp.com", "use_global_catalog": False, "use_ssl": False,
           "servers": ["10.1.1.1", "[fd00::5]:1389"]}
    res = ad.candidate_servers(cfg, _lookup({}))
    assert [(s["host"], s["port"]) for s in res["servers"]] == [("10.1.1.1", 389), ("fd00::5", 1389)]
    assert "_ldap._tcp.dc._msdcs.corp.com" in res["errors"][0]


def test_discovery_off_uses_only_configured(ad):
    cfg = {"domain": "corp.com", "discover": False, "servers": ["dc1"]}
    res = ad.candidate_servers(cfg, _lookup({"_gc._tcp.corp.com": [{"target": "x", "port": 3268}]}))
    assert [s["host"] for s in res["servers"]] == ["dc1"]


def test_base_dn_for(ad):
    assert ad.base_dn_for("corp.example.com.") == "DC=corp,DC=example,DC=com"


# ---- Bind and search -------------------------------------------------------------

class _Conn:
    def __init__(self, ldap, uri, behaviour, entries=()):
        self.ldap, self.uri, self.behaviour, self.entries = ldap, uri, behaviour, list(entries)
        self.opts = {}

    def set_option(self, k, v):
        self.opts[k] = v

    def start_tls_s(self):
        self.tls = True
        if self.behaviour == "notls":
            raise self.ldap.LDAPError("StartTLS refused")

    def simple_bind_s(self, who, pw):
        self.bound_with_tls = self.uri.startswith("ldaps://") or getattr(self, "tls", False)
        if self.behaviour == "down":
            raise self.ldap.SERVER_DOWN("can't contact")
        if self.behaviour == "badpw":
            raise self.ldap.INVALID_CREDENTIALS("49")

    def unbind_s(self):
        if self.behaviour == "badunbind":
            raise self.ldap.SERVER_DOWN("connection reset")

    def search_ext(self, base, scope, filt, attrs, sizelimit=0):
        self.search = (base, filt, sizelimit)
        self.queue = [(self.ldap.RES_SEARCH_ENTRY, [e]) for e in self.entries[:sizelimit]]
        self.over = len(self.entries) > sizelimit
        return 1

    def result3(self, msgid, all=0):
        if self.queue:
            return self.queue.pop(0) + (msgid, [])
        if self.over:
            raise self.ldap.SIZELIMIT_EXCEEDED("4")
        return (self.ldap.RES_SEARCH_RESULT, [], msgid, [])


def _dir(ad, behaviours, entries=(), **cfg):
    base = {"domain": "corp.com", "discover": False, "bind_user": "svc@corp.com",
            "bind_password": "pw", "servers": list(behaviours)}
    base.update(cfg)
    made = []

    def connect(uri):
        host = uri.split("//")[1].split(":")[0]
        made.append(_Conn(sys.modules["ldap"], uri, behaviours[host], entries))
        return made[-1]
    return ad.AdDirectory(base, connect=connect), made


def test_failover_to_backup_when_primary_down(ad):
    d, made = _dir(ad, {"dc1": "down", "dc2": "ok"})
    res = d.test()
    assert res["status"] == "SUCCESS" and res["server"]["host"] == "dc2"
    assert [a["ok"] for a in res["attempts"]] == [False, True]
    assert made[1].uri == "ldaps://dc2:3269"


def test_bad_password_is_not_retried_on_backup(ad):
    d, made = _dir(ad, {"dc1": "badpw", "dc2": "ok"})
    res = d.test()
    assert res["error"] == "INVALID_CREDENTIALS" and len(made) == 1


def test_all_down_and_empty_password(ad):
    d, _ = _dir(ad, {"dc1": "down", "dc2": "down"})
    assert "no AD server answered" in d.test()["message"]
    d, made = _dir(ad, {"dc1": "ok"}, bind_password="")
    res = d.test()
    # No credentials is its own state (the operation never ran), not an outage.
    assert res["status"] == "ERROR" and res["error"] == "NO_CREDENTIALS" and made == []
    assert d.search_users()["error"] == "NO_CREDENTIALS"


def test_a_failed_unbind_does_not_turn_success_into_error(ad):
    entries = [("CN=u0,DC=corp,DC=com", {"sAMAccountName": [b"u0"]})]
    d, _ = _dir(ad, {"dc1": "badunbind"}, entries=entries)
    assert d.test()["status"] == "SUCCESS"
    res = d.search_users()
    assert res["status"] == "SUCCESS" and [u["username"] for u in res["data"]] == ["u0"]


def test_not_configured(ad):
    res = ad.AdDirectory({}).discover()
    assert res["status"] == "ERROR" and res["error"] == "NOT_CONFIGURED"


def test_discover_with_no_server_left_is_an_error(ad):
    # Every lookup failed and nothing is configured: not an empty success.
    res = ad.AdDirectory({"domain": "corp.com"}, lookup=_lookup({})).discover()
    assert res["status"] == "ERROR" and res["servers"] == [] and res["errors"]
    assert "no AD server found" in res["message"]
    # A failed lookup next to a configured server is only a warning.
    res = ad.AdDirectory({"domain": "corp.com", "servers": ["dc1"]}, lookup=_lookup({})).discover()
    assert res["status"] == "SUCCESS" and res["errors"]


def test_search_users_maps_and_keeps_partial_results(ad):
    entries = [(f"CN=u{i},DC=corp,DC=com",
                {"sAMAccountName": [f"u{i}".encode()], "userPrincipalName": [f"u{i}@corp.com".encode()],
                 "userAccountControl": [b"514" if i == 1 else b"512"]}) for i in range(3)]
    # An account whose userAccountControl the bind cannot read: state unknown.
    entries.append(("CN=u3,DC=corp,DC=com", {"sAMAccountName": [b"u3"]}))
    entries.append((None, ["ldap://other/"]))  # referral
    d, made = _dir(ad, {"dc1": "ok"}, entries=entries)
    res = d.search_users("u*", limit=2)
    assert res["status"] == "SUCCESS" and res["truncated"] is True
    assert [(u["username"], u["enabled"]) for u in res["data"]] == [("u0", True), ("u1", False)]
    base, filt, limit = made[0].search
    assert base == "DC=corp,DC=com" and limit == 2 and r"u\2a*" in filt
    res = d.search_users("", limit=10)
    assert res["truncated"] is False and len(res["data"]) == 4
    assert res["data"][3]["enabled"] is None


def test_plain_port_binds_only_after_starttls(ad):
    # use_ssl off (even as the string "false") means 3268 + StartTLS: the
    # password is never sent in clear, and a server without TLS is skipped.
    d, made = _dir(ad, {"dc1": "notls", "dc2": "ok"}, use_ssl="false")
    res = d.test()
    assert res["status"] == "SUCCESS" and res["server"]["host"] == "dc2"
    assert made[1].uri == "ldap://dc2:3268" and made[1].bound_with_tls
    assert not hasattr(made[0], "bound_with_tls")


def test_string_false_flags_are_honoured_everywhere(ad):
    # Hub forms may push switches as strings; "false" must mean off in the
    # SRV names, the port choice and the discovery switch alike.
    cfg = {"domain": "corp.com", "use_global_catalog": "false"}
    assert ad.srv_names(cfg) == ["_ldap._tcp.dc._msdcs.corp.com"]
    res = ad.candidate_servers(cfg, _lookup({"_ldap._tcp.dc._msdcs.corp.com":
                                             [{"target": "dc1", "port": 389}]}))
    assert [(s["host"], s["port"], s["ssl"]) for s in res["servers"]] == [("dc1", 636, True)]
    off = {"domain": "corp.com", "discover": "false", "servers": ["dc9"]}
    res = ad.candidate_servers(off, _lookup({"_gc._tcp.corp.com": [{"target": "x", "port": 3268}]}))
    assert [s["host"] for s in res["servers"]] == ["dc9"]
    assert not ad.AdDirectory({"domain": "corp.com", "discover": "false"}).configured()


def test_explicit_ldaps_port_always_uses_ldaps(ad):
    cfg = {"use_ssl": False, "discover": False, "servers": ["dc1", "dc2:636"]}
    res = ad.candidate_servers(cfg, _lookup({}))
    assert [(s["port"], s["ssl"]) for s in res["servers"]] == [(3268, False), (636, True)]


def test_ipv6_server_uri_is_bracketed(ad):
    made = []

    def connect(uri):
        made.append(_Conn(sys.modules["ldap"], uri, "ok"))
        return made[-1]
    d = ad.AdDirectory({"discover": False, "bind_user": "svc", "bind_password": "pw",
                        "servers": ["[fd00::5]:1389"]}, connect=connect)
    assert d.test()["status"] == "SUCCESS"
    assert made[0].uri == "ldaps://[fd00::5]:1389"
