"""LdapSpoke list/read handlers return a clean ERROR envelope on LDAPError.

Previously the list/read handlers (LIST_OUS / LIST_USERS / LIST_GROUPS /
LDAP_LIST_USERS / LDAP_LIST_GROUPS) let ``ldap.LDAPError`` propagate; the
control plane catches it but via ``logger.exception``, dumping a 30-line
traceback PER CALL into the spoke log. A stale admin password (bind result 49
= ``INVALID_CREDENTIALS``) therefore spammed the log on every poll. These
handlers now catch ``LDAPError`` and return a targeted ERROR envelope — one
log line, and a "re-push LDAP_ADMIN_PW" hint for the common bind failure.

Self-contained: stubs python-ldap (not installed in dev) including
``INVALID_CREDENTIALS``, loads ldap_spoke as a synthetic namespace package
(mirrors test_install_cert.py's harness), and monkeypatches the manager's
list methods to raise.
"""
import asyncio
import importlib.util
import re
import sys
import time
import types
from pathlib import Path

import pytest

_PXMX_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, "/Users/lbockenstedt/vscode/lm/core/src")

# Stub python-ldap just enough that ldap_manager + ldap_spoke import. Adds
# INVALID_CREDENTIALS (the bind-failure result 49) — the install_cert stub
# doesn't need it, but the error-envelope path does.
_ldap = types.ModuleType("ldap")
_ldap.SCOPE_SUBTREE = 2
_ldap.LDAPError = type("LDAPError", (Exception,), {})
_ldap.INVALID_CREDENTIALS = type("INVALID_CREDENTIALS", (_ldap.LDAPError,), {})
_ldap.MOD_ADD = 0
_ldap.MOD_DELETE = 1
_ldap.MOD_REPLACE = 2
_ldap.initialize = lambda url: None
_ldap.filter = types.ModuleType("ldap.filter")
_ldap.dn = types.ModuleType("ldap.dn")
_ldap.dn.escape_dn_chars = lambda v: v
sys.modules["ldap"] = _ldap
sys.modules["ldap.filter"] = _ldap.filter
sys.modules["ldap.dn"] = _ldap.dn
_ldap.modlist = types.ModuleType("ldap.modlist")
_ldap.modlist.addModlist = lambda entry: [(k, v) for k, v in entry.items() if v]
sys.modules["ldap.modlist"] = _ldap.modlist

SRC = _PXMX_ROOT / "src"
_pkg = types.ModuleType("ldap_src_pkg")
_pkg.__path__ = [str(SRC)]
sys.modules["ldap_src_pkg"] = _pkg
_spec_m = importlib.util.spec_from_file_location(
    "ldap_src_pkg.ldap_manager", SRC / "ldap_manager.py")
_mgr = importlib.util.module_from_spec(_spec_m)
sys.modules["ldap_src_pkg.ldap_manager"] = _mgr
_spec_m.loader.exec_module(_mgr)
_spec_s = importlib.util.spec_from_file_location(
    "ldap_src_pkg.ldap_spoke", SRC / "ldap_spoke.py")
spoke_mod = importlib.util.module_from_spec(_spec_s)
sys.modules["ldap_src_pkg.ldap_spoke"] = spoke_mod
_spec_s.loader.exec_module(spoke_mod)
LdapSpoke = spoke_mod.LdapSpoke
LdapBindError = _mgr.LdapBindError
LDAPError = _ldap.LDAPError
INVALID_CREDENTIALS = _ldap.INVALID_CREDENTIALS


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


def _spoke():
    return LdapSpoke("ldap-1", {})


def test_list_ous_invalid_credentials_returns_clean_envelope():
    sp = _spoke()
    sp.manager.list_ous = lambda: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LIST_OUS", {}))
    assert res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"
    assert "LDAP_ADMIN_PW" in res["message"]


def test_ldap_list_users_invalid_credentials_returns_clean_envelope():
    sp = _spoke()
    sp.manager.list_users_scoped = lambda slug: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LDAP_LIST_USERS", {"tenant_slug": "lrb"}))
    assert res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"


def test_list_ous_does_not_raise_on_invalid_credentials():
    # The whole point: the handler must NOT raise (which would trigger the
    # control plane's logger.exception traceback dump). It returns a dict.
    sp = _spoke()
    sp.manager.list_ous = lambda: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LIST_OUS", {}))
    assert isinstance(res, dict) and "status" in res


def test_generic_ldap_error_envelope_has_type_and_message():
    sp = _spoke()
    sp.manager.list_groups = lambda: (_ for _ in ()).throw(
        LDAPError("server down"))
    res = _run(sp.handle_command("LIST_GROUPS", {}))
    assert res["status"] == "ERROR"
    assert "LDAPError" in res["message"]
    assert "server down" in res["message"]


def test_ldap_list_groups_invalid_credentials_returns_clean_envelope():
    sp = _spoke()
    sp.manager.list_groups_scoped = lambda slug: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LDAP_LIST_GROUPS", {"tenant_slug": "lrb"}))
    assert res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"


def test_list_users_invalid_credentials_returns_clean_envelope():
    sp = _spoke()
    sp.manager.list_users = lambda: (_ for _ in ()).throw(
        INVALID_CREDENTIALS("result 49"))
    res = _run(sp.handle_command("LIST_USERS", {}))
    assert res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"


def test_list_ous_served_from_cache_within_ttl():
    # Counting fake: a repeated read inside the TTL makes ONE LDAP call.
    sp = _spoke()
    calls = []
    sp.manager.list_ous_scoped = lambda slug: (calls.append(slug),
                                               {"status": "SUCCESS", "ous": []})[1]
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    assert len(calls) == 1


def test_ou_cache_is_per_tenant():
    sp = _spoke()
    calls = []
    sp.manager.list_ous_scoped = lambda slug: (calls.append(slug),
                                               {"status": "SUCCESS", "ous": []})[1]
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "other"}))
    assert calls == ["lrb", "other"]


def test_concurrent_misses_are_coalesced():
    # Single-flight: five simultaneous misses make one LDAP call.
    sp = _spoke()
    calls = []

    def slow(slug):
        calls.append(slug)
        time.sleep(0.05)
        return {"status": "SUCCESS", "ous": []}

    sp.manager.list_ous_scoped = slow

    async def many():
        return await asyncio.gather(*[
            sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"})
            for _ in range(5)])

    _run(many())
    assert len(calls) == 1


def test_failed_read_is_not_cached():
    sp = _spoke()
    calls = []
    sp.manager.list_ous_scoped = lambda slug: (calls.append(slug),
                                               {"status": "ERROR", "message": "boom"})[1]
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    assert len(calls) == 2


def test_successful_write_invalidates_the_cache():
    sp = _spoke()
    calls = []
    sp.manager.list_ous_scoped = lambda slug: (calls.append(slug),
                                               {"status": "SUCCESS", "ous": []})[1]
    sp.manager.create_ou_scoped = lambda name, parent, slug: {"status": "SUCCESS"}
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    _run(sp.handle_command("LDAP_CREATE_OU", {"tenant_slug": "lrb", "name": "Lab"}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    assert len(calls) == 2


def test_write_during_an_in_flight_read_prevents_stale_cache():
    # A write landing while the read is in flight bumps the generation, so the
    # pre-write answer is returned but never stored.
    sp = _spoke()
    calls = []

    def racing(slug):
        calls.append(slug)
        sp._ou_cache_invalidate(slug)
        return {"status": "SUCCESS", "ous": ["stale"]}

    sp.manager.list_ous_scoped = racing
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    assert len(calls) == 2


def _prime(sp, calls):
    sp.manager.list_ous_scoped = lambda slug: (calls.append(slug),
                                               {"status": "SUCCESS", "ous": []})[1]
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))


def test_partial_rollback_invalidates_the_cache():
    sp = _spoke()
    calls = []
    _prime(sp, calls)
    sp.manager.move_user_scoped = lambda *a: {"status": "ERROR", "error": "PARTIAL_ROLLBACK"}
    _run(sp.handle_command("LDAP_MOVE_USER", {"uid": "a", "target_path": "X", "tenant_slug": "lrb"}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    assert len(calls) == 2


def test_update_config_clears_the_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_ENV_PATH", str(tmp_path / ".env"))
    sp = _spoke()
    calls = []
    _prime(sp, calls)
    _run(sp.handle_command("UPDATE_CONFIG", {"LDAP_BASE_DN": "dc=x,dc=y", "LDAP_ADMIN_PW": "pw"}))
    sp.manager.list_ous_scoped = lambda slug: (calls.append(slug),
                                               {"status": "SUCCESS", "ous": []})[1]
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    assert len(calls) == 2


def test_legacy_dn_write_clears_the_cache():
    sp = _spoke()
    calls = []
    _prime(sp, calls)
    sp.manager.delete_entity = lambda dn: {"status": "SUCCESS"}
    _run(sp.handle_command("DELETE_ENTITY", {"dn": "ou=x"}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    assert len(calls) == 2


@pytest.mark.parametrize("read_slug,write_slug", [
    (" lrb ", "LRB"), ("lrb", " LRB "), (None, ""),
])
def test_ou_cache_uses_canonical_tenant_identity(read_slug, write_slug):
    """Equivalent slugs share both cached reads and write invalidation."""
    sp = _spoke()
    calls = []
    sp.manager.list_ous_scoped = lambda slug: (
        calls.append(slug), {"status": "SUCCESS", "ous": []})[1]
    sp.manager.create_ou_scoped = lambda *a: {"status": "SUCCESS"}
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": read_slug}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": write_slug}))
    assert len(calls) == 1
    _run(sp.handle_command("LDAP_CREATE_OU", {
        "tenant_slug": write_slug, "name": "Lab"}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": read_slug}))
    assert len(calls) == 2


@pytest.mark.parametrize("slug", ["   ", "bad,slug"])
def test_invalid_slug_cannot_read_the_base_cache(slug):
    """Invalid tenant identities never alias a cached base-level listing."""
    sp = _spoke()
    calls = []
    sp.manager.list_ous_scoped = lambda tenant: (
        calls.append(tenant), {"status": "SUCCESS", "ous": []})[1]
    _run(sp.handle_command("LDAP_LIST_OUS", {}))
    result = _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": slug}))
    assert result["status"] == "ERROR"
    assert calls == [None]
    sp.manager.create_ou_scoped = lambda *a: {"status": "ERROR", "message": "invalid slug"}
    result = _run(sp.handle_command("LDAP_CREATE_OU", {
        "tenant_slug": slug, "name": "Lab"}))
    assert result == {"status": "ERROR", "message": "invalid slug"}


def test_partial_migration_invalidates_every_tenant():
    """A migration can move entries before returning PARTIAL."""
    sp = _spoke()
    calls = []
    _prime(sp, calls)
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "other"}))
    partial = {"status": "PARTIAL", "moved": ["uid=a,ou=users,dc=old"]}
    sp.manager.migrate_tenant = lambda *a: partial
    result = _run(sp.handle_command("LDAP_MIGRATE_TENANT", {
        "source_base_dn": "dc=old", "target_base_dn": "dc=new"}))
    assert result == partial
    for slug in ("lrb", "other"):
        _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": slug}))
    assert calls == ["lrb", "other", "lrb", "other"]


@pytest.mark.parametrize("command", ["LDAP_CREATE_OU", "DELETE_ENTITY"])
@pytest.mark.parametrize("raises", [False, True])
def test_unknown_write_outcome_invalidates_cache(command, raises):
    """Returned and propagated LDAP failures may follow a committed write."""
    sp = _spoke()
    calls = []
    _prime(sp, calls)

    def uncertain_write(*args):
        """Simulate a lost response after a possible directory mutation."""
        if raises:
            raise LDAPError("connection lost after write")
        return {"status": "ERROR", "message": "connection lost after write"}

    sp.manager.create_ou_scoped = uncertain_write
    sp.manager.delete_entity = uncertain_write
    result = _run(sp.handle_command(command, {
        "tenant_slug": "lrb", "name": "Lab", "dn": "ou=Lab"}))
    assert result["status"] == "ERROR"
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    assert len(calls) == 2


@pytest.mark.parametrize("error", ["NOT_PROVISIONED", "INVALID_CREDENTIALS"])
def test_known_clean_refusal_preserves_cache(error):
    """Explicit pre-mutation refusals need not discard a valid cached read."""
    sp = _spoke()
    calls = []
    _prime(sp, calls)
    sp.manager.create_ou_scoped = lambda *a: {"status": "ERROR", "error": error}
    _run(sp.handle_command("LDAP_CREATE_OU", {"tenant_slug": "lrb", "name": "Lab"}))
    _run(sp.handle_command("LDAP_LIST_OUS", {"tenant_slug": "lrb"}))
    assert len(calls) == 1


def test_success_path_still_wraps_data():
    sp = _spoke()
    sp.manager.list_ous = lambda: [{"name": "users", "dn": "ou=users,dc=example,dc=org"}]
    res = _run(sp.handle_command("LIST_OUS", {}))
    assert res["status"] == "SUCCESS"
    assert res["data"][0]["name"] == "users"


# ── write path: a bind failure must surface as the targeted envelope ───────
# The manager's _bind() raises LdapBindError (NOT an LDAPError) on
# INVALID_CREDENTIALS so it bypasses the per-method `except ldap.LDAPError`
# blocks (which used to log + return the raw {'result':49,…} dict). The spoke's
# _ldap_write catches it and maps it to the clean INVALID_CREDENTIALS envelope.
def test_write_bind_failure_returns_targeted_envelope():
    sp = _spoke()

    def _boom(*a, **k):
        raise LdapBindError(
            "LDAP bind failed: invalid credentials — the LDAP_ADMIN_PW in this "
            "spoke's config does not match slapd's admin password. Re-push the "
            "correct password via Setup → LDAP (UPDATE_CONFIG).")

    sp.manager.create_user_scoped = _boom
    res = _run(sp.handle_command("LDAP_CREATE_USER", {
        "uid": "lance", "attrs": {"cn": "Lance", "sn": "B",
                                  "mail": "l@x.org"},
        "tenant_slug": "lrb", "auth_mode": "local"}))
    assert res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"
    assert "LDAP_ADMIN_PW" in res["message"]
    assert "UPDATE_CONFIG" in res["message"]


def test_write_bind_failure_does_not_raise():
    # The whole point: a bind failure on a write must NOT propagate (which
    # would trigger the control plane's logger.exception traceback dump).
    sp = _spoke()
    sp.manager.create_group_scoped = lambda *a, **k: (_ for _ in ()).throw(
        LdapBindError("bind failed"))
    res = _run(sp.handle_command("LDAP_CREATE_GROUP",
                                 {"cn": "admins", "tenant_slug": "lrb"}))
    assert isinstance(res, dict) and res["status"] == "ERROR"
    assert res["error"] == "INVALID_CREDENTIALS"


def test_write_operation_error_passes_through_unchanged():
    # A legit per-operation error (e.g. ALREADY_EXISTS) is caught inside the
    # manager method and returned as {status:ERROR, message:str(e)} — _ldap_write
    # must NOT remap it to INVALID_CREDENTIALS (only a bind failure is).
    sp = _spoke()
    sp.manager.create_user_scoped = lambda *a, **k: {
        "status": "ERROR", "message": "Already exists"}
    res = _run(sp.handle_command("LDAP_CREATE_USER", {
        "uid": "dup", "attrs": {}, "tenant_slug": "lrb"}))
    assert res["status"] == "ERROR"
    assert res.get("error") is None  # not remapped to INVALID_CREDENTIALS
    assert res["message"] == "Already exists"


def test_manager_bind_raises_ldap_bind_error_on_invalid_credentials():
    # The manager's _bind() converts a raw INVALID_CREDENTIALS from simple_bind_s
    # into a LdapBindError carrying the actionable message (so per-method
    # `except ldap.LDAPError` blocks don't swallow it).
    class _Conn:
        def simple_bind_s(self, dn, pw):
            raise INVALID_CREDENTIALS("result 49")
        def unbind_s(self):
            pass
    mgr = _mgr.LdapManager("cn=admin,dc=example,dc=org", "wrong",
                           "dc=example,dc=org", "ldap://localhost:389")
    with pytest.raises(LdapBindError) as ei:
        mgr._bind(_Conn())
    assert "LDAP_ADMIN_PW" in str(ei.value)
    assert "UPDATE_CONFIG" in str(ei.value)

def test_malformed_ou_path_is_an_error_not_the_root():
    # A dict/number path must not be read as "move to ou=users"; an explicit
    # empty path still means the root.
    sp = _spoke()
    calls = []
    sp.manager.move_user_scoped = lambda *a: calls.append(a) or {"status": "SUCCESS"}
    res = _run(sp.handle_command("LDAP_MOVE_USER", {
        "uid": "alice", "target_path": {"x": 1}, "tenant_slug": "lrb"}))
    assert res["status"] == "ERROR" and "target_path" in res["message"] and calls == []
    res = _run(sp.handle_command("LDAP_MOVE_USER", {
        "uid": "alice", "target_path": ["Eng", 5], "tenant_slug": "lrb"}))
    assert res["status"] == "ERROR" and calls == []
    for blank in ("/", "   ", "Eng//Lab", ["Eng", " "]):
        res = _run(sp.handle_command("LDAP_MOVE_USER", {
            "uid": "alice", "target_path": blank, "tenant_slug": "lrb"}))
        assert res["status"] == "ERROR" and calls == [], blank
    res = _run(sp.handle_command("LDAP_MOVE_USER", {
        "uid": "alice", "target_path": "", "tenant_slug": "lrb"}))
    assert res["status"] == "SUCCESS" and calls == [("alice", [], "lrb")]


def test_ldap_list_on_unprovisioned_tenant_is_not_provisioned_not_empty():
    sp = _spoke()
    for cmd, attr in (("LDAP_LIST_USERS", "list_users_scoped"),
                      ("LDAP_LIST_GROUPS", "list_groups_scoped")):
        setattr(sp.manager, attr, lambda slug: (_ for _ in ()).throw(
            _mgr.TenantNotProvisionedError("this tenant's directory is not provisioned")))
        res = _run(sp.handle_command(cmd, {"tenant_slug": "newco"}))
        assert res == {"status": "ERROR", "error": "NOT_PROVISIONED",
                       "message": "this tenant's directory is not provisioned"}, res


def test_ad_commands_use_the_connection_sent_with_the_command(monkeypatch):
    seen = []

    class _FakeAd:
        def __init__(self, cfg):
            self.cfg = cfg
            seen.append(cfg)

        def configured(self):
            return bool(self.cfg.get("domain"))

        def test(self):
            return {"status": "SUCCESS", "server": "dc1"}
    monkeypatch.setattr(spoke_mod, "AdDirectory", _FakeAd)
    sp = LdapSpoke("ldap-1", {"ad": {"domain": "stale.example", "bind_password": "old"}})
    conn = {"domain": "corp.example", "bind_password": "from-vault"}
    assert _run(sp.handle_command("AD_TEST", {"ad": conn})) == {"status": "SUCCESS", "server": "dc1"}
    # The spoke's own config is never used for AD.
    assert seen == [conn]
    # No connection, or one with no domain, is NOT_CONFIGURED for every verb.
    blank = {"bind_password": "x"}
    for cmd in ("AD_TEST", "AD_DISCOVER", "AD_SEARCH_USERS"):
        for data in ({}, {"ad": blank}):
            res = _run(sp.handle_command(cmd, data))
            assert res["status"] == "ERROR" and res["error"] == "NOT_CONFIGURED", (cmd, res)
    assert seen == [conn] + [blank] * 3


def test_replication_errors_never_carry_the_admin_password():
    """slapd can echo the rejected olcSyncrepl value; the UPDATE_CONFIG
    reply must not pass the password on to the hub."""
    sp = _spoke()
    pw = 'Pa"ss w0rd'

    async def _echo(ldif, tolerate=""):
        return f'ldapmodify failed: olcSyncrepl: bad credentials="{pw}" rid=001 ({pw})'
    sp._ldapmodify_tolerant = _echo
    ok, note = asyncio.run(sp._apply_replication_config({
        "LDAP_BASE_DN": "dc=x", "LDAP_ADMIN_DN": "cn=admin,dc=x", "LDAP_ADMIN_PW": pw},
        1, ["ldap://peer:389"]))
    assert not ok and "failed" in note and "credentials=***" in note
    assert "w0rd" not in note


# ── UPDATE_CONFIG: the hub's payload contract (lm main.py _ldap_config_for_spoke) ──

_PEM_KEY = "-----BEGIN PRIVATE KEY-----\nAAA=\nBBB==\n-----END PRIVATE KEY-----"
_PEM_CERT = "-----BEGIN CERTIFICATE-----\nCCC\n-----END CERTIFICATE-----"


def _hub_push(**extra):
    """A payload shaped like the hub's push for a single node."""
    cfg = {"LDAP_SERVER_URL": "ldap://localhost:389", "LDAP_BASE_DN": "dc=x,dc=y",
           "LDAP_ADMIN_DN": "cn=admin,dc=x,dc=y", "LDAP_ADMIN_PW": "pw",
           "LDAP_SERVER_ID": "inst-7f3a", "LDAP_MIRROR_PEERS": "[]",
           "ENTRA_TENANT_ID": "t", "ENTRA_CLIENT_ID": "c",
           "ENTRA_CLIENT_CERT": _PEM_CERT, "ENTRA_CLIENT_KEY": _PEM_KEY,
           "ENTRA_ROPC_SCOPE": "openid"}
    cfg.update(extra)
    return cfg


def _load_ropc():
    spec = importlib.util.spec_from_file_location("entra_ropc_auth_t", _PXMX_ROOT / "src" / "entra_ropc_auth.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_update_config_stores_pushed_entra_pems_as_files(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    monkeypatch.setenv("LDAP_ENV_PATH", str(env))
    for k in ("ENTRA_CLIENT_CERT", "ENTRA_CLIENT_KEY"):
        monkeypatch.delenv(k, raising=False)
    # An older spoke left a multi-line PEM in .env; it is dropped on rewrite.
    env.write_text("KEEP=1\nENTRA_CLIENT_KEY=" + _PEM_KEY + "\nOTHER=2\n")
    sp = _spoke()
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push()))
    assert res["status"] == "SUCCESS", res
    text = env.read_text()
    assert "BEGIN" not in text and "AAA=" not in text
    assert "KEEP=1" in text and "OTHER=2" in text
    cfg = _load_ropc().load_config(str(env))
    key_path, cert_path = Path(cfg["key_path"]), Path(cfg["cert_path"])
    assert key_path.read_text().strip() == _PEM_KEY
    assert cert_path.read_text().strip() == _PEM_CERT
    assert oct(key_path.stat().st_mode & 0o777) == "0o600"
    # A blank cert/key from the hub keeps the stored paths.
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push(ENTRA_CLIENT_CERT="", ENTRA_CLIENT_KEY="")))
    assert res["status"] == "SUCCESS"
    assert _load_ropc().load_config(str(env))["key_path"] == str(key_path)


def test_update_config_applies_hub_mirror_peer_dicts(tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_ENV_PATH", str(tmp_path / ".env"))
    sp = _spoke()
    applied = []

    async def _modify(ldif):
        applied.append(ldif)
    sp._ldapmodify = _modify

    async def _ids():
        return []
    sp._read_server_ids = _ids
    peers = '[{"server_id": "2", "url": "ldap://peer2:389"}]'
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push(LDAP_SERVER_ID="1", LDAP_MIRROR_PEERS=peers)))
    assert res["status"] == "SUCCESS", res
    assert any('provider="ldap://peer2:389"' in l for l in applied)
    # A single node ("[]" peers, non-numeric instance id) touches no replication.
    applied.clear()
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push()))
    assert res["status"] == "SUCCESS" and applied == []


def test_update_config_rejects_bad_input_without_changing_anything(tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_ENV_PATH", str(tmp_path / ".env"))
    sp = LdapSpoke("ldap-1", {"LDAP_ADMIN_PW": "old", "LDAP_TLS_CERT": "/etc/ldap/tls/c.pem"})
    before = sp.manager
    # No admin password anywhere: refused rather than defaulted.
    sp2 = _spoke()
    res = _run(sp2.handle_command("UPDATE_CONFIG", {"LDAP_BASE_DN": "dc=x,dc=y"}))
    assert res["status"] == "ERROR" and "LDAP_ADMIN_PW" in res["message"]
    assert sp.manager is before and not (tmp_path / ".env").exists()
    # A valid push merges: keys the hub doesn't send (LDAP_TLS_*) survive,
    # and a None admin password keeps the current one.
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push(LDAP_ADMIN_PW=None)))
    assert res["status"] == "SUCCESS"
    assert sp.config["LDAP_TLS_CERT"] == "/etc/ldap/tls/c.pem"
    assert sp.manager.admin_pw == "old"


def test_multi_instance_hub_push_applies_connection_and_skips_replication(tmp_path, monkeypatch):
    """With 2+ ldap_instances and no Setup server_id the hub sends the
    instance UUID as LDAP_SERVER_ID plus peers derived from the other
    instances. The connection settings must still apply (PARTIAL), with
    replication left untouched."""
    env = tmp_path / ".env"
    monkeypatch.setenv("LDAP_ENV_PATH", str(env))
    sp = LdapSpoke("ldap-1", {"LDAP_ADMIN_PW": "old"})
    applied = []

    async def _modify(ldif):
        applied.append(ldif)
    sp._ldapmodify = _modify
    for peers in ('[{"server_id": "9b1c2d3e-0000-4000-8000-000000000002", "url": "ldap://p:389"}]',
                  '[not json'):
        res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push(
            LDAP_SERVER_ID="7f3a9c4e-0000-4000-8000-000000000001", LDAP_MIRROR_PEERS=peers,
            LDAP_ADMIN_PW="new-pw", LDAP_BASE_DN="dc=new,dc=y")))
        assert res["status"] == "PARTIAL", res
        assert "replication not applied" in res["message"]
        assert sp.manager.admin_pw == "new-pw" and sp.manager.base_dn == "dc=new,dc=y"
        assert "ENTRA_CLIENT_KEY=" in env.read_text()
        assert applied == []


def test_cleanup_only_deletes_files_the_spoke_named(tmp_path, monkeypatch):
    """Superseded PEMs are removed only when they carry the spoke's own
    randomised name; installer or operator files beside .env survive."""
    monkeypatch.setenv("LDAP_ENV_PATH", str(tmp_path / ".env"))
    sp = _spoke()
    names = ["entra-client.crt", "entra-client-prod.key", "entra-client.0123456789ab.crt.bak",
             "entra-client.0123456789ab.key"]
    for n in names:
        (tmp_path / n).write_text("x")
    sp._remove_spoke_pems([str(tmp_path / n) for n in names])
    left = sorted(p.name for p in tmp_path.iterdir())
    assert left == sorted(names[:3])


def test_update_config_reports_a_failed_step_as_error(tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_ENV_PATH", str(tmp_path / ".env"))
    sp = _spoke()

    async def _fail(ldif):
        raise spoke_mod._CertInstallError("ldapmodify: Insufficient access")
    sp._ldapmodify = _fail
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push(
        LDAP_SERVER_ID="1", LDAP_MIRROR_PEERS='["ldap://p:389"]')))
    assert res["status"] == "ERROR" and "replication" in res["message"]
    # .env persist failure is an ERROR too, not a SUCCESS with a note.
    def _boom(data):
        raise OSError("read-only file system")
    sp._persist_env = _boom
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push()))
    assert res["status"] == "ERROR" and "env persist failed" in res["message"]


def _snapshot(tmp_path, sp):
    """Everything a failed UPDATE_CONFIG must leave alone."""
    files = {p.name: p.read_bytes() for p in sorted(tmp_path.iterdir())}
    return sp.manager, dict(sp.config), files


def test_failed_replication_leaves_runtime_env_and_pems_unchanged(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    monkeypatch.setenv("LDAP_ENV_PATH", str(env))
    sp = _spoke()
    assert _run(sp.handle_command("UPDATE_CONFIG", _hub_push()))["status"] == "SUCCESS"
    before = _snapshot(tmp_path, sp)

    async def _ids():
        return []

    async def _fail(ldif):
        if "olcSyncrepl" in ldif:
            raise spoke_mod._CertInstallError("ldapmodify failed: Other (e.g., implementation specific) error")
    sp._read_server_ids, sp._ldapmodify = _ids, _fail
    # New Entra key + base DN + peers: every step runs before replication fails.
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push(
        LDAP_BASE_DN="dc=new,dc=y", LDAP_SERVER_ID="1", LDAP_MIRROR_PEERS='["ldap://p:389"]',
        ENTRA_CLIENT_KEY=_PEM_KEY.replace("AAA=", "ZZZ="))))
    assert res["status"] == "ERROR" and "not applied" in res["message"], res
    manager, config, files = _snapshot(tmp_path, sp)
    assert manager is before[0] and config == before[1] and files == before[2]


def test_failed_mirror_modify_restores_the_previous_server_id(tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_ENV_PATH", str(tmp_path / ".env"))
    sp = _spoke()
    applied = []

    async def _ids():
        return [b"3"]

    async def _modify(ldif):
        applied.append(ldif)
        if "olcSyncrepl" in ldif:
            raise spoke_mod._CertInstallError('ldapmodify failed: bad olcSyncrepl credentials="pw" rid=001')
    sp._read_server_ids, sp._ldapmodify = _ids, _modify
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push(
        LDAP_SERVER_ID="1", LDAP_MIRROR_PEERS='["ldap://p:389"]', LDAP_ADMIN_PW="s3cr3t-pw")))
    assert res["status"] == "ERROR"
    # Neither the quoted credentials nor the raw password reach the reply.
    assert "credentials=***" in res["message"] and '"pw"' not in res["message"]
    server_id_writes = [l for l in applied if "olcServerID" in l]
    assert "olcServerID: 1" in server_id_writes[0] and "olcServerID: 3" in server_id_writes[-1]
    # syncrepl and mirror mode go in one modify record.
    mirror = next(l for l in applied if "olcSyncrepl" in l)
    assert "replace: olcMirrorMode" in mirror and mirror.count("dn:") == 1


def test_an_unchanged_server_id_is_not_rewritten(tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_ENV_PATH", str(tmp_path / ".env"))
    sp = _spoke()
    applied = []

    async def _ids():
        return [b"1"]

    async def _modify(ldif):
        applied.append(ldif)
    sp._read_server_ids, sp._ldapmodify = _ids, _modify
    res = _run(sp.handle_command("UPDATE_CONFIG", _hub_push(
        LDAP_SERVER_ID="1", LDAP_MIRROR_PEERS='["ldap://p:389"]')))
    assert res["status"] == "SUCCESS", res
    assert not any("olcServerID" in l for l in applied)


def test_read_server_ids_parses_ldapsearch_output():
    sp = _spoke()

    async def _search(tool, args, stdin=b""):
        assert tool == "ldapsearch" and "olcServerID" in args
        return (b"dn: cn=config\nolcServerID: 2 ldap://a:389\nolcServerID:: Mw==\n"
                b"olcServerID: 4 ldap://folded-\n host:389\n\n")
    sp._run_ldapi = _search
    assert _run(sp._read_server_ids()) == [b"2 ldap://a:389", b"3", b"4 ldap://folded-host:389"]


def test_spoke_imports_without_python_ldap_ldif():
    """CI can't build python-ldap and stubs only the ldap package, so the
    spoke must not import python-ldap's top-level ldif module."""
    src = (Path(spoke_mod.__file__)).read_text()
    assert not re.search(r"^\s*(import ldif|from ldif )", src, re.M)


def test_server_id_ldif_round_trips_any_value():
    values = [b"1 ldap://a:389", b" lead", b"\xc3\xa9t\xc3\xa9", b"x:y"]
    out = LdapSpoke._server_id_ldif(values)
    assert "olcServerID: 1 ldap://a:389" in out and "replace: olcServerID" in out

    async def _search(tool, args, data=None):
        return out.encode()
    sp = _spoke()
    sp._run_ldapi = _search
    assert _run(sp._read_server_ids()) == values
    assert "delete: olcServerID" in LdapSpoke._server_id_ldif([])


def test_ldapi_timeout_kills_and_reaps_the_tool(monkeypatch):
    calls = []

    class _Proc:
        returncode = None

        async def communicate(self, input=None):
            await asyncio.sleep(3600)

        def kill(self):
            calls.append("kill")

        async def wait(self):
            calls.append("wait")

    async def _exec(*a, **k):
        return _Proc()

    async def _wait_for(coro, timeout):
        coro.close()
        raise asyncio.TimeoutError
    monkeypatch.setattr(spoke_mod.asyncio, "create_subprocess_exec", _exec)
    monkeypatch.setattr(spoke_mod.asyncio, "wait_for", _wait_for)
    with pytest.raises(spoke_mod._CertInstallError, match="timed out"):
        _run(_spoke()._run_ldapi("ldapmodify", [], b""))
    assert calls == ["kill", "wait"]


def test_update_config_pushes_are_serialised(tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_ENV_PATH", str(tmp_path / ".env"))
    sp = _spoke()
    active, peak = [0], [0]

    async def _ids():
        return []

    async def _modify(ldif):
        active[0] += 1
        peak[0] = max(peak[0], active[0])
        await asyncio.sleep(0.01)
        active[0] -= 1
    sp._read_server_ids, sp._ldapmodify = _ids, _modify
    push = _hub_push(LDAP_SERVER_ID="1", LDAP_MIRROR_PEERS='["ldap://p:389"]')

    async def _both():
        return await asyncio.gather(sp.handle_command("UPDATE_CONFIG", push),
                                    sp.handle_command("UPDATE_CONFIG", push))
    assert [r["status"] for r in _run(_both())] == ["SUCCESS", "SUCCESS"]
    assert peak[0] == 1


def test_persist_env_refuses_a_multiline_value(tmp_path, monkeypatch):
    monkeypatch.setenv("LDAP_ENV_PATH", str(tmp_path / ".env"))
    with pytest.raises(ValueError):
        _spoke()._persist_env({"ENTRA_TENANT_ID": "t\nLDAP_ADMIN_PW=x"})


def test_empty_admin_password_is_never_sent_as_a_bind():
    binds = []
    conn = types.SimpleNamespace(simple_bind_s=lambda dn, pw: binds.append((dn, pw)))
    mgr = spoke_mod.LdapManager("cn=admin,dc=x", "", "dc=x")
    with pytest.raises(spoke_mod.LdapBindError):
        mgr._bind(conn)
    assert binds == []


def test_redaction_survives_a_quote_in_the_password():
    pw = 'Pa"ss w0rd'
    out = LdapSpoke._redact_credentials(f'bad credentials="{pw}" rid=001 ({pw})', pw)
    assert "w0rd" not in out and "credentials=***" in out
