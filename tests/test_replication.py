"""Tests for the syncrepl mirror-mode LDIF builders (src/replication.py)."""
import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "replication", os.path.join(os.path.dirname(__file__), "..", "src", "replication.py"))
replication = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replication)

import pytest

BASE = "dc=lm,dc=local"
ADMIN = "cn=admin,dc=lm,dc=local"
PW = "s3cr3t"
PEERS = ["ldaps://ldap2.lm.local:636"]


def test_serverid_ldif():
    out = replication.build_serverid_ldif(1)
    assert "dn: cn=config" in out
    assert "replace: olcServerID" in out
    assert "olcServerID: 1" in out


def test_serverid_rejects_bad():
    with pytest.raises(ValueError):
        replication.build_serverid_ldif(0)


def test_syncprov_overlay():
    out = replication.build_syncprov_overlay_ldif()
    assert "olcOverlay=syncprov,olcDatabase={1}mdb,cn=config" in out
    assert "objectClass: olcSyncProvConfig" in out
    assert "changetype: add" in out


def test_syncrepl_ldif_has_peer_and_creds():
    out = replication.build_syncrepl_ldif(1, PEERS, BASE, ADMIN, PW)
    assert "dn: olcDatabase={1}mdb,cn=config" in out
    assert "replace: olcSyncrepl" in out and "delete:" not in out
    assert 'provider="ldaps://ldap2.lm.local:636"' in out
    assert 'type=refreshAndPersist' in out
    assert f'binddn="{ADMIN}"' in out
    assert f'credentials="{PW}"' in out
    assert f'searchbase="{BASE}"' in out


def test_syncrepl_rid_is_node_scoped():
    # node 1 → rid 101.. ; node 2 → rid 201.. (never collide across the pair)
    out1 = replication.build_syncrepl_ldif(1, PEERS, BASE, ADMIN, PW)
    out2 = replication.build_syncrepl_ldif(2, PEERS, BASE, ADMIN, PW)
    assert "rid=101" in out1
    assert "rid=201" in out2


def test_syncrepl_multiple_peers_distinct_rids():
    peers = ["ldaps://a:636", "ldaps://b:636"]
    out = replication.build_syncrepl_ldif(2, peers, BASE, ADMIN, PW)
    assert "rid=201" in out and "rid=202" in out
    assert 'provider="ldaps://a:636"' in out and 'provider="ldaps://b:636"' in out


def test_syncrepl_requires_peers_and_base():
    with pytest.raises(ValueError):
        replication.build_syncrepl_ldif(1, [], BASE, ADMIN, PW)
    with pytest.raises(ValueError):
        replication.build_syncrepl_ldif(1, PEERS, "", ADMIN, PW)


def test_mirrormode_toggle():
    assert "olcMirrorMode: TRUE" in replication.build_mirrormode_ldif(True)
    assert "olcMirrorMode: FALSE" in replication.build_mirrormode_ldif(False)


def test_full_mirror_ldif_combines_all():
    out = replication.build_full_mirror_ldif(1, PEERS, BASE, ADMIN, PW)
    assert "replace: olcServerID" in out
    assert "replace: olcSyncrepl" in out
    assert "olcMirrorMode: TRUE" in out


def test_syncprov_module_load():
    out = replication.build_syncprov_module_ldif()
    assert "dn: cn=module{0},cn=config" in out
    assert "add: olcModuleLoad" in out and "olcModuleLoad: syncprov" in out


def _slapd_tokens(line):
    """Split a value the way slapd's strtok_quote does: whitespace separates
    tokens, double quotes group, and a backslash escapes the next character."""
    out, cur, quoted, i, started = [], [], False, 0, False
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            cur.append(line[i + 1]); i += 2; started = True; continue
        if ch == '"':
            quoted = not quoted; started = True
        elif ch in " \t" and not quoted:
            if started:
                out.append("".join(cur)); cur, started = [], False
        else:
            cur.append(ch); started = True
        i += 1
    if started:
        out.append("".join(cur))
    return out


def _syncrepl_value(out):
    import base64
    line = next(l for l in out.splitlines() if l.startswith("olcSyncrepl:"))
    if line.startswith("olcSyncrepl:: "):
        return base64.b64decode(line[len("olcSyncrepl:: "):]).decode("utf-8")
    return line[len("olcSyncrepl: "):]


def test_syncrepl_quotes_hostile_values_into_single_tokens():
    pw = 'p"w\\ binddn="cn=evil" x'
    dn = 'cn=a "b",dc=lm,dc=local'
    out = replication.build_syncrepl_ldif(1, PEERS, BASE, dn, pw)
    toks = dict(t.split("=", 1) for t in _slapd_tokens(_syncrepl_value(out)))
    assert toks["credentials"] == pw
    assert toks["binddn"] == dn
    assert toks["searchbase"] == BASE
    assert toks["provider"] == PEERS[0]


@pytest.mark.parametrize("field", ["pw", "dn", "base", "peer"])
def test_syncrepl_refuses_control_characters(field):
    vals = {"pw": PW, "dn": ADMIN, "base": BASE, "peer": PEERS[0]}
    vals[field] = vals[field] + "\nolcRootPW: owned"
    with pytest.raises(ValueError) as exc:
        replication.build_syncrepl_ldif(1, [vals["peer"]], vals["base"], vals["dn"], vals["pw"])
    assert "owned" not in str(exc.value)


def test_syncrepl_starttls_only_for_plain_ldap_peers():
    plain = _syncrepl_value(replication.build_syncrepl_ldif(1, ["ldap://p:389"], BASE, ADMIN, PW))
    tls = _syncrepl_value(replication.build_syncrepl_ldif(1, PEERS, BASE, ADMIN, PW))
    assert "starttls=critical" in _slapd_tokens(plain) and "tls_reqcert=allow" in _slapd_tokens(plain)
    assert "starttls=" not in tls


def test_syncrepl_non_ascii_value_is_base64():
    out = replication.build_syncrepl_ldif(1, PEERS, BASE, ADMIN, "pässwörd")
    assert "olcSyncrepl:: " in out
    assert dict(t.split("=", 1) for t in _slapd_tokens(_syncrepl_value(out)))["credentials"] == "pässwörd"


def _cli(args, env_pw):
    import subprocess
    import sys
    env = {k: v for k, v in os.environ.items() if k != "LDAP_ADMIN_PW"}
    if env_pw is not None:
        env["LDAP_ADMIN_PW"] = env_pw
    root = os.path.join(os.path.dirname(__file__), "..")
    return subprocess.run([sys.executable, "-m", "src.replication", *args],
                          cwd=root, env=env, capture_output=True, text=True)


def test_cli_syncrepl_reads_password_from_env_not_argv():
    res = _cli(["syncrepl", "1", BASE, ADMIN, PEERS[0]], PW)
    assert res.returncode == 0, res.stderr
    assert f'credentials="{PW}"' in res.stdout
    assert f'provider="{PEERS[0]}"' in res.stdout


def test_cli_syncrepl_without_env_password_fails():
    res = _cli(["syncrepl", "1", BASE, ADMIN, PEERS[0]], None)
    assert res.returncode != 0 and "credentials" not in res.stdout
