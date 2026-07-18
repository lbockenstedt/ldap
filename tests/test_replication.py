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
    assert "delete: olcSyncrepl" in out and "add: olcSyncrepl" in out
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
    assert "add: olcSyncrepl" in out
    assert "olcMirrorMode: TRUE" in out
