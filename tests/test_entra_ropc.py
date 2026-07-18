"""Tests for the Entra ROPC pass-through authenticator (src/entra_ropc_auth.py).

Covers the pure arg/stdin parsing and the token-response → exit-code decision,
plus the end-to-end authenticate() flow with the HTTP call and the cert-based
client-assertion builder mocked (no network, no real key material).
"""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
_spec = importlib.util.spec_from_file_location(
    "entra_ropc_auth", os.path.join(os.path.dirname(__file__), "..", "src", "entra_ropc_auth.py"))
ropc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ropc)


CFG = {
    "tenant_id": "tenant-guid",
    "client_id": "client-guid",
    "cert_path": "/etc/lm/entra/client-cert.pem",
    "key_path": "/etc/lm/entra/client-key.pem",
    "scope": "openid",
}


# ── read_credentials (pure) ─────────────────────────────────────────────────

def test_read_credentials_from_pam_user_and_stdin():
    u, p = ropc.read_credentials(["prog"], {"PAM_USER": "alice@corp.com"}, b"hunter2")
    assert u == "alice@corp.com"
    assert p == "hunter2"


def test_read_credentials_strips_nul_and_newline_terminators():
    # pam_exec expose_authtok terminates the authtok with a NUL.
    u, p = ropc.read_credentials(["prog"], {"PAM_USER": "bob@corp"}, b"pw\x00garbage")
    assert p == "pw"
    u2, p2 = ropc.read_credentials(["prog"], {"PAM_USER": "bob@corp"}, b"pw\ntrailing")
    assert p2 == "pw"


def test_read_credentials_falls_back_to_argv():
    u, p = ropc.read_credentials(["prog", "carol@corp"], {}, b"pw")
    assert u == "carol@corp"


# ── token_ok (pure decision) ────────────────────────────────────────────────

def test_token_ok_true_on_200_with_token():
    assert ropc.token_ok(200, {"access_token": "xyz"}) is True
    assert ropc.token_ok(200, {"id_token": "xyz"}) is True


def test_token_ok_false_otherwise():
    assert ropc.token_ok(401, {"error": "invalid_grant"}) is False
    assert ropc.token_ok(200, {}) is False
    assert ropc.token_ok(200, None) is False
    assert ropc.token_ok(500, {"access_token": "x"}) is False  # non-200 always denies


# ── authenticate (HTTP + assertion mocked) ──────────────────────────────────

def _fake_assertion(cfg, endpoint):
    return "FAKE.JWT.ASSERTION"


def test_authenticate_success():
    captured = {}

    def fake_post(url, data):
        captured["url"] = url
        captured["data"] = data
        return 200, {"access_token": "tok"}

    ok = ropc.authenticate(CFG, "alice@corp", "pw", post=fake_post,
                           assertion_builder=_fake_assertion)
    assert ok is True
    assert captured["data"]["grant_type"] == "password"
    assert captured["data"]["username"] == "alice@corp"
    assert captured["data"]["password"] == "pw"
    assert captured["data"]["client_id"] == "client-guid"
    assert captured["data"]["client_assertion"] == "FAKE.JWT.ASSERTION"
    assert captured["url"].endswith("/tenant-guid/oauth2/v2.0/token")


def test_authenticate_denied_on_bad_credentials():
    def fake_post(url, data):
        return 401, {"error": "invalid_grant"}

    assert ropc.authenticate(CFG, "alice@corp", "wrong", post=fake_post,
                             assertion_builder=_fake_assertion) is False


def test_authenticate_denies_when_not_configured():
    bad = dict(CFG, tenant_id="")
    called = {"n": 0}

    def fake_post(url, data):
        called["n"] += 1
        return 200, {"access_token": "x"}

    assert ropc.authenticate(bad, "alice@corp", "pw", post=fake_post,
                             assertion_builder=_fake_assertion) is False
    assert called["n"] == 0  # never hits the network when unconfigured


def test_authenticate_denies_on_missing_user_or_pw():
    def fake_post(url, data):
        raise AssertionError("should not be called")

    assert ropc.authenticate(CFG, "", "pw", post=fake_post,
                             assertion_builder=_fake_assertion) is False
    assert ropc.authenticate(CFG, "alice@corp", "", post=fake_post,
                             assertion_builder=_fake_assertion) is False


def test_authenticate_denies_on_http_exception():
    def fake_post(url, data):
        raise TimeoutError("network down")

    assert ropc.authenticate(CFG, "alice@corp", "pw", post=fake_post,
                             assertion_builder=_fake_assertion) is False


def test_load_config_reads_env_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        'ENTRA_TENANT_ID="t1"\nENTRA_CLIENT_ID=c1\n'
        'ENTRA_CLIENT_CERT=/x/cert.pem\nENTRA_CLIENT_KEY=/x/key.pem\n')
    cfg = ropc.load_config(str(env))
    assert cfg["tenant_id"] == "t1"
    assert cfg["client_id"] == "c1"
    assert cfg["cert_path"] == "/x/cert.pem"
    assert cfg["scope"] == "openid"  # default when absent


def test_main_wires_stdin_and_env(monkeypatch):
    # main() reads username from PAM_USER, password from stdin, config from
    # load_config, then delegates to authenticate. Stub the config + network.
    monkeypatch.setattr(ropc, "load_config", lambda *a, **k: dict(CFG))
    monkeypatch.setattr(ropc, "request_token",
                        lambda cfg, u, p, **k: (200, {"access_token": "t"}))
    rc = ropc.main(argv=["prog"], environ={"PAM_USER": "alice@corp"}, stdin=b"pw")
    assert rc == 0
    # Wrong password → non-zero exit (deny).
    monkeypatch.setattr(ropc, "request_token",
                        lambda cfg, u, p, **k: (401, {"error": "invalid_grant"}))
    rc2 = ropc.main(argv=["prog"], environ={"PAM_USER": "alice@corp"}, stdin=b"bad")
    assert rc2 == 1
