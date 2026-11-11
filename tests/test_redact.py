"""Redaction at ingest: what reaches the database, the pages, issues and Slack.

The canaries below are fake but shaped like the real thing; each must be gone after
``redact_text``. Docker list responses carry ``ContainerSpec.Env`` in plain text, so
``redact_spec`` must drop it wherever it nests.
"""

from __future__ import annotations

import pytest

from tgx_monitor.redact import redact_spec, redact_text

GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FINE = "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"
SLACK = "https://hooks.slack.com/services/" + "T000/B000/XXXXXXXXXXXXXXXX"
HC = "https://hc-ping.com/" + "0f1e2d3c-4b5a-6978-8091-a2b3c4d5e6f7"
XOX = "xoxb-" + "123456789012-abcdefghijkl"
KEY = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow" + "IBAAKCAQEA\nabc\n"
       "-----END RSA PRIVATE KEY-----")


@pytest.mark.parametrize("secret", [GH, FINE, SLACK, HC, XOX, KEY,
                                    "gho_" + "x" * 36, "ghs_" + "y" * 36])
def test_token_shapes_are_removed(secret):
    out = redact_text(f"before {secret} after")
    assert secret not in out
    assert out.startswith("before [redacted]") and out.endswith("after")


@pytest.mark.parametrize(("text", "kept", "gone"), [
    ("password=hunter2&user=bob", "password=[redacted]", "hunter2"),
    ("token: abc.def.ghi", "token: [redacted]", "abc.def.ghi"),
    ("API_KEY = s3cr3t", "API_KEY = [redacted]", "s3cr3t"),
    ("https://x.org/q?apikey=12345;next", "apikey=[redacted];next", "12345"),
])
def test_key_value_secrets_keep_the_key(text, kept, gone):
    out = redact_text(text)
    assert kept in out and gone not in out


def test_prefixed_env_style_secrets():
    out = redact_text("DBA_PASSWORD=hunter2 GITHUB_TOKEN=abc123")
    assert "hunter2" not in out and "abc123" not in out


@pytest.mark.parametrize("text", ['{"password": "hunter2", "user": "bob"}',
                                  "password='hunter2'", 'secret="hunter2"'])
def test_quoted_secrets(text):
    assert "hunter2" not in redact_text(text)


def test_bearer_header():
    assert "eyJhbGciOi" not in redact_text("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig")


@pytest.mark.parametrize(("text", "gone"), [
    ('{"access_token":"abcdef123"}', "abcdef123"),
    ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ("postgres://u:hunter2@db/x", "hunter2"),
    ("Set-Cookie: session=abcdef123; Path=/", "abcdef123"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl here", "eyJzdWIiOiIxIn0"),
])
def test_more_secret_shapes(text, gone):
    assert gone not in redact_text(text)


def test_ansi_and_control_characters_are_stripped():
    out = redact_text("\x1b[31mred\x1b[0m\x00\x07bell\r\nnext\ttab")
    assert out == "redbell\r\nnext\ttab"


def test_cap_and_empty():
    assert redact_text("") == ""
    out = redact_text("a" * 100, cap=10)
    assert out == "a" * 10 + "\n[… truncated]"


def test_ordinary_text_is_untouched():
    for text in ("200 OK, Default Data, version 2026.11.07, tokens: none",
                 "the basic setup is a bearer of news", "see https://example.org:8080/x"):
        assert redact_text(text) == text


# ---------------------------------------------------------------- docker specs
SERVICE = {
    "ID": "abc",
    "Spec": {
        "Name": "aopwiki-dashboard_dashboard",
        "Labels": {"traefik.enable": "true", "com.example.api-token": "t0k",
                   "tgx.service.owner": "marvinm2", "basicauth.users": "admin:hash"},
        "TaskTemplate": {
            "ContainerSpec": {
                "Image": "ghcr.io/marvinm2/aopwiki-dashboard:sha-1234567",
                "Env": ["DBA_PASSWORD=hunter2", "SPARQL_ENDPOINT=http://virtuoso:8890/sparql"],
                "Args": ["--password", "hunter2"], "Command": ["sh", "-c", "echo hunter2"],
                "Secrets": [{"SecretName": "virtuoso_dba_password"}],
                "Configs": [{"ConfigName": "c"}], "Hostname": "box", "DNSConfig": {},
                "Healthcheck": {"Test": ["CMD", "curl", "-fu", "admin:hunter2", "http://x"]},
                "Mounts": [{"Source": "/mnt/gluster/docker/x", "Target": "/data"}],
            },
        },
    },
}


def test_redact_spec_drops_sensitive_fields_everywhere():
    out = redact_spec([SERVICE, {"Spec": {"Env": ["A=1"]}}])
    cs = out[0]["Spec"]["TaskTemplate"]["ContainerSpec"]
    assert set(cs) == {"Image", "Mounts"}
    assert "Env" not in out[1]["Spec"]
    assert "hunter2" not in repr(out)


def test_redact_spec_masks_secret_looking_labels_only():
    labels = redact_spec(SERVICE)["Spec"]["Labels"]
    assert labels["com.example.api-token"] == "[redacted]"
    assert labels["basicauth.users"] == "[redacted]"
    assert labels["traefik.enable"] == "true"
    assert labels["tgx.service.owner"] == "marvinm2"


def test_redact_spec_does_not_mutate_input_and_passes_scalars():
    redact_spec(SERVICE)
    assert "Env" in SERVICE["Spec"]["TaskTemplate"]["ContainerSpec"]
    assert redact_spec("x") == "x" and redact_spec(3) == 3 and redact_spec(None) is None
