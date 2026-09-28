from __future__ import annotations

from kornode.config.models import AppConfig
from kornode.services.secrets import is_secret_key, mask_text, redact_value


def test_mask_text_redacts_secret_assignments_without_hiding_paths() -> None:
    rendered = "\n".join(
        [
            "password=kornodectl-local",
            "camouflage_secret = tunnel-word",
            "cert-pass: bundle-pass",
            "secrets_dir=/var/lib/kornode/secrets",
        ]
    )

    masked = mask_text(rendered)

    assert "password=***" in masked
    assert "cert-pass: ***" in masked
    assert "secrets_dir=/var/lib/kornode/secrets" in masked
    assert "kornodectl-local" not in masked
    assert "bundle-pass" not in masked

    # camouflage_secret is a shared TLS camouflage password, not a per-user
    # credential; the UI displays it in plain text instead of masking it.
    assert "camouflage_secret = tunnel-word" in masked


def test_is_secret_key_treats_camouflage_secret_as_secret_structurally() -> None:
    # Regression test: is_secret_key()/redact_value() operate on structured
    # config dicts, where "camouflage_secret" is the actual field name of
    # UpstreamProfileConfig.camouflage_secret -- a genuinely sensitive
    # shared credential for reaching the upstream server. This is a
    # DIFFERENT field from server.camouflage.secret (structural key
    # "secret", intentionally shown in plaintext) that only *coincidentally*
    # shares its name with that field's rendered ocserv.conf directive
    # ("camouflage_secret = ..."). The two must not be conflated: the
    # ocserv.conf-directive exemption belongs only to mask_text()'s
    # rendered-text masking (see the test above), never to this structural
    # check -- otherwise AppConfig.model_dump_safe() (used by e.g. GET
    # /api/config) would leak it in plaintext.
    assert is_secret_key("camouflage_secret") is True
    assert redact_value("shhh", key="camouflage_secret") == "***"


def test_model_dump_safe_masks_upstream_profile_camouflage_secret() -> None:
    config = AppConfig.model_validate(
        {
            "upstream": {
                "enabled": True,
                "profiles": [
                    {
                        "name": "primary",
                        "server": "vpn.example.com",
                        "auth_type": "password",
                        "username": "user",
                        "password": "pw-secret",
                        "camouflage_secret": "camo-leak-me",
                    }
                ],
            },
        }
    )

    dumped = config.model_dump_safe()

    profile = dumped["upstream"]["profiles"][0]
    assert profile["camouflage_secret"] == "***"
    assert profile["password"] == "***"
