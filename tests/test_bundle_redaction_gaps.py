from kornode.bundle.redaction import REDACTED, Redactor


def test_extended_secret_keys_are_redacted_in_data() -> None:
    data = {"psk": "a", "api_key": "b", "session_id": "c", "credentials": {"u": "x"}, "name": "ok"}
    out = Redactor().data(data)
    assert out["name"] == "ok"
    assert all(out[k] == REDACTED for k in ("psk", "api_key", "session_id", "credentials"))


def test_extended_secrets_are_redacted_in_text() -> None:
    text = "psk=hunter2\napi-key: abcdef\nsent Bearer abcdefgh12345 to hub"
    out = Redactor().text(text)
    assert "hunter2" not in out and "abcdef\n" not in out and "abcdefgh12345" not in out


def test_boolean_flags_on_secret_named_keys_stay_readable() -> None:
    out = Redactor().data({"credentials_set": False, "password_set": True, "password": "x"})
    assert out == {"credentials_set": False, "password_set": True, "password": REDACTED}


def test_words_that_merely_contain_otp_or_session_are_not_secrets() -> None:
    out = Redactor().data({"footprint": 3, "sessions": 2, "session_id": "s", "otp": "1"})
    assert out == {"footprint": 3, "sessions": 2, "session_id": REDACTED, "otp": REDACTED}


def test_public_keys_and_hashes_survive_the_base64_line_rule() -> None:
    pubkey = "A" * 43 + "="
    digest = "ab" * 32
    out = Redactor().data({"next_signing_pubkey": pubkey, "content_sha256": digest})
    assert out == {"next_signing_pubkey": pubkey, "content_sha256": digest}
    assert Redactor().text(digest) == digest  # hex digest on its own line
    assert Redactor().text("A" * 44) == REDACTED  # a bare key-shaped blob still goes
