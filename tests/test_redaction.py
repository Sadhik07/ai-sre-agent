from sre_agent.guardrails.redaction import Redactor

r = Redactor()


def test_redacts_common_secrets_and_pii():
    text = (
        "user bob@example.com paid with 4111 1111 1111 1111, aws AKIAIOSFODNN7EXAMPLE, "
        "Authorization: Bearer EXAMPLEbearerTOKENnotREAL0123 password=hunter2 ssn 123-45-6789"
    )
    out = r.redact_text(text)
    for secret in [
        "bob@example.com",
        "4111",
        "AKIAIOSFODNN7EXAMPLE",
        "EXAMPLEbearer",
        "hunter2",
        "123-45-6789",
    ]:
        assert secret not in out.text
    assert out.counts["card_number"] == 1
    assert "password=[REDACTED:secret_kv]" in out.text  # key kept, value removed


def test_non_luhn_numbers_are_kept():
    assert r.redact_text("order 1234567890123 shipped").text == "order 1234567890123 shipped"


def test_structured_redaction_keeps_structure_and_counts():
    data = {"msg": "token=abc123 for alice@corp.io", "token": "s3cr3t", "n": 4, "items": [{"api_key": "x"}]}
    clean, count = r.redact(data)
    assert clean["n"] == 4
    assert clean["token"] == "[REDACTED:secret_field]"
    assert clean["items"][0]["api_key"] == "[REDACTED:secret_field]"
    assert "alice@corp.io" not in clean["msg"] and "abc123" not in clean["msg"]
    assert count == 4


def test_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
    assert r.redact_text(f"key: {pem}").text == "key: [REDACTED:private_key]"
