from commandcompass.redaction import contains_secret, redact_text


def test_redact_token():
    text = "curl -H 'Authorization: Bearer abcdefghijklmnop' https://x"
    red = redact_text(text)
    assert "abcdefghijklmnop" not in red
    assert "[REDACTED]" in red


def test_redact_sk():
    text = "OPENAI_API_KEY=sk-1234567890abcdef"
    red = redact_text(text)
    assert "sk-1234567890abcdef" not in red


def test_contains_secret():
    assert contains_secret("password=supersecret")
    assert not contains_secret("echo hello")
