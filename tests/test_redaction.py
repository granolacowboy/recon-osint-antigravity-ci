from app.schemas.entities import EmailEntity
from app.adapters.breach import DeHashedAdapter, H8mailAdapter
from app.redaction import (
    redact_entity,
    redact_entities,
    REDACTED_SENTINEL,
    SENSITIVE_KEYS,
)


# ---- Unit tests for the redaction module itself ----

def test_redact_entity_strips_password():
    ent = EmailEntity(value="alice@example.com")
    ent.metadata["password"] = "p@ssw0rd123"
    ent.metadata["database_name"] = "Collection1"

    clean = redact_entity(ent)

    assert clean.metadata["password"] == REDACTED_SENTINEL
    assert clean.metadata["database_name"] == "Collection1"  # non-sensitive preserved


def test_redact_entity_strips_hashed_password():
    ent = EmailEntity(value="bob@example.com")
    ent.metadata["hashed_password"] = "5f4dcc3b5aa765d61d8327deb882cf99"

    clean = redact_entity(ent)

    assert clean.metadata["hashed_password"] == REDACTED_SENTINEL


def test_redact_entity_strips_cleartext_passwords():
    ent = EmailEntity(value="carol@example.com")
    ent.metadata["cleartext_passwords"] = ["pwd1", "pwd2"]
    ent.metadata["breaches"] = ["Adobe2013"]

    clean = redact_entity(ent)

    assert clean.metadata["cleartext_passwords"] == REDACTED_SENTINEL
    assert clean.metadata["breaches"] == ["Adobe2013"]  # safe field preserved


def test_redact_entity_does_not_mutate_original():
    ent = EmailEntity(value="dave@example.com")
    ent.metadata["password"] = "originalpass"

    clean = redact_entity(ent)

    assert clean.metadata["password"] == REDACTED_SENTINEL
    assert ent.metadata["password"] == "originalpass"  # original unchanged


def test_redact_entities_batch():
    entities = [
        EmailEntity(value="a@example.com"),
        EmailEntity(value="b@example.com"),
    ]
    entities[0].metadata["password"] = "secret1"
    entities[1].metadata["hashed_password"] = "abc123"

    cleaned = redact_entities(entities)

    assert len(cleaned) == 2
    assert cleaned[0].metadata["password"] == REDACTED_SENTINEL
    assert cleaned[1].metadata["hashed_password"] == REDACTED_SENTINEL


# ---- Integration tests: redaction applied to breach adapter output ----

def test_dehashed_output_redacted():
    """
    End-to-end: DeHashed adapter produces raw passwords, redaction strips them.
    """
    recorded_output = {
        "entries": [
            {
                "email": "alice@example.com",
                "password": "p@ssw0rd123",
                "hashed_password": "5f4dcc3b5aa765d61d8327deb882cf99",
                "database_name": "Collection1",
            }
        ]
    }
    adapter = DeHashedAdapter()
    raw_results = adapter.parse(recorded_output)
    # Raw results still have passwords
    assert raw_results[0].metadata["password"] == "p@ssw0rd123"

    # After redaction, passwords are gone
    clean_results = redact_entities(raw_results)
    for ent in clean_results:
        assert ent.metadata["password"] == REDACTED_SENTINEL
        assert ent.metadata["hashed_password"] == REDACTED_SENTINEL
        # Non-sensitive data preserved
        assert "database_name" in ent.metadata


def test_h8mail_output_redacted():
    """
    End-to-end: h8mail adapter produces cleartext passwords, redaction strips them.
    """
    adapter = H8mailAdapter()
    raw_results = adapter.parse(
        {
            "results": [
                {
                    "email": "test@example.com",
                    "breaches": ["Adobe2013", "Dropbox2012"],
                    "passwords_found": 2,
                    "cleartext_passwords": ["adobe123", "dropbox2012pass"],
                }
            ]
        }
    )
    assert raw_results[0].metadata["cleartext_passwords"] == ["adobe123", "dropbox2012pass"]

    clean_results = redact_entities(raw_results)
    for ent in clean_results:
        assert ent.metadata["cleartext_passwords"] == REDACTED_SENTINEL
        # Breach names preserved
        assert ent.metadata["breaches"] == ["Adobe2013", "Dropbox2012"]


def test_sensitive_keys_coverage():
    """
    Verify the SENSITIVE_KEYS set covers all known credential-bearing fields.
    """
    expected = {"password", "hashed_password", "cleartext_passwords",
                "raw_password", "password_hash", "credential", "secret"}
    assert SENSITIVE_KEYS == expected
