import pytest
from pydantic import ValidationError
from app.schemas.entities import (
    DomainEntity,
    EmailEntity,
    IPEntity,
    PhoneEntity,
    URLEntity,
    UsernameEntity,
)

def test_username_entity():
    user = UsernameEntity(value="alice")
    assert user.value == "alice"

def test_email_entity():
    email = EmailEntity(value="alice@example.com")
    assert email.value == "alice@example.com"

    with pytest.raises(ValidationError):
        EmailEntity(value="not-an-email")

def test_phone_entity():
    phone = PhoneEntity(value="+12025550123")
    assert phone.value == "+12025550123"

    with pytest.raises(ValidationError):
        PhoneEntity(value="abc")  # not a number

def test_domain_entity():
    domain = DomainEntity(value="example.com")
    assert domain.value == "example.com"

    with pytest.raises(ValidationError):
        DomainEntity(value="not-a-domain")

    with pytest.raises(ValidationError):
        DomainEntity(value="-invalid.example")

    assert DomainEntity(value="EXAMPLE.COM.").value == "example.com"


@pytest.mark.parametrize(
    "value",
    ["999.999.999.999", "192.0.2.1;touch-pwned", "not-an-ip"],
)
def test_ip_entity_rejects_invalid_or_injected_values(value):
    with pytest.raises(ValidationError):
        IPEntity(value=value)


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "ftp://example.com/file",
        "https://user:pass@example.com",
        "https://example.com/?access_token=private",
        "https://example.com/?token=private",
        "https://example.com/?signature=private",
        "https://example.com/?sig=private",
        "https://example.com/?X-Amz-Signature=private",
        "https://example.com/?X-Amz-Credential=private",
        "https://example.com/path#private-fragment",
    ],
)
def test_url_entity_accepts_only_credential_free_http_urls(value):
    with pytest.raises(ValidationError):
        URLEntity(value=value)


def test_entity_metadata_and_tags_are_not_shared_between_instances():
    first = UsernameEntity(value="first")
    second = UsernameEntity(value="second")

    first.metadata["source"] = "fixture"
    first.tags.append("observed")

    assert second.metadata == {}
    assert second.tags == []
