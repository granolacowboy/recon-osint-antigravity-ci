from ipaddress import ip_address
from urllib.parse import parse_qsl, urlsplit

from app.redaction import is_sensitive_key
from app.schemas.base import TargetEntity
from pydantic import EmailStr, Field, field_validator
from typing import Optional, List

class UsernameEntity(TargetEntity):
    pass

class EmailEntity(TargetEntity):
    value: EmailStr

class PhoneEntity(TargetEntity):
    # Could add specific regex for E.164
    value: str = Field(..., pattern=r'^\+?[1-9]\d{1,14}$')

class DomainEntity(TargetEntity):
    @field_validator("value")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        normalized = value.rstrip(".").casefold()
        try:
            ascii_domain = normalized.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("value must be a valid domain") from exc
        labels = ascii_domain.split(".")
        if (
            len(ascii_domain) > 253
            or len(labels) < 2
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(character.isalnum() or character == "-" for character in label)
                for label in labels
            )
            or len(labels[-1]) < 2
            or labels[-1].isdigit()
        ):
            raise ValueError("value must be a valid domain")
        return ascii_domain

class IPEntity(TargetEntity):
    @field_validator("value")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        try:
            return str(ip_address(value))
        except ValueError as exc:
            raise ValueError("value must be a valid IPv4 or IPv6 address") from exc

class URLEntity(TargetEntity):
    @field_validator("value")
    @classmethod
    def validate_http_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("value must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL targets must not contain credentials")
        if parsed.fragment:
            raise ValueError("URL targets must not contain fragments")
        if any(
            is_sensitive_key(key)
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
        ):
            raise ValueError("URL targets must not contain credential query parameters")
        return value

class CompanyEntity(TargetEntity):
    pass

class VulnerabilityEntity(TargetEntity):
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None

class CVEEntity(TargetEntity):
    # Basic CVE validation
    value: str = Field(..., pattern=r'^CVE-\d{4}-\d{4,}$')

class RepositoryEntity(TargetEntity):
    pass

class CloudStorageEntity(TargetEntity):
    pass

class BreachEntity(TargetEntity):
    breach_date: Optional[str] = None
    compromised_data_types: Optional[List[str]] = None
    source: Optional[str] = None

class DarkWebForumEntity(TargetEntity):
    forum_name: Optional[str] = None
    post_url: Optional[str] = None
    aliases: Optional[List[str]] = None
