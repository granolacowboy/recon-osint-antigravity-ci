from __future__ import annotations

from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Mapping

from app.adapters.base import ToolAdapter
from app.adapters.breach import DeHashedAdapter, H8mailAdapter
from app.adapters.cloud import CloudEnumAdapter, GitReconAdapter, TruffleHogAdapter
from app.adapters.corporate import SpiderFootAdapter
from app.adapters.darkweb import DarkdumpAdapter, OnionSearchAdapter, TorBotAdapter
from app.adapters.domain import AmassAdapter, AssetfinderAdapter
from app.adapters.email import MosintAdapter, TheHarvesterAdapter
from app.adapters.geo import CreepyAdapter, ExifToolAdapter, GeoGuessrResolverAdapter
from app.adapters.ip import CensysAdapter, ShodanAdapter
from app.adapters.metadata import FOCAAdapter, MetagoofilAdapter
from app.adapters.network import MasscanAdapter, NaabuAdapter, NmapAdapter, RustScanAdapter
from app.adapters.phone import PhoneInfogaAdapter
from app.adapters.social import CrossLinkedAdapter, OSINTgramAdapter, SocialAnalyzerAdapter
from app.adapters.threat_intel import MISPAdapter, OpenCTIAdapter, YetiAdapter
from app.adapters.username import BlackbirdAdapter, SherlockAdapter
from app.adapters.vuln import NucleiAdapter, SearchSploitAdapter, VulnersAdapter
from app.adapters.web_archive import GauAdapter, WaybackurlsAdapter
from app.core.config import Settings
from app.schemas.base import TargetEntity
from app.schemas.entities import (
    BreachEntity,
    CVEEntity,
    CloudStorageEntity,
    CompanyEntity,
    DarkWebForumEntity,
    DomainEntity,
    EmailEntity,
    IPEntity,
    PhoneEntity,
    RepositoryEntity,
    URLEntity,
    UsernameEntity,
    VulnerabilityEntity,
)
from app.schemas.outcomes import AdapterMetadata


TARGET_MODEL_REGISTRY: Mapping[str, type[TargetEntity]] = MappingProxyType(
    {
        "username": UsernameEntity,
        "email": EmailEntity,
        "phone": PhoneEntity,
        "domain": DomainEntity,
        "ip": IPEntity,
        "url": URLEntity,
        "company": CompanyEntity,
        "vulnerability": VulnerabilityEntity,
        "cve": CVEEntity,
        "repository": RepositoryEntity,
        "cloud_storage": CloudStorageEntity,
        "breach": BreachEntity,
        "dark_web_forum": DarkWebForumEntity,
    }
)


_PLACEHOLDER_CREDENTIALS = frozenset(
    {
        "",
        "mock",
        "placeholder",
        "changeme",
        "change-me",
        "test",
        "your-api-key",
        "your_api_key",
        "shodan-api-key",
    }
)


def _is_placeholder_credential(value: object) -> bool:
    normalized = str(value or "").strip().casefold()
    compact = "".join(character for character in normalized if character.isalnum())
    return normalized in _PLACEHOLDER_CREDENTIALS or compact.startswith(
        ("mock", "placeholder", "changeme", "your", "testkey", "example")
    )


@dataclass(frozen=True)
class AdapterRegistration:
    adapter_type: type[ToolAdapter]
    metadata: AdapterMetadata
    required_setting: str | None = None

    @property
    def adapter_id(self) -> str:
        return self.metadata.adapter_id

    def metadata_for(self, config: Settings) -> AdapterMetadata:
        if self.required_setting is None:
            return self.metadata
        configured_value = getattr(config, self.required_setting, None)
        if _is_placeholder_credential(configured_value):
            return replace(
                self.metadata,
                enabled=False,
                unavailable_reason="missing_credentials",
            )
        return replace(
            self.metadata,
            enabled=True,
            unavailable_reason=None,
        )

    def create(self, config: Settings) -> ToolAdapter:
        return self.adapter_type(config=config)


def _disabled(
    adapter_id: str,
    display_name: str,
    adapter_type: type[ToolAdapter],
    target_types: tuple[str, ...],
    *,
    passive: bool,
    reason: str,
) -> AdapterRegistration:
    return AdapterRegistration(
        adapter_type=adapter_type,
        metadata=AdapterMetadata(
            adapter_id=adapter_id,
            display_name=display_name,
            target_types=target_types,
            passive=passive,
            enabled=False,
            unavailable_reason=reason,
        ),
    )


_REGISTRATIONS = (
    AdapterRegistration(
        adapter_type=ShodanAdapter,
        metadata=AdapterMetadata(
            adapter_id="shodan",
            display_name="Shodan Host API",
            target_types=("ip",),
            passive=True,
            enabled=False,
            unavailable_reason="missing_credentials",
        ),
        required_setting="SHODAN_API_KEY",
    ),
    _disabled("censys", "Censys", CensysAdapter, ("ip",), passive=True, reason="unfinished_adapter"),
    _disabled("dehashed", "DeHashed", DeHashedAdapter, ("email", "username"), passive=True, reason="v1_policy_disabled"),
    _disabled("h8mail", "h8mail", H8mailAdapter, ("email",), passive=True, reason="cli_adapter_disabled"),
    _disabled("cloud_enum", "Cloud Enum", CloudEnumAdapter, ("company", "domain"), passive=False, reason="active_adapter_disabled"),
    _disabled("trufflehog", "TruffleHog", TruffleHogAdapter, ("repository",), passive=False, reason="active_adapter_disabled"),
    _disabled("git_recon", "GitHub Recon", GitReconAdapter, ("username", "company"), passive=True, reason="v1_policy_disabled"),
    _disabled("spiderfoot", "SpiderFoot", SpiderFootAdapter, ("company", "domain", "ip"), passive=False, reason="active_adapter_disabled"),
    _disabled("torbot", "TorBot", TorBotAdapter, ("domain",), passive=False, reason="active_adapter_disabled"),
    _disabled("onionsearch", "OnionSearch", OnionSearchAdapter, ("username", "domain"), passive=True, reason="cli_adapter_disabled"),
    _disabled("darkdump", "Darkdump", DarkdumpAdapter, ("username",), passive=True, reason="cli_adapter_disabled"),
    _disabled("amass", "Amass", AmassAdapter, ("domain",), passive=False, reason="active_adapter_disabled"),
    _disabled("assetfinder", "Assetfinder", AssetfinderAdapter, ("domain",), passive=True, reason="cli_adapter_disabled"),
    _disabled("mosint", "Mosint", MosintAdapter, ("email",), passive=True, reason="cli_adapter_disabled"),
    _disabled("theharvester", "theHarvester", TheHarvesterAdapter, ("email", "domain"), passive=True, reason="cli_adapter_disabled"),
    _disabled("exiftool", "ExifTool", ExifToolAdapter, ("url",), passive=True, reason="cli_adapter_disabled"),
    _disabled("geoguessr_resolver", "GeoGuessr Resolver", GeoGuessrResolverAdapter, ("url",), passive=True, reason="fabricated_adapter"),
    _disabled("creepy", "Creepy", CreepyAdapter, ("url",), passive=True, reason="fabricated_adapter"),
    _disabled("foca", "FOCA", FOCAAdapter, ("domain",), passive=True, reason="fabricated_adapter"),
    _disabled("metagoofil", "Metagoofil", MetagoofilAdapter, ("domain",), passive=True, reason="fabricated_adapter"),
    _disabled("nmap", "Nmap", NmapAdapter, ("ip", "domain"), passive=False, reason="active_adapter_disabled"),
    _disabled("masscan", "Masscan", MasscanAdapter, ("ip",), passive=False, reason="active_adapter_disabled"),
    _disabled("rustscan", "RustScan", RustScanAdapter, ("ip",), passive=False, reason="active_adapter_disabled"),
    _disabled("naabu", "Naabu", NaabuAdapter, ("ip", "domain"), passive=False, reason="active_adapter_disabled"),
    _disabled("phoneinfoga", "PhoneInfoga", PhoneInfogaAdapter, ("phone",), passive=True, reason="cli_adapter_disabled"),
    _disabled("social_analyzer", "Social Analyzer", SocialAnalyzerAdapter, ("username",), passive=True, reason="fabricated_adapter"),
    _disabled("osintgram", "OSINTgram", OSINTgramAdapter, ("username",), passive=True, reason="fabricated_adapter"),
    _disabled("crosslinked", "CrossLinked", CrossLinkedAdapter, ("company",), passive=True, reason="fabricated_adapter"),
    _disabled("misp", "MISP", MISPAdapter, ("domain", "ip", "url"), passive=True, reason="fabricated_adapter"),
    _disabled("opencti", "OpenCTI", OpenCTIAdapter, ("domain", "ip"), passive=True, reason="fabricated_adapter"),
    _disabled("yeti", "Yeti", YetiAdapter, ("domain", "ip"), passive=True, reason="fabricated_adapter"),
    _disabled("sherlock", "Sherlock", SherlockAdapter, ("username",), passive=True, reason="cli_adapter_disabled"),
    _disabled("blackbird", "Blackbird", BlackbirdAdapter, ("username",), passive=True, reason="cli_adapter_disabled"),
    _disabled("nuclei", "Nuclei", NucleiAdapter, ("domain", "ip"), passive=False, reason="active_adapter_disabled"),
    _disabled("searchsploit", "SearchSploit", SearchSploitAdapter, ("ip",), passive=True, reason="cli_adapter_disabled"),
    _disabled("vulners", "Vulners", VulnersAdapter, ("cve",), passive=True, reason="v1_policy_disabled"),
    _disabled("waybackurls", "Waybackurls", WaybackurlsAdapter, ("domain",), passive=True, reason="cli_adapter_disabled"),
    _disabled("gau", "GetAllURLs", GauAdapter, ("domain",), passive=True, reason="cli_adapter_disabled"),
)


ADAPTER_REGISTRY: Mapping[str, AdapterRegistration] = MappingProxyType(
    {registration.adapter_id: registration for registration in _REGISTRATIONS}
)


def get_adapter_registrations(target_type: str) -> tuple[AdapterRegistration, ...]:
    if target_type not in TARGET_MODEL_REGISTRY:
        return ()
    return tuple(
        registration
        for registration in _REGISTRATIONS
        if target_type in registration.metadata.target_types
    )


def get_registration_for_adapter(
    adapter_type: type[ToolAdapter],
) -> AdapterRegistration:
    for registration in _REGISTRATIONS:
        if registration.adapter_type is adapter_type:
            return registration
    raise LookupError(f"Adapter type {adapter_type.__name__} is not registered")


def get_target_model(target_type: str) -> type[TargetEntity] | None:
    return TARGET_MODEL_REGISTRY.get(target_type)
