"""Strict Pydantic v2 models for IOC ingestion aligned to the mature vault schema (TLP, kill chain, confidence)."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

# ---------------------------------------------------------------------------
# Regular expressions for Internet number formats (full-match validation)
# ---------------------------------------------------------------------------

# IPv4 dotted-decimal, no leading-zero octets except single 0 (strict, common CTI form).
_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|0)"
IPV4_REGEX = re.compile(rf"^{_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}$")

# IPv6: full-match alternation (anchored); includes IPv4-mapped and embedded IPv4 tail forms.
IPV6_REGEX = re.compile(
    r"^(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|"
    r"[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|"
    r":(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)|"
    r"fe80:(?::[0-9A-Fa-f]{0,4}){0,4}%[0-9A-Za-z._~-]+|"
    r"::(?:ffff(?::0{1,4})?:)?"
    r"(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]\.){3}"
    r"(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}:"
    r"(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]\.){3}"
    r"(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])"
    r")$",
    re.IGNORECASE,
)

_IOC_TYPES_REQUIRING_IP_REGEX: frozenset[str] = frozenset(
    {
        "ip",
        "ipv4",
        "ipv6",
        "ip_address",
        "ip-address",
        "ipv4-addr",
        "ipv6-addr",
        "ipv4_addr",
        "ipv6_addr",
    }
)

_KILL_CHAIN_CANONICAL: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "weaponization": "Weaponization",
    "delivery": "Delivery",
    "exploitation": "Exploitation",
    "installation": "Installation",
    "command_and_control": "Command and Control",
    "command and control": "Command and Control",
    "command-and-control": "Command and Control",
    "c2": "Command and Control",
    "actions_on_objectives": "Actions on Objectives",
    "actions on objectives": "Actions on Objectives",
    "actions-on-objectives": "Actions on Objectives",
    "aoo": "Actions on Objectives",
}

TLPLevel = Literal["RED", "AMBER", "GREEN", "CLEAR"]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IOCRecord(BaseModel):
    """
    Mature IOC row: identifiers, enrichment fields, TLP, kill chain, confidence, and timestamps.

    Field order ensures ``ioc_type`` is validated before ``ioc_value`` so IP-format checks can use
    ``ValidationInfo.data`` inside ``ioc_value`` validators.
    """

    model_config = ConfigDict(
        str_strip_whitespace=False,
        validate_assignment=True,
    )

    id: UUID = Field(default_factory=uuid.uuid4, description="Primary key UUID for the IOC row.")
    ioc_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Logical IOC type (e.g. domain, url, ip, hash).",
    )
    ioc_value: str = Field(
        ...,
        min_length=1,
        max_length=8192,
        description="Normalized indicator value after defang sanitization.",
    )
    threat_actor: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Attributed threat actor name, if known.",
    )
    kill_chain_phase: Optional[str] = Field(
        default=None,
        max_length=128,
        description="MITRE-style kill chain phase label.",
    )
    confidence_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Analyst confidence from 0 through 100 inclusive.",
    )
    severity: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="Severity label (e.g. LOW, MEDIUM, HIGH, CRITICAL).",
    )
    tlp_level: TLPLevel = Field(
        ...,
        description="Traffic Light Protocol sharing designation.",
    )
    expiration_date: Optional[datetime] = Field(
        default=None,
        description="When the indicator should no longer be treated as active.",
    )
    created_at: datetime = Field(
        default_factory=_utc_now,
        description="Row creation time in UTC.",
    )

    @field_validator("id", mode="before")
    @classmethod
    def coerce_uuid(cls, value: object) -> UUID:
        if value is None:
            return uuid.uuid4()
        if isinstance(value, UUID):
            return value
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return uuid.uuid4()
            return UUID(text)
        raise TypeError("id must be a UUID instance, UUID string, or omitted for auto-generation.")

    @field_validator("ioc_type", mode="before")
    @classmethod
    def normalize_ioc_type(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("ioc_type must be a string.")
        stripped = value.strip()
        if not stripped:
            raise ValueError("ioc_type must not be empty or whitespace-only.")
        return stripped

    @field_validator("ioc_value", mode="before")
    @classmethod
    def sanitize_defanged_schemes_and_dots(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("ioc_value must be a string.")
        text = value.strip()
        if not text:
            raise ValueError("ioc_value must not be empty or whitespace-only.")
        # Defanged dots in domains and hostnames (e.g. example[.]com, evil[.]tld/path).
        text = text.replace("[.]", ".")
        # Scheme defanging: hxxps:// and hxxp:// (case-insensitive), longest match first.
        text = re.sub(r"(?i)\bhxxps(?=://)", "https", text)
        text = re.sub(r"(?i)\bhxxp(?=://)", "http", text)
        # Bare scheme tokens without slashes (e.g. "hxxps:example.com" from some feeds).
        text = re.sub(r"(?i)\bhxxps(?=:)", "https", text)
        text = re.sub(r"(?i)\bhxxp(?=:)", "http", text)
        return text

    @field_validator("ioc_value", mode="after")
    @classmethod
    def regex_validate_ipv4_ipv6_when_ip_type(cls, value: str, info: ValidationInfo) -> str:
        raw_type = info.data.get("ioc_type") if info.data is not None else None
        if not isinstance(raw_type, str):
            return value
        key = raw_type.strip().lower()
        if key not in _IOC_TYPES_REQUIRING_IP_REGEX:
            return value
        candidate = value.strip()
        if IPV4_REGEX.fullmatch(candidate):
            return value
        if IPV6_REGEX.fullmatch(candidate):
            return value
        raise ValueError(
            "ioc_value is not a valid IPv4 or IPv6 textual address for the given ioc_type "
            f"({raw_type!r}); expected full-match dotted IPv4 or RFC-style IPv6."
        )

    @field_validator("threat_actor", mode="before")
    @classmethod
    def optional_actor_strip_blank_to_none(cls, value: object) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("threat_actor must be a string or null.")
        s = value.strip()
        return s if s else None

    @field_validator("kill_chain_phase", mode="before")
    @classmethod
    def optional_kill_chain_strip(cls, value: object) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("kill_chain_phase must be a string or null.")
        s = value.strip()
        return s if s else None

    @field_validator("kill_chain_phase", mode="after")
    @classmethod
    def validate_and_canonicalize_kill_chain(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        collapsed = " ".join(value.strip().split())
        lowered = collapsed.lower()
        underscored = lowered.replace(" ", "_").replace("-", "_")
        hyphenated = lowered.replace(" ", "-").replace("_", "-")
        candidates = (
            underscored,
            lowered.replace(" ", "_"),
            lowered.replace("-", "_"),
            lowered.replace("_", " "),
            hyphenated,
            lowered,
        )
        for candidate in candidates:
            if candidate in _KILL_CHAIN_CANONICAL:
                return _KILL_CHAIN_CANONICAL[candidate]
        for canonical in _KILL_CHAIN_CANONICAL.values():
            if lowered == canonical.lower():
                return canonical
        raise ValueError(
            "kill_chain_phase must be one of the MITRE-style phases: "
            "Reconnaissance, Weaponization, Delivery, Exploitation, Installation, "
            "'Command and Control' (or C2), or Actions on Objectives."
        )

    @field_validator("severity", mode="before")
    @classmethod
    def severity_non_empty_string(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("severity must be a string.")
        s = value.strip()
        if not s:
            raise ValueError("severity must not be empty or whitespace-only.")
        return s

    @field_validator("tlp_level", mode="before")
    @classmethod
    def uppercase_tlp(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("tlp_level must be a string.")
        upper = value.strip().upper()
        allowed = {"RED", "AMBER", "GREEN", "CLEAR"}
        if upper not in allowed:
            raise ValueError("tlp_level must be one of RED, AMBER, GREEN, CLEAR (case-insensitive).")
        return upper

    @field_validator("expiration_date", "created_at", mode="before")
    @classmethod
    def datetime_must_be_timezone_aware_or_naive_utc_coerced(cls, value: object) -> object:
        if value is None:
            return value
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value
