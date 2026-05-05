"""Strict Pydantic v2 models for ASM assets and CVE rows prior to SQLite WAL persistence."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# CPE 2.3 formatted string (URI binding): cpe:2.3:part:vendor:product:version:
# update:edition:language:sw_edition:target_sw:target_hw:other
# Each component is one or more characters that are either an escape pair (backslash + any)
# or any character except unescaped colon and backslash (per NIST CPE 2.3 name escaping).
# ---------------------------------------------------------------------------

CPE_2_3_URI_REGEX = re.compile(
    r"^cpe:2\.3:"
    r"(?P<part>[aho*\-]):"
    r"(?P<vendor>(?:\\.|[^\\:])+):"
    r"(?P<product>(?:\\.|[^\\:])+):"
    r"(?P<version>(?:\\.|[^\\:])+):"
    r"(?P<update>(?:\\.|[^\\:])+):"
    r"(?P<edition>(?:\\.|[^\\:])+):"
    r"(?P<language>(?:\\.|[^\\:])+):"
    r"(?P<sw_edition>(?:\\.|[^\\:])+):"
    r"(?P<target_sw>(?:\\.|[^\\:])+):"
    r"(?P<target_hw>(?:\\.|[^\\:])+):"
    r"(?P<other>(?:\\.|[^\\:])+)$",
    re.IGNORECASE,
)

CVE_ID_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_cpe23_uri_format(value: str, field_name: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError(f"{field_name} must not be empty or whitespace-only.")
    if CPE_2_3_URI_REGEX.fullmatch(candidate) is None:
        raise ValueError(
            f"{field_name} must be a valid CPE 2.3 formatted string (URI binding), "
            "starting with 'cpe:2.3:', using part a|h|o|*|-, followed by exactly eleven "
            "colon-separated components (vendor through other), with colons inside "
            "components only as backslash-escaped sequences."
        )
    return candidate


class Asset(BaseModel):
    """
    Normalized host or software asset with a mandatory CPE 2.3 identifier and optional network
    or inventory metadata.
    """

    model_config = ConfigDict(
        str_strip_whitespace=False,
        validate_assignment=True,
    )

    id: Optional[int] = Field(
        default=None,
        ge=1,
        description="SQLite primary key when the row already exists; omit on first insert.",
    )
    hostname: Optional[str] = Field(
        default=None,
        max_length=253,
        description="DNS hostname associated with the asset, if known.",
    )
    ip: Optional[str] = Field(
        default=None,
        max_length=45,
        description="IPv4 or IPv6 literal for the asset, if known.",
    )
    cpe_string: str = Field(
        ...,
        min_length=7,
        max_length=2048,
        description="CPE 2.3 formatted string (URI binding) for the platform or application.",
    )
    os: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Human-readable operating system label, if distinct from CPE fields.",
    )
    created_at: datetime = Field(
        default_factory=_utc_now,
        description="Record creation timestamp in UTC.",
    )

    @field_validator("hostname", "ip", "os", mode="before")
    @classmethod
    def optional_string_strip_empty_to_none(cls, value: object) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("hostname, ip, and os must be strings or null.")
        stripped = value.strip()
        return stripped if stripped else None

    @field_validator("cpe_string", mode="before")
    @classmethod
    def cpe_string_strip(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("cpe_string must be a string.")
        stripped = value.strip()
        if not stripped:
            raise ValueError("cpe_string must not be empty or whitespace-only.")
        return stripped

    @field_validator("cpe_string", mode="after")
    @classmethod
    def cpe_string_must_match_cpe_2_3_uri_regex(cls, value: str) -> str:
        return _validate_cpe23_uri_format(value, "cpe_string")

    @field_validator("id", mode="before")
    @classmethod
    def coerce_optional_positive_int_id(cls, value: object) -> Optional[int]:
        if value is None or value == "":
            return None
        if isinstance(value, bool):
            raise TypeError("id must not be a boolean.")
        if isinstance(value, int):
            if value < 1:
                raise ValueError("id must be a positive integer when provided.")
            return value
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            parsed = int(text, 10)
            if parsed < 1:
                raise ValueError("id must be a positive integer when provided.")
            return parsed
        raise TypeError("id must be a positive integer, numeric string, null, or omitted.")

    @field_validator("created_at", mode="before")
    @classmethod
    def created_at_timezone_normalize(cls, value: object) -> object:
        if value is None:
            return _utc_now()
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value


class CVE(BaseModel):
    """
    Normalized CVE record with bounded CVSS base score, prose description, and CPE applicability.
    """

    model_config = ConfigDict(
        str_strip_whitespace=False,
        validate_assignment=True,
    )

    cve_id: str = Field(
        ...,
        min_length=13,
        max_length=32,
        description="Official CVE identifier (CVE-YYYY-NNNN+).",
    )
    cvss_score: Optional[float] = Field(
        default=None,
        description="CVSS base score from 0.0 through 10.0 inclusive when present.",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=65535,
        description="Vulnerability description text from the source feed.",
    )
    base_cpe: str = Field(
        ...,
        min_length=7,
        max_length=2048,
        description="CPE 2.3 formatted string (URI binding) describing the affected product configuration.",
    )
    published_date: Optional[datetime] = Field(
        default=None,
        description="CVE publication timestamp from the authority, if provided.",
    )

    @field_validator("cve_id", mode="before")
    @classmethod
    def cve_id_strip_and_uppercase_prefix(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("cve_id must be a string.")
        text = value.strip().upper()
        if not text:
            raise ValueError("cve_id must not be empty or whitespace-only.")
        return text

    @field_validator("cve_id", mode="after")
    @classmethod
    def cve_id_must_match_registered_pattern(cls, value: str) -> str:
        if CVE_ID_REGEX.fullmatch(value) is None:
            raise ValueError(
                "cve_id must match the pattern CVE-YYYY-NNNN with a four-digit year and "
                "at least four sequence digits (for example CVE-2024-12345)."
            )
        return value

    @field_validator("cvss_score", mode="before")
    @classmethod
    def cvss_score_coerce_numeric(cls, value: object) -> Optional[float]:
        if value is None or value == "":
            return None
        if isinstance(value, bool):
            raise TypeError("cvss_score must not be a boolean.")
        if isinstance(value, float):
            return value
        if isinstance(value, int):
            return float(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            return float(text)
        raise TypeError("cvss_score must be a float, int, numeric string, or null.")

    @field_validator("cvss_score", mode="after")
    @classmethod
    def cvss_score_must_be_float_between_zero_and_ten_inclusive(cls, value: Optional[float]) -> Optional[float]:
        if value is None:
            return None
        if value != value:
            raise ValueError("cvss_score must not be NaN.")
        if value < 0.0 or value > 10.0:
            raise ValueError("cvss_score must be between 0.0 and 10.0 inclusive when provided.")
        return value

    @field_validator("description", mode="before")
    @classmethod
    def description_strip_empty_to_none(cls, value: object) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("description must be a string or null.")
        stripped = value.strip()
        return stripped if stripped else None

    @field_validator("base_cpe", mode="before")
    @classmethod
    def base_cpe_strip(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("base_cpe must be a string.")
        stripped = value.strip()
        if not stripped:
            raise ValueError("base_cpe must not be empty or whitespace-only.")
        return stripped

    @field_validator("base_cpe", mode="after")
    @classmethod
    def base_cpe_must_match_cpe_2_3_uri_regex(cls, value: str) -> str:
        return _validate_cpe23_uri_format(value, "base_cpe")

    @field_validator("published_date", mode="before")
    @classmethod
    def published_date_timezone_normalize(cls, value: object) -> object:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value
