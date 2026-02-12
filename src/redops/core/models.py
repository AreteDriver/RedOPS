"""
Pydantic models and data structures for RedOps.

Defines data models for risk assessment, targets, findings, and other
structured data used throughout the framework.
"""

from typing import Any
from pydantic import BaseModel, Field
from enum import Enum


class RiskLevel(str, Enum):
    """Risk level enumeration."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskCategory(str, Enum):
    """Risk category enumeration."""

    OWASP = "owasp"
    MITRE = "mitre"
    EXPOSURE = "exposure"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"


class Risk(BaseModel):
    """Model for risk assessment."""

    title: str
    description: str
    likelihood: int = Field(ge=1, le=5, description="Likelihood score (1-5)")
    impact: int = Field(ge=1, le=5, description="Impact score (1-5)")
    category: RiskCategory | None = None
    mitre_id: str | None = None
    owasp_id: str | None = None

    @property
    def score(self) -> int:
        """Calculate risk score as likelihood × impact."""
        return self.likelihood * self.impact

    @property
    def level(self) -> RiskLevel:
        """Determine risk level based on score."""
        if self.score >= 20:
            return RiskLevel.CRITICAL
        elif self.score >= 12:
            return RiskLevel.HIGH
        elif self.score >= 6:
            return RiskLevel.MEDIUM
        elif self.score >= 3:
            return RiskLevel.LOW
        return RiskLevel.INFO


class Target(BaseModel):
    """Model for a target (domain, IP, directory, etc.)."""

    value: str
    type: str = Field(description="Type of target: domain, ip, directory, etc.")
    metadata: dict[str, Any] = Field(default_factory=dict)
    in_scope: bool = True


class Finding(BaseModel):
    """Model for a finding or discovery."""

    module: str
    title: str
    description: str
    severity: RiskLevel = RiskLevel.INFO
    data: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class Asset(BaseModel):
    """Model for an identified asset."""

    name: str
    type: str
    description: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    risks: list[Risk] = Field(default_factory=list)


class AttackPath(BaseModel):
    """Model for an attack path in simulation."""

    name: str
    description: str
    steps: list[str]
    mitre_techniques: list[str] = Field(default_factory=list)
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)

    @property
    def risk_score(self) -> int:
        """Calculate attack path risk score."""
        return self.likelihood * self.impact


class ReconResult(BaseModel):
    """Model for reconnaissance results."""

    target: str
    findings: list[Finding] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    risks: list[Risk] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TechStack(BaseModel):
    """Model for technology stack fingerprinting."""

    web_server: str | None = None
    frameworks: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    libraries: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    fingerprints: dict[str, Any] = Field(default_factory=dict)


class ExifData(BaseModel):
    """Model for EXIF metadata."""

    filename: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    sensitive_fields: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class DocumentMetadata(BaseModel):
    """Model for document metadata."""

    filename: str
    file_type: str
    author: str | None = None
    created: str | None = None
    modified: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
