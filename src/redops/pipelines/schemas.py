"""
Pipeline schema validation using Pydantic.

Defines the structure of pipeline JSON files and validates them.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class PipelineStep(BaseModel):
    """
    A single step in a pipeline.

    Each step references a module function via dotted path,
    e.g., "recon.domains.profile_domain"
    """

    name: str = Field(description="Human-readable name for the step")
    module: str = Field(
        description="Dotted path to module function, e.g., 'recon.domains.profile_domain'"
    )
    params: Dict[str, Any] = Field(
        default_factory=dict, description="Parameters to pass to the module"
    )
    enabled: bool = Field(default=True, description="Whether this step is enabled")
    continue_on_error: bool = Field(
        default=False, description="Continue pipeline execution if this step fails"
    )

    @field_validator("module")
    @classmethod
    def validate_module_path(cls, v: str) -> str:
        """Validate that module path has at least one dot."""
        if "." not in v:
            raise ValueError(f"Module path must be a dotted path, got: {v}")
        return v


class PipelineMetadata(BaseModel):
    """Metadata about the pipeline."""

    name: str
    description: Optional[str] = None
    version: str = "1.0"
    author: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class Pipeline(BaseModel):
    """
    A complete pipeline definition.

    Pipelines are JSON-defined workflows that run sequentially,
    passing a Context object through each step.
    """

    metadata: PipelineMetadata
    steps: List[PipelineStep] = Field(
        min_length=1, description="Pipeline must have at least one step"
    )
    config: Dict[str, Any] = Field(
        default_factory=dict, description="Pipeline-level configuration"
    )

    @property
    def enabled_steps(self) -> List[PipelineStep]:
        """Return only enabled steps."""
        return [step for step in self.steps if step.enabled]

    def validate_pipeline(self) -> bool:
        """
        Validate the pipeline structure.

        Returns:
            True if valid, raises ValueError otherwise
        """
        if not self.steps:
            raise ValueError("Pipeline must have at least one step")

        if not self.enabled_steps:
            raise ValueError("Pipeline must have at least one enabled step")

        return True
