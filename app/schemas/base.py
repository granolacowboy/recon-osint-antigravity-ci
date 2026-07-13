from typing import Any

from pydantic import BaseModel, ConfigDict, Field

class TargetEntity(BaseModel):
    """
    Base class for any entity targeted by RECON OSINT adapters.
    """
    model_config = ConfigDict(extra='forbid')

    value: str = Field(min_length=1, max_length=2048)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
