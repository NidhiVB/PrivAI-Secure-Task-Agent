"""Risk scoring models."""

from pydantic import BaseModel, ConfigDict, Field
from backend.app.models.enums import RiskBand


class RiskFactors(BaseModel):
    """Component factors explaining the calculated risk score."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: float = Field(ge=0.0, le=1.0, description="Normalized maximum severity S")
    count: int = Field(ge=0, description="Raw number of findings")
    normalized_count: float = Field(default=0.0, ge=0.0, le=1.0, description="Normalized count factor N")
    context: float = Field(ge=0.0, le=1.0, description="Context sensitivity factor C")
    destination: float = Field(ge=0.0, le=1.0, description="Destination exposure factor D")
    identifiability: float = Field(ge=0.0, le=1.0, description="Identifiability/linkage factor I")


class RiskScore(BaseModel):
    """Explainable risk score representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    score: int = Field(ge=0, le=100, description="Risk score from 0 to 100")
    band: RiskBand
    factors: RiskFactors | None = None
    factor_contributions: dict[str, float] = Field(
        default_factory=dict, description="Factor contributions to the aggregate score"
    )
    reason_codes: list[str] = Field(
        default_factory=list, description="Machine-readable risk reason codes"
    )
    version: str = Field(default="risk-v1", description="Risk scoring algorithm version")
