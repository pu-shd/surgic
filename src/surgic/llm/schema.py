"""Structured output contract for Phase B.

The model returns only offsets, the exact flagged substring (validated against
the chunk, never logged), a category enum and a rationale enum. No free text.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal[
    "INDIRECT_IDENTIFIER", "PERSON_CONTEXTUAL", "TRADE_SECRET", "CLIENT_RELATIONSHIP",
    "VENDOR_RELATIONSHIP", "FINANCIAL_DETAIL", "LOCATION_CONTEXTUAL", "INTERNAL_PROJECT",
    "LEGAL_MATTER", "SECURITY_DETAIL", "OTHER_SENSITIVE",
]
Rationale = Literal[
    "UNIQUE_ROLE_OR_TITLE", "QUASI_IDENTIFIER_COMBINATION", "PROPRIETARY_PROCESS",
    "PRICING_OR_TERMS", "CONTRACT_COUNTERPARTY", "NON_PUBLIC_PLAN", "NAMED_ENTITY_IN_CONTEXT",
    "INFRASTRUCTURE_DETAIL", "HEALTH_OR_PERSONAL_DETAIL", "OTHER",
]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    text: str = Field(min_length=1, max_length=2000)
    category: Category
    rationale_code: Rationale


class Findings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[Finding] = Field(max_length=500)


def json_schema() -> dict:
    schema = Findings.model_json_schema()
    # Grammar engines prefer inlined definitions.
    defs = schema.pop("$defs", {})
    items = schema["properties"]["findings"]["items"]
    if "$ref" in items:
        schema["properties"]["findings"]["items"] = defs[items["$ref"].split("/")[-1]]
    return schema
