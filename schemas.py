from pydantic import BaseModel


class ThreatVerdict(BaseModel):
    severity: str
    confidence: str
    summary: str
    delivery_vector: str
    user_interaction: str
    kit_fingerprint: str
    reasoning: str


class HuntDecision(BaseModel):
    hunt: bool
    reason: str


class ChainFilter(BaseModel):
    approve: list[str]
    skip: list[str]
    reason: str


class MemoryEntry(BaseModel):
    url: str
    domain: str
    severity: str
    kit_fingerprint: str
    delivery_vector: str
    timestamp: str
    has_malicious_download: bool = False


class MemoryQueryResult(BaseModel):
    entries: list[MemoryEntry]
    pattern_note: str


class TakedownEmail(BaseModel):
    email: str
