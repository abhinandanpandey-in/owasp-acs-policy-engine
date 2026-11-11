from pydantic import BaseModel, Field
from typing import List, Dict, Optional

class AgBOMComponent(BaseModel):
    name: str
    type: str  # "tool", "mcp_server", "model"
    properties: Dict[str, str] = Field(default_factory=dict)

class AgBOMManifest(BaseModel):
    agent_name: str
    version: str
    components: List[AgBOMComponent]
    signature: Optional[str] = None

class AttenuatedToken(BaseModel):
    root_id: str
    signature: str  # Ed25519 signature of the root state
    caveats: List[str] = Field(default_factory=list)  # Chained HMACs

class ToolCallRequest(BaseModel):
    tool_name: str
    arguments: dict
    token: AttenuatedToken
