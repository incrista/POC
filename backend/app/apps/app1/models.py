from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime

class AdminActionRequest(BaseModel):
    action_type: str
    parameters: Dict[str, Any]

class AdminActionResponse(BaseModel):
    status: str
    result: Dict[str, Any]
    timestamp: datetime