from pydantic import BaseModel
from typing import Dict, Any

class OperatorActionRequest(BaseModel):
    operation_type: str
    data: Dict[str, Any]

class OperatorActionResponse(BaseModel):
    status: str
    operation_result: Dict[str, Any]