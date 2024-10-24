from fastapi import APIRouter, Depends
from typing import Annotated
from apps.app2.services import App2Service
from apps.app2.models import OperatorActionRequest, OperatorActionResponse
from api.deps import RoleVerifier
from core.auth.service import ApplicationID, Role

router = APIRouter(prefix="/app2")

@router.post("/operator-action", response_model=OperatorActionResponse)
async def operator_action(
    action_request: OperatorActionRequest,
    token: Annotated[dict, Depends(RoleVerifier(ApplicationID.APP2, Role.OPERATOR))],
    service: App2Service = Depends()
):
    return await service.process_operator_action(token['sub'], action_request)