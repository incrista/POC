from fastapi import APIRouter, Depends
from typing import Annotated
from apps.app1.services import App1Service
from apps.app1.models import AdminActionRequest, AdminActionResponse
from api.deps import RoleVerifier
from core.auth.service import ApplicationID, Role

router = APIRouter(prefix="/app1")

@router.post("/admin-action", response_model=AdminActionResponse)
async def admin_action(
    action_request: AdminActionRequest,
    token: Annotated[dict, Depends(RoleVerifier(ApplicationID.APP1, Role.ADMIN))],
    service: App1Service = Depends()
):
    print("Hi")
    return await service.process_admin_action(token['sub'], action_request)

@router.get("/admin-data")
async def get_admin_data(
    token: Annotated[dict, Depends(RoleVerifier(ApplicationID.APP1, Role.ADMIN))],
    service: App1Service = Depends()
):
    return await service.get_admin_data(token['sub'])