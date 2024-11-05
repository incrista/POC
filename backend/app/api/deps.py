from fastapi import Depends, HTTPException, Request
from typing import Annotated
from core.auth.service import AuthorizationService, ApplicationID, Role
from core.auth.keycloak import User, AuthenticationError, AuthErrorCode

class RoleVerifier:
    def __init__(self, app_id: ApplicationID, required_role: Role):
        self.app_id = app_id
        self.required_role = required_role
        self.auth_service = AuthorizationService()

    async def __call__(self, request: Request) -> User:
        if not hasattr(request.scope, 'user'):
            print(request.scope)
            raise AuthenticationError(
                code=AuthErrorCode.MISSING_TOKEN,
                detail="User context not found"
            )
            
        user: User = request.state.user
        app_roles = user.get_application_roles(self.app_id)
        app_roles = self.auth_service.get_user_role()
        
        highest_role = None
        for role in app_roles:
            if not highest_role or self.auth_service.has_permission(role, highest_role):
                highest_role = role
                
        if not highest_role or not self.auth_service.has_permission(highest_role, self.required_role):
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions for {self.app_id}. Required: {self.required_role}"
            )
            
        return user