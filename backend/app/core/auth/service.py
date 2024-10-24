from typing import Dict, List, Optional
from enum import Enum

class ApplicationID(str, Enum):
    APP1 = "App1"
    APP2 = "App2"
    APP3 = "App3"
    APP4 = "App4"

class Role(str, Enum):
    SUPER_ADMIN = "super-admin"
    ADMIN = "admin"
    OPERATOR = "operator"
    USER = "user"

class AuthorizationService:
    def __init__(self):
        self.role_hierarchy = {
            Role.SUPER_ADMIN: [Role.SUPER_ADMIN, Role.ADMIN, Role.OPERATOR, Role.USER],
            Role.ADMIN: [Role.ADMIN, Role.OPERATOR, Role.USER],
            Role.OPERATOR: [Role.OPERATOR, Role.USER],
            Role.USER: [Role.USER]
        }

    def get_user_role(self, token: dict, app_id: ApplicationID) -> Optional[Role]:
        application_roles = token.get('application-roles', [])
        app_prefix = f"/Applications/{app_id}"
        
        for role in Role:
            if f"{app_prefix}/{role}" in application_roles:
                return role
        return None

    def has_permission(self, user_role: Role, required_role: Role) -> bool:
        if user_role not in self.role_hierarchy:
            return False
        return required_role in self.role_hierarchy[user_role]