from pydantic import BaseModel, EmailStr, ConfigDict
from uuid import UUID
from datetime import datetime

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str = "ANALYST"

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: UUID
    email: str
    full_name: str
    role: str

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    full_name: str
    role: str
    created_at: datetime
