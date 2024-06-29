from pydantic import BaseModel
from typing import Optional

class UserSignup(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str
    otp: Optional[str] = None  # Optional OTP field


