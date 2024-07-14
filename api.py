from fastapi import Depends, HTTPException, APIRouter, Request
from fastapi.responses import JSONResponse
import pyotp
import qrcode
from database import get_db
from models import User
from schema import  UserLogin, UserSignup
from sqlalchemy.orm import Session
import bcrypt
import os
from datetime import datetime, timedelta
import jwt

SECRET_KEY = "f3c5e57ef88a6c4e7eb5fa53bb03ab11b7281b9b3d74f90ad1e9650b70727dbf"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1  

router = APIRouter()

@router.post("/signup")
async def signup(signup_request: UserSignup, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == signup_request.username).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail={"status": False, "message": "Username already taken"},
        )

    hashed_password = bcrypt.hashpw(
        signup_request.password.encode("utf-8"), bcrypt.gensalt()
    )
    new_user = User(
        username=signup_request.username, password=hashed_password.decode("utf-8")
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return JSONResponse(
        content={"status": True, "message": "User created successfully"}
    )

@router.post("/login")
async def login(login_request: UserLogin, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_request.username).first()
    if not user or not bcrypt.checkpw(
        login_request.password.encode("utf-8"), user.password.encode("utf-8")
    ):
        raise HTTPException(
            status_code=401,
            detail={"status": False, "message": "Invalid username or password"},
        )

    if user.is_2fa_enabled:
        if not login_request.otp:
            raise HTTPException(
                status_code=401,
                detail={"status": False, "otp": True, "message": "OTP required"},
            )
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(login_request.otp):
            raise HTTPException(
                status_code=401,
                detail={"status": False, "message": "Invalid OTP"},
            )
        # Generate JWT token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
        return JSONResponse(content={"status": True, "message": "Login successful", "access_token": access_token})
    else:
        # 2FA is not enabled, generate a QR code for enabling 2FA
        totp = pyotp.TOTP(pyotp.random_base32())
        user.totp_secret = totp.secret
        user.is_2fa_enabled = True
        db.add(user)
        db.commit()
        db.refresh(user)

        # Generate provisioning URI
        uri = totp.provisioning_uri(name=user.username, issuer_name=user.username)

        # Generate QR code
        qr = qrcode.make(uri)
        file_path = os.path.join("static", "qrcodes", f"{user.username}.png")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        qr.save(file_path)

        # Construct the full URL for the QR code
        qr_code_url = request.url_for('static', path=f'qrcodes/{user.username}.png')

        # Generate JWT token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

        return JSONResponse(content={
            "status": True,
            "message": "Login successful",
            "otp": False,
            "qr_code_url": str(qr_code_url),  # Convert URL object to string
            "access_token": access_token
        })

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



