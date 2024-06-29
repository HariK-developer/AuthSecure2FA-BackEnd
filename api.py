from fastapi import Depends, HTTPException, APIRouter
from fastapi.responses import JSONResponse, StreamingResponse
import pyotp
import qrcode
from database import get_db
from models import User
from schema import  UserLogin, UserSignup
from sqlalchemy.orm import Session
import bcrypt
import io

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
async def login(login_request: UserLogin, db: Session = Depends(get_db)):
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
                detail={"status": False, "message": "OTP required"},
            )
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(login_request.otp):
            raise HTTPException(
                status_code=401,
                detail={"status": False, "message": "Invalid OTP"},
            )
        return JSONResponse(content={"status": True, "message": "Login successful"})
    else:
        # 2FA is not enabled, generate a QR code for enabling 2FA
        totp = pyotp.TOTP(pyotp.random_base32())
        user.totp_secret = totp.secret
        user.is_2fa_enabled = True
        db.add(user)
        db.commit()
        db.refresh(user)

        # Generate provisioning URI
        uri = totp.provisioning_uri(name=user.username, issuer_name="App")

        # Generate QR code
        qr = qrcode.make(uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        buf.seek(0)

        return StreamingResponse(buf, media_type="image/png")


