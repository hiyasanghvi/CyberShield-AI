from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Request,
)
from datetime import datetime, timedelta
import os
import uuid
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt

from sqlalchemy.orm import Session

from app.db.database import get_db

from app.models.user import User
from app.models.auth_session import AuthSession

from app.schemas.auth import (
    UserRegister,
    UserLogin,
    UserResponse,
    Token,
)

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"],
)


# ==================================================
# REGISTER
# ==================================================

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user_data: UserRegister,
    db: Session = Depends(get_db),
):

    existing_user = (
        db.query(User)
        .filter(
            User.email == user_data.email
        )
        .first()
    )

    if existing_user:

        raise HTTPException(
            status_code=400,
            detail="Email already registered",
        )

    new_user = User(
        name=user_data.name,
        email=user_data.email,
        hashed_password=hash_password(
            user_data.password
        ),
    )

    db.add(new_user)

    db.commit()

    db.refresh(new_user)

    return new_user


# ==================================================
# LOGIN
# ==================================================

@router.post(
    "/login",
    response_model=Token,
)
def login(
    user_data: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
):

    user = (
        db.query(User)
        .filter(
            User.email == user_data.email
        )
        .first()
    )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    if not verify_password(
        user_data.password,
        user.hashed_password,
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    now = datetime.utcnow()
    expires_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    session_id = str(uuid.uuid4())
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "jti": session_id,
        },
        expires_minutes=expires_minutes,
    )
    db.add(AuthSession(
        session_id=session_id,
        user_id=user.id,
        created_at=now,
        expires_at=now + timedelta(minutes=expires_minutes),
        user_agent=request.headers.get("user-agent", "")[:300],
    ))
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


# ==================================================
# PROFILE
# ==================================================

@router.get(
    "/profile",
    response_model=UserResponse,
)
def profile(
    current_user: User = Depends(
        get_current_user
    ),
):

    return current_user


def _session_id(credentials: HTTPAuthorizationCredentials) -> str | None:
    secret_key = os.getenv("SECRET_KEY")
    algorithm = os.getenv("ALGORITHM", "HS256")
    payload = jwt.decode(credentials.credentials, secret_key, algorithms=[algorithm])
    return payload.get("jti")


@router.get("/sessions")
def sessions(request: Request, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
             current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current_id = _session_id(credentials)
    rows = db.query(AuthSession).filter(
        AuthSession.user_id == current_user.id,
        AuthSession.revoked_at.is_(None),
        AuthSession.expires_at > datetime.utcnow(),
    ).order_by(AuthSession.created_at.desc()).all()
    return [{"session_id": row.session_id, "current": row.session_id == current_id,
             "created_at": row.created_at, "expires_at": row.expires_at,
             "device": (row.user_agent or request.headers.get("user-agent", "This device"))[:120]}
            for row in rows]


@router.post("/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
           current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    session_id = _session_id(credentials)
    if session_id:
        db.query(AuthSession).filter_by(session_id=session_id, user_id=current_user.id,
                                        revoked_at=None).update({"revoked_at": datetime.utcnow()})
        db.commit()
    return {"message": "Session signed out"}


@router.delete("/sessions/{session_id}")
def revoke_session(session_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.query(AuthSession).filter_by(session_id=session_id, user_id=current_user.id,
                                          revoked_at=None).first()
    if not row:
        raise HTTPException(status_code=404, detail="Active session not found")
    row.revoked_at = datetime.utcnow()
    db.commit()
    return {"message": "Session revoked"}


@router.post("/logout-all")
def logout_all(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(AuthSession).filter(AuthSession.user_id == current_user.id,
                                 AuthSession.revoked_at.is_(None)).update(
        {"revoked_at": datetime.utcnow()}, synchronize_session=False)
    db.commit()
    return {"message": "All active sessions signed out"}
