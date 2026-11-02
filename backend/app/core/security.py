from passlib.context import CryptContext
from jose import jwt, JWTError

from datetime import datetime, timedelta, timezone

import os

from fastapi import (
    Depends,
    HTTPException,
    status,
)

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User
from app.models.auth_session import AuthSession


# ==================================================
# PASSWORD HASHING
# ==================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:

    return pwd_context.verify(
        plain_password,
        hashed_password,
    )


# ==================================================
# JWT TOKEN CREATION
# ==================================================

def create_access_token(
    data: dict,
    expires_minutes: int = 60,
) -> str:

    to_encode = data.copy()

    expire = (
        datetime.now(timezone.utc)
        + timedelta(minutes=expires_minutes)
    )

    to_encode.update({
        "exp": expire
    })

    secret_key = os.getenv("SECRET_KEY")

    if not secret_key:
        raise ValueError(
            "SECRET_KEY is not configured"
        )

    algorithm = os.getenv(
        "ALGORITHM",
        "HS256",
    )

    return jwt.encode(
        to_encode,
        secret_key,
        algorithm=algorithm,
    )


# ==================================================
# JWT AUTHENTICATION
# ==================================================

security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials

    secret_key = os.getenv("SECRET_KEY")

    algorithm = os.getenv(
        "ALGORITHM",
        "HS256",
    )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={
            "WWW-Authenticate": "Bearer"
        },
    )

    try:

        payload = jwt.decode(
            token,
            secret_key,
            algorithms=[algorithm],
        )

        user_id = payload.get("sub")

        if user_id is None:
            raise credentials_exception

        session_id = payload.get("jti")
        if session_id:
            auth_session = db.query(AuthSession).filter_by(
                session_id=session_id, user_id=int(user_id), revoked_at=None
            ).first()
            if auth_session is None or auth_session.expires_at <= datetime.utcnow():
                raise credentials_exception

    except (
        JWTError,
        ValueError,
        TypeError,
    ):
        raise credentials_exception

    user = (
        db.query(User)
        .filter(
            User.id == int(user_id)
        )
        .first()
    )

    if user is None:
        raise credentials_exception

    return user
