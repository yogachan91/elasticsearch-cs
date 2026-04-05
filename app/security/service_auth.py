from fastapi import Header, HTTPException
import jwt
import os

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "rahasia")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

def verify_service_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(401, "Missing service token")

    try:
        scheme, token = authorization.split()
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

        if payload.get("type") != "service":
            raise HTTPException(403, "Not service token")

        if payload.get("iss") != "main-backend":
            raise HTTPException(403, "Invalid issuer")

    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Service token expired")
    except Exception:
        raise HTTPException(403, "Forbidden")
