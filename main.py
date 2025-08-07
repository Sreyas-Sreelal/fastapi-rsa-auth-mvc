from fastapi import FastAPI, Request, Response, Depends, HTTPException
from typing import Annotated
import jwt
from datetime import datetime, timedelta

PRIVATE_KEY = None
PUBLIC_KEY = None


def load_secret_keys():
    global PRIVATE_KEY, PUBLIC_KEY

    f = open("private_key", "rb")
    PRIVATE_KEY = f.read()
    f.close()

    f = open("public_key", "rb")
    PUBLIC_KEY = f.read()
    f.close()


def decode_token(token: str):
    jwt.decode(token, key=PUBLIC_KEY, algorithm="RS256")


def create_token_pairs(response: Response, data: dict):
    current = datetime.now()
    access_token = jwt.encode(
        {
            **data,
            "iat": current.timestamp(),
            "exp": (timedelta(seconds=10) + current).timestamp()
        },
        key=PRIVATE_KEY,
        algorithm="RS256"
    )

    refresh_token = jwt.encode(
        {
            **data,
            "iat": current.timestamp(),
            "exp": (timedelta(hours=10) + current).timestamp()
        },
        key=PRIVATE_KEY,
        algorithm="RS256"
    )
    response.set_cookie("access_token", access_token, httponly=True)
    response.set_cookie("refresh_token", refresh_token, httponly=True, path="/refresh")


def decode_token(token: str):
    if not token:
        raise HTTPException(status_code=403, detail="no token")
    try:
        token_decoded = jwt.decode(token, key=PUBLIC_KEY, algorithms="RS256")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"invalid token, {e}")

    if token_decoded['exp'] < datetime.now().timestamp():
        raise HTTPException(status_code=403, detail="expired token")

    return token_decoded


def validate_access_token(request: Request):
    return decode_token(request.cookies.get("access_token"))


load_secret_keys()

app = FastAPI()


@app.post("/login")
def login(username: str, password: str,  response:  Response):
    create_token_pairs(response, {"username": username})
    return {"ok": True, "message": "login success"}


@app.get('/refresh')
def refresh(request: Request, response: Response):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException()
    refresh_token_decoded = decode_token(refresh_token)
    create_token_pairs(
        response, {"username": refresh_token_decoded['username']}
    )
    return {"ok": True, "message": "success"}


@app.post("/protected")
def do_some_protected_work(decoded_token: Annotated[str, Depends(validate_access_token)]):
    return "success"
