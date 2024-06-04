import base64
import binascii
import casbin_sqlalchemy_adapter
import casbin
import os

from fastapi import FastAPI
from starlette.authentication import AuthenticationBackend, AuthenticationError, SimpleUser, AuthCredentials
from starlette.middleware.authentication import AuthenticationMiddleware

from fastapi_authz import CasbinMiddleware

from . import models
from .database import SessionLocal, engine
from dotenv import load_dotenv

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

load_dotenv()
adapter = casbin_sqlalchemy_adapter.Adapter(os.getenv("DB_URL"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class BasicAuth(AuthenticationBackend):
    async def authenticate(self, request):
        if "Authorization" not in request.headers:
            return None

        auth = request.headers["Authorization"]
        try:
            scheme, credentials = auth.split()
            decoded = base64.b64decode(credentials).decode("ascii")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            raise AuthenticationError("Invalid basic auth credentials")

        username, _, password = decoded.partition(":")
        return AuthCredentials(["authenticated"]), SimpleUser(username)


# enforcer = casbin.Enforcer('./app/casbin/rbac_model.conf', './app/casbin/rbac_policy.csv')
enforcer = casbin.Enforcer('./app/casbin/rbac_model.conf', adapter)

app.add_middleware(CasbinMiddleware, enforcer=enforcer)
app.add_middleware(AuthenticationMiddleware, backend=BasicAuth())


@app.get('/')
async def index():
    return "If you see this, you have been authenticated."


@app.get('/dataset1/protected')
async def auth_test():
    return "You must be alice to see this."
