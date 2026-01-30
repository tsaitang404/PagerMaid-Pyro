from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pyrogram.errors import BadRequest
from starlette.responses import HTMLResponse

from pagermaid.services import bot
from pagermaid.utils import logs
from pagermaid.web.api import authentication
from pagermaid.web.api.web_login import web_login, UserModel
from pagermaid.web.html import get_web_login_passkey_html
from pyromod.methods.sign_in_passkey import (
    get_passkey_options,
    CredentialModel,
    authorize_by_passkey_web,
)
from pyromod.utils.errors import QRCodeWebNeedPWDError

route = APIRouter()
html_route = APIRouter()
web_login_passkey_html = get_web_login_passkey_html()


@route.get(
    "/web_login_passkey", response_class=JSONResponse, dependencies=[authentication()]
)
async def get_passkey_parameters():
    """Get passkey parameters for login"""
    if web_login.has_login():
        return {"status": 0, "msg": "已登录"}
    try:
        await web_login.connect()
        data = await get_passkey_options(bot)
        return {
            "status": 1,
            "msg": "Success",
            "content": data.dict(),
        }
    except Exception as e:
        logs.error(f"Failed to get passkey parameters: {str(e)}")
        return {"status": 3, "msg": f"Failed to get passkey parameters: {str(e)}"}


@route.post(
    "/web_login_passkey", response_class=JSONResponse, dependencies=[authentication()]
)
async def verify_passkey(credential: CredentialModel):
    """Verify passkey credential"""
    if web_login.has_login():
        return {"status": 0, "msg": "已登录"}
    try:
        await web_login.connect()
        if not web_login.is_authorized:
            await authorize_by_passkey_web(bot, credential)
            web_login.is_authorized = True
        await web_login.init()
        return {"status": 0, "msg": "登录成功"}
    except QRCodeWebNeedPWDError as e:
        web_login.need_password = True
        web_login.password_hint = e.hint or ""
        return {"status": 2, "msg": "需要密码", "content": web_login.password_hint}
    except BadRequest as e:
        return {"status": 3, "msg": e.MESSAGE}
    except Exception as e:
        logs.error(f"Passkey verification failed: {str(e)}")
        return {"status": 3, "msg": f"{type(e)}"}


@route.post(
    "/web_login_passkey_2fa",
    response_class=JSONResponse,
    dependencies=[authentication()],
)
async def verify_2fa(user: UserModel):
    """Verify 2FA password"""
    if web_login.has_login():
        return {"status": 0, "msg": "已登录"}
    if not web_login.need_password:
        return {"status": 0, "msg": "无需密码"}
    try:
        await authorize_by_passkey_web(bot, None, user.password)
        web_login.is_authorized = True
        await web_login.init()
        return {"status": 0, "msg": "登录成功"}
    except QRCodeWebNeedPWDError as e:
        web_login.need_password = True
        return {"status": 2, "msg": "密码错误", "content": e.hint or ""}
    except BadRequest as e:
        return {"status": 3, "msg": e.MESSAGE}
    except Exception as e:
        logs.error(f"2fa verification failed: {str(e)}")
        return {"status": 3, "msg": f"{type(e)}"}


@html_route.get(
    "/web_login_passkey", response_class=HTMLResponse, dependencies=[authentication()]
)
async def get_web_login_passkey():
    return web_login_passkey_html
