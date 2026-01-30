import base64
from typing import TYPE_CHECKING, Optional

import json

import pyrogram
import pyrogram.raw
from pydantic import BaseModel
from pyrogram.errors import SessionPasswordNeeded, BadRequest

from pyromod.methods.sign_in_qrcode import migrate_to_dc
from pyromod.utils.errors import QRCodeWebNeedPWDError

if TYPE_CHECKING:
    from pyrogram import Client

    from pyrogram.raw.types.auth.passkey_login_options import PasskeyLoginOptions


class CredentialResponseModel(BaseModel):
    authenticatorData: str
    clientDataJSON: str
    signature: str
    userHandle: str


class CredentialModel(BaseModel):
    id: str
    rawId: str
    type: str
    response: CredentialResponseModel


class PasskeyLoginOptionsModel(BaseModel):
    challenge: str
    rpId: str
    timeout: int
    userVerification: str


async def get_passkey_options(client: "Client") -> PasskeyLoginOptionsModel:
    req: "PasskeyLoginOptions" = await client.invoke(
        pyrogram.raw.functions.auth.InitPasskeyLogin(
            api_id=client.api_id,
            api_hash=client.api_hash,
        )
    )
    data = json.loads(req.options.data)
    return PasskeyLoginOptionsModel(**data["publicKey"])


async def authorize_by_passkey(client: "Client", credential: CredentialModel):
    user_handle = base64.b64decode(credential.response.userHandle).decode("utf-8")
    user_handle_split = user_handle.split(":")
    dc_id = int(user_handle_split[0])
    user_id = int(user_handle_split[1])

    client_data = pyrogram.raw.types.DataJSON(
        data=base64.b64decode(credential.response.clientDataJSON).decode("utf-8")
    )
    response = pyrogram.raw.types.InputPasskeyResponseLogin(
        client_data=client_data,
        authenticator_data=base64.b64decode(credential.response.authenticatorData),
        signature=base64.b64decode(credential.response.signature),
        user_handle=user_handle,
    )
    cred = pyrogram.raw.types.InputPasskeyCredentialPublicKey(
        id=credential.id,
        raw_id=credential.id,
        response=response,
    )
    login = pyrogram.raw.functions.auth.FinishPasskeyLogin(
        credential=cred,
    )
    if dc_id != client.session.dc_id:
        login.from_dc_id = client.session.dc_id
        login.from_auth_key_id = int.from_bytes(
            client.session.auth_key_id, byteorder="little", signed=True
        )

        await migrate_to_dc(client, dc_id)

    req = await client.invoke(login)

    if isinstance(req, pyrogram.raw.types.auth.Authorization):
        await client.storage.user_id(req.user.id)
        await client.storage.is_bot(False)
        return pyrogram.types.User._parse(client, req.user)


async def authorize_by_passkey_web(
    client: "Client",
    credential: Optional[CredentialModel] = None,
    password: Optional[str] = None,
):
    try:
        if password:
            client.password = password
            raise SessionPasswordNeeded()
        user = await authorize_by_passkey(client, credential)
    except BadRequest as e:
        raise e
    except SessionPasswordNeeded as e:
        try:
            if client.password:
                return await client.check_password(client.password)
        except BadRequest as e:
            client.password = None
            raise e
        raise QRCodeWebNeedPWDError(await client.get_password_hint()) from e
    if isinstance(user, pyrogram.types.User):
        return user
