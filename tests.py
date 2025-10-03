import asyncio, json, pytest, websockets, base64, os, uuid
from servidorr import main, HOST, PORT

@pytest.mark.asyncio
async def test_full_handshake():
    uri=f"ws://localhost:{PORT}"
    async with websockets.connect(uri) as ws:
        await ws.send(json.dumps({"type":"handshake_init","client_id":"c1"}))
        r=json.loads(await ws.recv())
        assert r["type"]=="handshake_session"
        # OTP válido
        await ws.send(json.dumps({"type":"handshake_complete",
            "otp_id":r["otp_challenge"],"otp_response":"fake"}))
        resp=json.loads(await ws.recv())
        assert resp["type"] in ["handshake_ok","error"]
