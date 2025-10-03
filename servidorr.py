#!/usr/bin/env python3
import asyncio, websockets, json, os, base64, hashlib, secrets, time, uuid
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST, PORT = "0.0.0.0", 8765

# Cargar clave RSA servidor
with open("server_key.pem","rb") as f:
    SERVER_KEY = serialization.load_pem_private_key(f.read(), password=None)
SERVER_PUB = SERVER_KEY.public_key()
SERVER_FP = hashlib.sha256(
    SERVER_PUB.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
).hexdigest()

CONNECTED = {}
USED_OTPS = {}

def now_iso(): return datetime.utcnow().isoformat()

async def handler(ws):
    client_id, session_key, aesgcm = None, None, None
    try:
        async for msg in ws:
            data = json.loads(msg)

            if data["type"] == "handshake_init":
                client_id = data["client_id"]
                # generar clave de sesión aleatoria
                raw_session = os.urandom(32)
                # derivar clave AES
                aes_key = HKDF(algorithm=hashes.SHA256(), length=32,
                               salt=None, info=b"session").derive(raw_session)
                aesgcm = AESGCM(aes_key)
                # OTP único
                otp_id = str(uuid.uuid4())
                otp_val = secrets.token_hex(8)
                USED_OTPS[otp_id] = {"val": otp_val, "ts": time.time(), "used": False}
                # cifrar clave de sesión con RSA
                enc_sess = SERVER_PUB.encrypt(
                    raw_session,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(), label=None))
                await ws.send(json.dumps({
                    "type":"handshake_session",
                    "enc_session_key": base64.b64encode(enc_sess).decode(),
                    "server_pub_fingerprint": SERVER_FP,
                    "otp_challenge": otp_id,
                    "otp_value_hint": "60s"
                }))
            
            elif data["type"] == "handshake_complete":
                otp_id, otp_resp = data["otp_id"], data["otp_response"]
                rec = USED_OTPS.get(otp_id)
                if not rec or rec["used"] or time.time()-rec["ts"]>60 or otp_resp!=rec["val"]:
                    await ws.send(json.dumps({"type":"error","reason":"OTP inválido"}))
                    await ws.close(); return
                rec["used"] = True
                CONNECTED[ws] = {"id": client_id, "aesgcm": aesgcm, "seen_ids": set()}
                await ws.send(json.dumps({"type":"handshake_ok"}))
            
            elif data["type"] == "message":
                if ws not in CONNECTED: continue
                state = CONNECTED[ws]
                iv = base64.b64decode(data["iv"])
                ct = base64.b64decode(data["ciphertext"])
                tag = base64.b64decode(data["tag"])
                try:
                    pt = state["aesgcm"].decrypt(iv, ct+tag, None).decode()
                except Exception:
                    continue
                # replay protection
                if data["message_id"] in state["seen_ids"]: continue
                state["seen_ids"].add(data["message_id"])
                ts = datetime.fromisoformat(data["timestamp"])
                if abs((datetime.utcnow()-ts).total_seconds())>30: continue
                print(f"[{state['id']}] {pt}")
                # rebroadcast en claro (solo demo)
                await asyncio.gather(*(c.send(json.dumps({
                    "type":"message","username":state["id"],"text":pt,"time":now_iso()
                })) for c in CONNECTED))
    finally:
        CONNECTED.pop(ws,None)

async def main():
    async with websockets.serve(handler, HOST, PORT):
        print(f"Servidor seguro en ws://{HOST}:{PORT}")
        await asyncio.Future()

if __name__=="__main__":
    asyncio.run(main())
