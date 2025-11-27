# backend/core/views.py
import json
import time
import uuid
import hmac
import hashlib

from django.conf import settings
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from cryptography.fernet import Fernet

# Helper: create a demo user token (replace with real token/jwt/session logic)
def _generate_user_token(user_id: str):
    return f"USER-TOKEN-{user_id}-{int(time.time())}"


def auth_init(request):
    """
    Endpoint: GET /auth/init/
    Returns a tiny HTML (index.html) with encrypted payload inserted.
    Intended to be loaded in a hidden iframe or fetched as HTML by React.
    """
    # -------------------------
    # 0) GET CLIENT IP
    # -------------------------
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    print("Forwarded", request.META.get("REMOTE_ADDR"), forwarded)
    client_ip = forwarded.split(",")[0] if forwarded else request.META.get("REMOTE_ADDR")

    print("\n==============================")
    print("CLIENT_IP =>", client_ip,)
    print("==============================\n")

    user_id = request.session.session_key or str(uuid.uuid4())
    token = _generate_user_token(user_id)

    aes_key = Fernet.generate_key()
    cipher = Fernet(aes_key)
    encrypted = cipher.encrypt(token.encode()).decode()

    signer = TimestampSigner(settings.SECRET_KEY)
    sealed_key = signer.sign(aes_key.decode()).decode()

    signature = hmac.new(settings.SECRET_KEY.encode(), encrypted.encode(), hashlib.sha256).hexdigest()

    return render(request, "index.html", {
        "encrypted": encrypted,
        "sealed_key": sealed_key,
        "signature": signature,
        "public_ip": client_ip,
    })


@csrf_exempt
def verify_access(request):
    """
    Endpoint: POST /auth/verify-access/
    Accepts { encrypted, sealed_key, signature }.
    Decrypts the token, validates, and returns access permission in one step.
    """

    # -------------------------
    # 0) GET CLIENT IP
    # -------------------------
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    client_ip = forwarded.split(",")[0] if forwarded else request.META.get("REMOTE_ADDR")

    print("\n==============================")
    print("CLIENT_IP =>", client_ip)
    print("==============================\n")

    # -------------------------
    # 1) Parse JSON body
    # -------------------------
    try:
        body = json.loads(request.body.decode())
        encrypted = body.get("encrypted")
        sealed_key = body.get("sealed_key")
        signature = body.get("signature")
    except Exception:
        return JsonResponse({"allowed": False, "error": "invalid_payload"}, status=400)

    if not all([encrypted, sealed_key, signature]):
        return JsonResponse({"allowed": False, "error": "missing_fields"}, status=400)

    # -------------------------
    # 2) Verify HMAC signature
    # -------------------------
    expected_sig = hmac.new(settings.SECRET_KEY.encode(), encrypted.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, signature):
        return JsonResponse({"allowed": False, "error": "bad_signature"}, status=403)

    # -------------------------
    # 3) Unseal AES key
    # -------------------------
    signer = TimestampSigner(settings.SECRET_KEY)
    try:
        aes_key_result = signer.unsign(sealed_key, max_age=60)
    except SignatureExpired:
        return JsonResponse({"allowed": False, "error": "sealed_key_expired"}, status=403)
    except BadSignature:
        return JsonResponse({"allowed": False, "error": "bad_sealed_key"}, status=403)

    aes_key = aes_key_result.encode() if isinstance(aes_key_result, str) else aes_key_result

    # -------------------------
    # 4) Decrypt Token
    # -------------------------
    try:
        cipher = Fernet(aes_key)
        real_token = cipher.decrypt(encrypted.encode()).decode()
    except Exception:
        return JsonResponse({"allowed": False, "error": "decrypt_failed"}, status=500)

    # -------------------------
    # 5) Your Auth Logic
    # -------------------------
    allowed = real_token.startswith("USER-TOKEN-")
    print("IIIIIIIIIPPPPPPPPP", client_ip)
    return JsonResponse({
        "allowed": allowed,
        "token": real_token,
        "client_ip": client_ip  # optional: remove if you don’t want
    })
