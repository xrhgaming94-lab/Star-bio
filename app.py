from flask import Flask, request, jsonify, make_response
import requests
import binascii
import jwt
import urllib3
import json
import base64
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

DEFAULT_REGION = "IND"

# ==================== AES CONSTANTS ====================

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_data(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

# ==================== UID/PASSWORD -> JWT (API) ====================

def get_jwt_from_uid_password_api(uid, password):
    """Get JWT directly using the star-jwt-gen API"""
    url = f"https://star-jwt-api1.lovable.app/api/public/token?uid={uid}&password={password}"
    try:
        print(f"[UID/PASS] Calling JWT API: {url}")
        response = requests.get(url, timeout=25)
        response.raise_for_status()
        data = response.json()
        print(f"[UID/PASS] API Response success: {data.get('success')}")

        if "token" in data:
            jwt_token = data["token"]
            try:
                decoded = jwt.decode(jwt_token, options={"verify_signature": False})
                account_id = str(decoded.get("account_id"))
                nickname = decoded.get("nickname")
                region = decoded.get("lock_region") or decoded.get("noti_region") or decoded.get("region") or DEFAULT_REGION
                print(f"[UID/PASS] Success! UID: {account_id}, Name: {nickname}, Region: {region}")
                return jwt_token, account_id, nickname, region
            except Exception as e:
                print(f"[UID/PASS] JWT decode error: {e}")
                return jwt_token, uid, "Unknown", DEFAULT_REGION
        else:
            error_msg = data.get("error", "No token in response")
            print(f"[UID/PASS] API Error: {error_msg}")
            return None, None, None, None
    except Exception as e:
        print(f"[UID/PASS] Request error: {e}")
        return None, None, None, None

# ==================== ACCESS TOKEN -> JWT (NEW API Method) ====================

def get_jwt_from_access_token(access_token):
    """Convert access token to JWT using the ff-jwt-gen-api"""
    url = f"https://ff-jwt-gen-api.lovable.app/api/public/token?access_token={access_token}"
    try:
        print(f"[ACCESS] Calling JWT API: {url}")
        response = requests.get(url, timeout=25)
        response.raise_for_status()
        data = response.json()
        print(f"[ACCESS] API Response success: {data.get('success')}")

        if not data.get("success") or "token" not in data:
            error_msg = data.get("error", "No token in response")
            print(f"[ACCESS] API Error: {error_msg}")
            return None, None, None

        jwt_token = data["token"]
        account_uid = str(data.get("account_uid") or "")
        region = data.get("region") or DEFAULT_REGION

        # Fallback: try decoded payload if account_uid missing
        if not account_uid:
            try:
                decoded = jwt.decode(jwt_token, options={"verify_signature": False})
                account_uid = str(decoded.get("account_id"))
                region = decoded.get("lock_region") or decoded.get("noti_region") or region
            except Exception as e:
                print(f"[ACCESS] JWT decode error: {e}")

        print(f"[ACCESS] Success! UID: {account_uid}, Region: {region}")
        return jwt_token, account_uid, region

    except Exception as e:
        print(f"[ACCESS] Request error: {e}")
        return None, None, None

# ==================== REGION CONFIGURATION ====================

MIDDLE_EAST_REGIONS = [
    "EUROPE", "MIDDLEEAST", "MIDDLE_EAST", "ME", "DUBAI", "UAE", "SAUDI",
    "SAUDIARABIA", "KSA", "EGYPT", "EG", "TURKEY", "TR", "IRAQ", "IQ",
    "QATAR", "QA", "KUWAIT", "KW", "OMAN", "OM", "BAHRAIN", "BH", "PAKISTAN", "PK"
]

REGION_ALIASES = {
    "EUROPE": "ME", "MIDDLEEAST": "ME", "DUBAI": "ME", "UAE": "ME",
    "SAUDI": "ME", "EGYPT": "ME", "TURKEY": "ME", "PAKISTAN": "ME", "PK": "ME",
    "ASIA": "SG", "SOUTHAMERICA": "BR", "NORTH_AMERICA": "NA"
}

REGION_MAP = {
    "IND": {"update_url": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo"},
    "ME": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "BD": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "PK": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "TW": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "TH": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "VN": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "ID": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "RU": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "EU": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "SG": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"},
    "BR": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo"},
    "SAC": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo"},
    "NA": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo"},
}

FREEFIRE_VERSION = "OB55"

# ✅ BIO / UpdateSocialBasicInfo Headers
BIO_HEADERS = {
    "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "Accept": "*/*",
    "Accept-Encoding": "deflate, gzip",
    "X-Ga-Sv": "1789534056",
    "Authorization": "Bearer ",
    "X-Ga": "v1 1",
    "Releaseversion": FREEFIRE_VERSION,
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Unity-Version": "2018.4.12f1",
}

# ==================== PROTOBUF: BioData ====================

_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
b'\n\ndata.proto"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage"\x0e\n\x0c\x45mptyMessageb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'data1_pb2', _globals)

BioData = _sym_db.GetSymbol('Data')
EmptyMessage = _sym_db.GetSymbol('EmptyMessage')

# ==================== HELPERS ====================

def decode_jwt_full(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        nickname = decoded.get("nickname")
        # Try base64 decode (FreeFire encodes nickname)
        if nickname:
            try:
                decoded_nick = base64.b64decode(nickname).decode("utf-8", errors="ignore")
                if decoded_nick and decoded_nick.isprintable():
                    nickname = decoded_nick
            except Exception:
                pass
        return {
            "uid": str(decoded.get("account_id")),
            "name": nickname,
            "region": (decoded.get("lock_region") or decoded.get("noti_region") or decoded.get("region") or "").upper(),
            "country": decoded.get("country_code")
        }
    except Exception:
        return None

def map_region(jwt_region):
    if not jwt_region:
        return DEFAULT_REGION
    jwt_region = jwt_region.upper()
    if jwt_region in REGION_MAP:
        return jwt_region
    if jwt_region in REGION_ALIASES:
        return REGION_ALIASES[jwt_region]
    return DEFAULT_REGION

def _add_region_param(url, region):
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q["region"] = region
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, urlencode(q), parts.fragment))

def get_region_urls(region):
    region = region.upper() if region else DEFAULT_REGION
    if region not in REGION_MAP:
        region = DEFAULT_REGION
    update_url = _add_region_param(REGION_MAP[region]["update_url"], region)
    return region, update_url

def upload_bio_request(jwt_token, bio_text, update_url):
    try:
        data = BioData()
        data.field_2 = 17
        data.field_5.CopyFrom(EmptyMessage())
        data.field_6.CopyFrom(EmptyMessage())
        data.field_8 = bio_text
        data.field_9 = 1
        data.field_11.CopyFrom(EmptyMessage())
        data.field_12.CopyFrom(EmptyMessage())

        data_bytes = data.SerializeToString()
        encrypted = encrypt_data(data_bytes)

        headers = BIO_HEADERS.copy()
        headers["Authorization"] = f"Bearer {jwt_token}"

        resp = requests.post(update_url, headers=headers, data=encrypted, verify=False, timeout=15)

        status = "✅ Success" if resp.status_code == 200 else "❌ Failed"
        return {
            "status": status,
            "code": resp.status_code,
            "server_response": binascii.hexlify(resp.content).decode()
        }
    except Exception as e:
        return {"status": str(e), "code": 500, "server_response": ""}

# ==================== MAIN ROUTE ====================

@app.route("/bio", methods=["GET", "POST"])
def combined_bio_upload():
    bio = request.args.get("bio") or request.form.get("bio")
    jwt_token = request.args.get("jwt") or request.form.get("jwt")
    uid = request.args.get("uid") or request.form.get("uid")
    password = request.args.get("pass") or request.args.get("password") or request.form.get("pass") or request.form.get("password")
    access_token = request.args.get("access") or request.args.get("access_token") or request.form.get("access") or request.form.get("access_token")

    if not bio:
        return jsonify({"status": "❌ Missing bio", "error": "bio parameter required"}), 400

    final_jwt = None
    jwt_info = None
    login_method = "Unknown"

    # 1. Direct JWT
    if jwt_token:
        login_method = "Direct JWT"
        final_jwt = jwt_token
        jwt_info = decode_jwt_full(final_jwt)
        print(f"[Direct JWT] Using provided JWT")

    # 2. UID + Password (Using API)
    elif uid and password:
        login_method = "UID/Pass via API"
        print(f"[UID/Pass] Attempting login for UID: {uid}")
        final_jwt, account_uid, name, region = get_jwt_from_uid_password_api(uid, password)

        if final_jwt:
            jwt_info = {
                "uid": account_uid,
                "name": name,
                "region": region
            }
            print(f"[UID/Pass] Successfully obtained JWT")
        else:
            print(f"[UID/Pass] Failed to get JWT")
            return jsonify({
                "status": "❌ Authentication Failed",
                "error": "Invalid UID/Password or API error",
                "login_method": login_method
            }), 401

    # 3. Access Token -> JWT (NEW API Method)
    elif access_token:
        login_method = "Access Token -> JWT (API)"
        print(f"[Access Token] Attempting conversion via API")
        final_jwt, account_uid, region = get_jwt_from_access_token(access_token)

        if final_jwt:
            jwt_info = decode_jwt_full(final_jwt)
            if not jwt_info:
                jwt_info = {"uid": account_uid, "region": region}
            print(f"[Access Token] Successfully obtained JWT")
        else:
            print(f"[Access Token] Failed to convert")
            return jsonify({
                "status": "❌ Access Token Conversion Failed",
                "error": "Could not convert access token to JWT",
                "login_method": login_method
            }), 401

    else:
        return jsonify({
            "status": "❌ Missing Credentials",
            "error": "Provide JWT, UID/Pass, or Access Token",
            "example": {
                "with_uid_pass": "/bio?bio=Hello&uid=123456789&pass=yourpassword",
                "with_jwt": "/bio?bio=Hello&jwt=your_jwt_token",
                "with_access": "/bio?bio=Hello&access=your_access_token"
            }
        }), 400

    if not final_jwt:
        return jsonify({"status": "❌ JWT Generation Failed", "error": "Could not generate valid JWT"}), 500

    # Upload bio
    jwt_region = jwt_info.get("region") if jwt_info else DEFAULT_REGION
    mapped_region = map_region(jwt_region)
    _, update_url = get_region_urls(mapped_region)
    result = upload_bio_request(final_jwt, bio, update_url)

    response_data = {
        "success": result["status"] == "✅ Success",
        "login_method": login_method,
        "status": result["status"],
        "http_code": result["code"],
        "bio": bio,
        "uid": jwt_info.get("uid") if jwt_info else None,
        "name": jwt_info.get("name") if jwt_info else None,
        "region_detected": jwt_region,
        "region_used": mapped_region,
        "generated_jwt": final_jwt[:50] + "..." if final_jwt and len(final_jwt) > 50 else final_jwt,
        "server_response": result["server_response"][:200] if result["server_response"] else "Empty"
    }

    return jsonify(response_data)

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "name": "FreeFire Bio Upload API",
        "version": "2.0",
        "endpoints": {
            "bio": "/bio?bio=text&uid=UID&pass=PASSWORD",
            "methods": ["GET", "POST"],
            "parameters": {
                "bio": "Bio text to upload (required)",
                "uid": "FreeFire UID (with password)",
                "pass": "FreeFire password (with uid)",
                "jwt": "Direct JWT token",
                "access": "Access token"
            }
        },
        "examples": {
            "uid_pass": "/bio?bio=Hello World&uid=4569404695&pass=yourpassword",
            "jwt": "/bio?bio=Hello World&jwt=eyJhbGciOiJIUzI1NiIs...",
            "access": "/bio?bio=Hello World&access=e41b36c8596cc8e706f7e5fb39d46da..."
        }
    })

if __name__ == "__main__":
    print("=" * 50)
    print("FreeFire Bio Upload API Started (v2.0)")
    print("=" * 50)
    print("Available endpoints:")
    print("  GET  / - API Info")
    print("  POST /bio - Upload bio")
    print("  GET  /bio?bio=text&uid=xxx&pass=xxx - Upload bio")
    print("  GET  /bio?bio=text&access=xxx - Upload bio")
    print("  GET  /bio?bio=text&jwt=xxx - Upload bio")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)