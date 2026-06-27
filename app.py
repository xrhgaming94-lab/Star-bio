#LONG BIO API FIXED BY STAR 
#ALL FEATURES FIXED DONE AND NAME DCODER
#ALL REGION SUPPORTED @STAR_RDP TG ID @STAR_METHDOE CHANNEL
from flask import Flask, request, jsonify, make_response
import requests
import binascii
import jwt
import json
import urllib3
import base64
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

try:
    import my_pb2
    import output_pb2
except ImportError:
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

DEFAULT_REGION = "IND"

REGION_MAP = {
    "IND": {"update_url": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "ME": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "BD": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "PK": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "TW": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "TH": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "VN": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "ID": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "RU": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "EU": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "SG": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "BR": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "SAC": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "NA": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
}
#ALL REGION ADDED BY STAR
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
FREEFIRE_VERSION = "OB54"

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# ============== NICKNAME DECODER ==============
# Replaced incorrect key with the fixed secret key for accurate UTF-8 decoding
FF_XOR_KEY = b"1e5898ccb8dfdd921f9bdea848768b64a201"

def decode_ff_nickname(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ FF_XOR_KEY[i % len(FF_XOR_KEY)])
        return dec.decode('utf-8', errors='replace')
    except Exception as e:
        print(f"[NICK DECODE ERROR] {e}")
        return f"[DECODE_ERROR: {e}]"

def decode_jwt_with_nickname(token: str):
    try:
        if not token:
            print("[JWT DECODE] Token is empty")
            return None, None, None
            
        parts = token.split('.')
        if len(parts) != 3:
            print(f"[JWT DECODE] Invalid format: {len(parts)} parts")
            return None, None, None
        
        payload_b64 = parts[1]
        payload_b64 += '=' * ((4 - len(payload_b64) % 4) % 4)
        
        try:
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
            print(f"[JWT DECODE] Successfully decoded payload")
        except Exception as e:
            print(f"[JWT DECODE] Failed to decode base64: {e}")
            return None, None, None
        
        uid = payload.get("account_id")
        region = payload.get("lock_region")
        
        raw_nickname = payload.get("nickname", "")
        if raw_nickname:
            name = decode_ff_nickname(raw_nickname)
            print(f"[JWT DECODE] Nickname decoded: {name}")
        else:
            name = None
            print("[JWT DECODE] No nickname found in payload")
        
        print(f"[JWT DECODE] UID: {uid}, Region: {region}")
        return str(uid) if uid else None, name, region
        
    except Exception as e:
        print(f"[JWT DECODE] Critical error: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None

BIO_HEADERS = {
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

LOGIN_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION
}

_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\ndata.proto\"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage\"\x0e\n\x0c\x45mptyMessageb\x06proto3'
)
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'data1_pb2', _globals)
BioData = _sym_db.GetSymbol('Data')
EmptyMessage = _sym_db.GetSymbol('EmptyMessage')

def encrypt_data(data_bytes):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

# ============== APP.PY VALIDATION LOGIC ==============
def validate_and_get_openid_from_token(access_token):
    """App.py style - Direct token inspect"""
    try:
        inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }
        resp = requests.get(inspect_url, headers=headers, verify=False, timeout=10)
        
        print(f"[TOKEN INSPECT] Status: {resp.status_code}")
        print(f"[TOKEN INSPECT] Response: {resp.text}")
        
        if resp.status_code == 200:
            data = resp.json()
            open_id = data.get('open_id')
            if open_id:
                print(f"[TOKEN INSPECT] Success! OpenID: {open_id}")
                return open_id, True
            else:
                print("[TOKEN INSPECT] No open_id in response")
                return None, False
        else:
            print(f"[TOKEN INSPECT] Failed with status {resp.status_code}")
            return None, False
            
    except Exception as e:
        print(f"[TOKEN INSPECT] Error: {e}")
        return None, False

# ============== REWARD API ==============
def get_name_region_from_reward(access_token):
    try:
        uid_url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
        uid_headers ={
            "authority": "prod-api.reward.ff.garena.com",
            "method": "GET",
            "path": "/redemption/api/auth/inspect_token/",
            "scheme": "https",
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "access-token": access_token,
            "cookie": "_gid=GA1.2.444482899.1724033242; _ga_XB5PSHEQB4=GS1.1.1724040177.1.1.1724040732.0.0.0; token_session=cb73a97aaef2f1c7fd138757dc28a08f92904b1062e66c; _ga_KE3SY7MRSD=GS1.1.1724041788.0.0.1724041788.0; _ga_RF9R6YT614=GS1.1.1724041788.0.0.1724041788.0; _ga=GA1.1.1843180339.1724033241; apple_state_key=817771465df611ef8ab00ac8aa985783; _ga_G8QGMJPWWV=GS1.1.1724049483.1.1.1724049880.0.0; datadome=HBTqAUPVsbBJaOLirZCUkN3rXjf4gRnrZcNlw2WXTg7bn083SPey8X~ffVwr7qhtg8154634Ee9qq4bCkizBuiMZ3Qtqyf3Isxmsz6GTH_b6LMCKWF4Uea_HSPk;",
            "origin": "https://reward.ff.garena.com",
            "referer": "https://reward.ff.garena.com/",
            "sec-ch-ua": '"Not.A/Brand";v="99", "Chromium";v="124"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        uid_res = requests.get(uid_url, headers=uid_headers, verify=False)
        uid_data = uid_res.json()
        print(f"[REWARD] Response: {uid_data}")
        return uid_data.get("uid"), uid_data.get("name"), uid_data.get("region")
    except Exception as e:
        print(f"[REWARD] Error: {e}")
        return None, None, None

# ============== SHOP2GAME ==============
def get_openid_from_shop2game(uid):
    if not uid: return None
    try:
        openid_url = "https://topup.pk/api/auth/player_id_login"
        openid_headers = { 
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-MM,en-US;q=0.9,en;q=0.8",
            "Content-Type": "application/json",
            "Origin": "https://topup.pk",
            "Referer": "https://topup.pk/",
            "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Android WebView";v="138"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; RMX5070 Build/UKQ1.231108.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.157 Mobile Safari/537.36",
            "X-Requested-With": "mark.via.gp",
            "Cookie": "source=mb; region=PK; mspid2=13c49fb51ece78886ebf7108a4907756; _fbp=fb.1.1753985808817.794945392376454660; language=en; datadome=WQaG3HalUB3PsGoSXY3TdcrSQextsSFwkOp1cqZtJ7Ax4YkiERHUgkgHlEAIccQO~w8dzTGM70D9SzaH7vymmEqOrVeX5pIsPVE22Uf3TDu6W3WG7j36ulnTg2DltRO7; session_key=hq02g63z3zjcumm76mafcooitj7nc79y",
        }
        payload = {"app_id": 100067, "login_id": str(uid)}
        res = requests.post(openid_url, headers=openid_headers, json=payload, verify=False)
        data = res.json()
        print(f"[SHOP2GAME] OpenID response: {data}")
        return data.get("open_id")
    except Exception as e:
        print(f"[SHOP2GAME] Error: {e}")
        return None

# ============== MAJOR LOGIN ==============
def perform_major_login(access_token, open_id, major_login_url):
    platforms = [2, 3, 4, 6, 8]  # App.py platform types
    for platform_type in platforms:
        try:
            game_data = my_pb2.GameData()
            game_data.timestamp = "2024-12-05 18:15:32"
            game_data.game_name = "free fire"
            game_data.game_version = 1
            game_data.version_code = "1.126.2"
            game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
            game_data.device_type = "Handheld"
            game_data.network_provider = "Verizon Wireless"
            game_data.connection_type = "WIFI"
            game_data.screen_width = 1280
            game_data.screen_height = 960
            game_data.dpi = "240"
            game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
            game_data.total_ram = 5951
            game_data.gpu_name = "Adreno (TM) 640"
            game_data.gpu_version = "OpenGL ES 3.0"
            game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
            game_data.ip_address = "172.190.111.97"
            game_data.language = "en"
            game_data.open_id = open_id
            game_data.access_token = access_token
            game_data.platform_type = platform_type
            game_data.field_99 = str(platform_type)
            game_data.field_100 = str(platform_type)

            serialized_data = game_data.SerializeToString()
            encrypted = encrypt_data(serialized_data)
            hex_encrypted = binascii.hexlify(encrypted).decode('utf-8')
            
            edata = bytes.fromhex(hex_encrypted)
            response = requests.post(major_login_url, data=edata, headers=LOGIN_HEADERS, verify=False, timeout=10)

            if response.status_code == 200:
                data_dict = None
                try:
                    example_msg = output_pb2.Garena_420()
                    example_msg.ParseFromString(response.content)
                    data_dict = {field.name: getattr(example_msg, field.name) 
                                 for field in example_msg.DESCRIPTOR.fields 
                                 if field.name == "token"}
                except Exception:
                    pass
                if data_dict and "token" in data_dict:
                    jwt_token = data_dict["token"]
                    print(f"[MAJOR LOGIN] Platform {platform_type} SUCCESS!")
                    return jwt_token
                else:
                    print(f"[MAJOR LOGIN] Platform {platform_type} - No token in response")
            else:
                print(f"[MAJOR LOGIN] Platform {platform_type} - Status: {response.status_code}")
        except Exception as e:
            print(f"[MAJOR LOGIN] Platform {platform_type} error: {e}")
            continue
    return None

# ============== GUEST LOGIN ==============
def perform_guest_login(uid, password):
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive"
    }
    try:
        resp = requests.post(OAUTH_URL, data=payload, headers=headers, timeout=10, verify=False)
        data = resp.json()
        print(f"[GUEST LOGIN] Response: {data}")
        if 'access_token' in data:
            return data['access_token'], data.get('open_id')
    except Exception as e:
        print(f"[GUEST LOGIN] Error: {e}")
    return None, None

# ============== REGION UTILITIES ==============
def _add_region_param(url: str, region: str) -> str:
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q["region"] = region
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, urlencode(q), parts.fragment))

def get_region_urls(region: str):
    region = (region or "").upper().strip() or DEFAULT_REGION
    if region not in REGION_MAP:
        raise ValueError(f"Unsupported region: {region}")
    update_url = _add_region_param(REGION_MAP[region]["update_url"], region)
    major_url  = _add_region_param(REGION_MAP[region]["major_login_url"], region)
    return region, update_url, major_url

# ============== BIO UPLOAD ==============
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

        resp = requests.post(update_url, headers=headers, data=encrypted, timeout=20, verify=False)

        status_text = "Unknown"
        if resp.status_code == 200: status_text = "✅ Success"
        elif resp.status_code == 401: status_text = "❌ Unauthorized (Invalid JWT)"
        else: status_text = f"⚠️ Status {resp.status_code}"

        raw_hex = binascii.hexlify(resp.content).decode('utf-8')

        return {
            "status": status_text,
            "code": resp.status_code,
            "bio": bio_text,
            "server_response": raw_hex
        }
    except Exception as e:
        return {"status": f"Error: {str(e)}", "code": 500, "bio": bio_text, "server_response": "N/A"}

# ============== MAIN ENDPOINT ==============
@app.route("/bio", methods=["GET", "POST"])
def combined_bio_upload():
    bio = request.args.get("bio") or request.form.get("bio")
    jwt_token = request.args.get("jwt") or request.form.get("jwt")
    uid = request.args.get("uid") or request.form.get("uid")
    password = request.args.get("pass") or request.form.get("password")
    access_token = request.args.get("access") or request.form.get("access") or request.args.get("access_token")
    region_in = request.args.get("region") or request.form.get("region")

    print(f"[REQUEST] bio={bio}, uid={uid}, has_pass={bool(password)}, has_access={bool(access_token)}")

    if not bio:
        return jsonify({"status": "❌ Error", "code": 400, "error": "Missing 'bio' parameter"}), 400

    try:
        selected_region, update_url, major_url = get_region_urls(region_in)
        print(f"[REGION] Selected: {selected_region}, Update: {update_url}")
    except ValueError as e:
        return jsonify({"status": "❌ Error", "code": 400, "error": str(e)}), 400

    final_jwt = None
    login_method = "Direct JWT"
    
    final_open_id = None
    final_access_token = None
    final_uid = None
    final_name = None
    final_region = None

    # ========== DIRECT JWT ==========
    if jwt_token:
        print("[AUTH] Using Direct JWT")
        final_jwt = jwt_token
        j_uid, j_name, j_region = decode_jwt_with_nickname(jwt_token)
        final_uid = j_uid
        final_name = j_name
        final_region = j_region
        print(f"[AUTH] Decoded: UID={final_uid}, Name={final_name}, Region={final_region}")
    
    # ========== UID/PASS LOGIN ==========
    elif uid and password:
        print("[AUTH] Using UID/Password Login")
        login_method = "UID/Pass Login"
        
        acc_token, login_openid = perform_guest_login(uid, password)
        
        if acc_token and login_openid:
            print(f"[AUTH] Guest login success, OpenID: {login_openid}")
            final_access_token = acc_token
            final_open_id = login_openid
            
            final_jwt = perform_major_login(final_access_token, final_open_id, major_url)
            
            if final_jwt:
                print("[AUTH] Major login success, decoding JWT...")
                j_uid, j_name, j_region = decode_jwt_with_nickname(final_jwt)
                final_uid = j_uid
                final_name = j_name
                final_region = j_region
                print(f"[AUTH] Decoded: UID={final_uid}, Name={final_name}, Region={final_region}")
            else:
                print("[AUTH] Major login failed")
                return jsonify({"status": "❌ JWT Generation Failed", "code": 500}), 500
        else:
            print("[AUTH] Guest login failed")
            return jsonify({"status": "❌ Guest Login Failed (Check UID/Pass)", "code": 401}), 401

    # ========== ACCESS TOKEN LOGIN (APP.PY STYLE) ==========
    elif access_token:
        print("[AUTH] Using Access Token Login (app.py style)")
        login_method = "Access Token Login"
        final_access_token = access_token
        
        # PRIMARY: Token inspect (app.py logic)
        open_id, is_valid = validate_and_get_openid_from_token(access_token)
        
        if not is_valid:
            print("[AUTH] Token inspect failed, trying reward API fallback...")
            # FALLBACK: Reward API
            f_uid, f_name, f_region = get_name_region_from_reward(access_token)
            if f_uid:
                final_uid = f_uid
                final_name = f_name
                final_region = f_region
                # Shop2Game se open_id
                open_id = get_openid_from_shop2game(f_uid)
                print(f"[AUTH] Shop2Game OpenID: {open_id}")
            else:
                return jsonify({
                    "status": "❌ Invalid Access Token", 
                    "code": 400, 
                    "error": "Token validation failed. Both inspect and reward API failed."
                }), 400
        else:
            # Inspect success - Reward API se UID/Name lete hain
            f_uid, f_name, f_region = get_name_region_from_reward(access_token)
            final_uid = f_uid
            final_name = f_name
            final_region = f_region
            print(f"[AUTH] Reward API: UID={final_uid}, Name={final_name}, Region={final_region}")
        
        if not open_id:
            return jsonify({"status": "❌ OpenID Fetch Failed", "code": 400}), 400
        
        # Major Login
        final_open_id = open_id
        final_jwt = perform_major_login(final_access_token, final_open_id, major_url)
        
        if final_jwt:
            print("[AUTH] Major login success, decoding JWT...")
            j_uid, j_name, j_region = decode_jwt_with_nickname(final_jwt)
            final_uid = j_uid
            final_name = j_name
            final_region = j_region
            print(f"[AUTH] Decoded: UID={final_uid}, Name={final_name}, Region={final_region}")
        else:
            return jsonify({"status": "❌ Major Login Failed", "code": 500}), 500
    
    else:
        return jsonify({"status": "❌ Error", "code": 400, "error": "Provide JWT, or UID/Pass, or Access Token"}), 400

    if not final_jwt:
        return jsonify({"status": "❌ JWT Generation Failed", "code": 500}), 500

    result = upload_bio_request(final_jwt, bio, update_url)
    
    response_data = {
        "status": result["status"],
        "login_method": login_method,
        "code": result["code"],
        "bio": result["bio"],
        "uid": str(final_uid) if final_uid else None,
        "name": final_name,
        "region": final_region
    }
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "name": "FreeFire Bio Upload API",
        "version": "1.0",
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
            "uid_pass": "/bio?bio=Hello World&uid=4569404695&pass=RAGHAVLIKESBOT_RAGHAV_2THCG",
            "jwt": "/bio?bio=Hello World&jwt=eyJhbGciOiJIUzI1NiIs...",
            "access": "/bio?bio=Hello World&access=660b275ac9fc3f12b65ed9008344cb74..."
        }
    })

    response = make_response(jsonify(response_data))
    response.headers["Content-Type"] = "application/json"
    return response

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
