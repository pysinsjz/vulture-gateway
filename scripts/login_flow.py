#!/usr/bin/env python3
"""
登录授权完整流程演示（本地直连服务器公网，无需隧道）。

走真实 Casdoor OIDC（auth.md A1），逐步打印请求/响应与解码后的 JWT：
  PKCE → GET /oauth/authorize → 解析上游 OIDC 参数
       → 直连公网 Casdoor /api/login（admin）换上游 code
       → GET /oauth/callback/casdoor（网关后端换 id_token+验签+建 User）→ GW_CODE
       → POST /oauth/token（GW_CODE+verifier+device）→ access/refresh JWT
       → GET /api/v1/whoami(Bearer)==200，无 token==401

约束：Casdoor discovery 的 issuer 仍钉死 http://127.0.0.1:8000，故网关 302 出的
上游 authorize host 不可直接跟随；本脚本改用公网 Casdoor 基址 + 解析出的 OIDC
参数登录拿 code，网关侧换 token 仍在服务器内走 127.0.0.1:8000。

基址/凭据经环境变量注入：
  VG_GATEWAY          默认 http://8.136.147.138:8080
  VG_CASDOOR_PUBLIC   默认 http://8.136.147.138:8000
  CASDOOR_ADMIN_USER  默认 admin
  CASDOOR_ADMIN_PASS  默认 123456
任一步失败 → 退出码 1。
"""
import os
import sys
import json
import base64
import hashlib
import secrets
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar

GW = os.environ.get("VG_GATEWAY", "http://8.136.147.138:8080")
CASDOOR = os.environ.get("VG_CASDOOR_PUBLIC", "http://8.136.147.138:8000")
DESKTOP_CLIENT_ID = os.environ.get("DESKTOP_CLIENT_ID", "vulture-desktop")
ADMIN_USER = os.environ.get("CASDOOR_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("CASDOOR_ADMIN_PASS", "123456")
ADMIN_ORG = os.environ.get("CASDOOR_ORG", "built-in")
ADMIN_APP = os.environ.get("CASDOOR_APP", "app-built-in")
LOOPBACK_REDIRECT = "http://127.0.0.1:9999/callback"

cj = http.cookiejar.CookieJar()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 不自动跟随，便于从 302 Location 解析授权码


opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj), _NoRedirect
)


def req(method, url, headers=None, body=None):
    h = dict(headers or {})
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        else:
            data = body if isinstance(body, bytes) else str(body).encode()
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        resp = opener.open(r, timeout=20)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwt_decode(tok: str):
    parts = tok.split(".")
    if len(parts) != 3:
        return None, None
    def d(seg):
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    return d(parts[0]), d(parts[1])


def die(msg):
    print(f"\n❌ FAIL: {msg}")
    sys.exit(1)


def line():
    print("─" * 72)


# ---------------------------------------------------------------------------
print("═" * 72)
print("  vulture-gateway 登录授权完整流程演示（本地直连公网）")
print("═" * 72)
print(f"  网关        : {GW}")
print(f"  Casdoor(公网): {CASDOOR}")
print(f"  登录账号    : {ADMIN_ORG}/{ADMIN_USER}（{ADMIN_APP}）")

verifier = b64url(secrets.token_bytes(40))
challenge = b64url(hashlib.sha256(verifier.encode()).digest())
state = b64url(secrets.token_bytes(16))
print(f"  PKCE verifier  = {verifier}")
print(f"  PKCE challenge = {challenge}  (S256)")
print(f"  state          = {state}")

# ---- [1] /oauth/authorize ----
line()
print("[1] 桌面端发起授权  GET /oauth/authorize")
authorize_q = urllib.parse.urlencode({
    "response_type": "code",
    "client_id": DESKTOP_CLIENT_ID,
    "redirect_uri": LOOPBACK_REDIRECT,
    "code_challenge": challenge,
    "code_challenge_method": "S256",
    "state": state,
    "scope": "openid profile",
})
url1 = f"{GW}/oauth/authorize?{authorize_q}"
print(f"    → {url1}")
code_, hdr, body = req("GET", url1)
if code_ != 302:
    die(f"/oauth/authorize 期望 302，实际 {code_}；body={body[:400]}")
upstream_loc = hdr.get("Location") or hdr.get("location")
print(f"    ← 302 网关暂存 {{state, challenge, redirect_uri, nonce}}，跳上游：")
print(f"      {upstream_loc}")
uq = {k: v[0] for k, v in urllib.parse.parse_qs(
    urllib.parse.urlsplit(upstream_loc).query).items()}
for need in ("client_id", "redirect_uri", "state", "nonce", "response_type"):
    if need not in uq:
        die(f"上游 authorize 缺参数 {need}：{uq}")
print(f"    解析出上游 OIDC 参数：client_id={uq['client_id']}")
print(f"      redirect_uri={uq['redirect_uri']}")
print(f"      nonce={uq['nonce']}  state(linked)={uq['state'][:24]}…")

# ---- [2] Casdoor 登录换上游 code（直连公网 Casdoor）----
line()
print("[2] 系统浏览器在 Casdoor 登录  POST {CASDOOR}/api/login")
login_q = urllib.parse.urlencode({
    "clientId": uq["client_id"],
    "responseType": uq["response_type"],
    "redirectUri": uq["redirect_uri"],
    "scope": uq.get("scope", "openid profile"),
    "state": uq["state"],
    "nonce": uq["nonce"],
})
login_body = {
    "application": ADMIN_APP, "organization": ADMIN_ORG,
    "username": ADMIN_USER, "password": ADMIN_PASS,
    "autoSignin": True, "type": "code",
}
url2 = f"{CASDOOR}/api/login?{login_q}"
print(f"    → {url2}")
print(f"      body: {{username:{ADMIN_USER}, type:code, …}}")
code_, hdr, body = req("POST", url2, body=login_body)
if code_ != 200:
    die(f"Casdoor /api/login HTTP {code_}；body={body[:500]}")
j = json.loads(body)
if j.get("status") != "ok":
    die(f"Casdoor 登录失败：{body[:500]}")
casdoor_code = j.get("data") or ""
if casdoor_code.startswith("http"):
    casdoor_code = urllib.parse.parse_qs(
        urllib.parse.urlsplit(casdoor_code).query).get("code", [""])[0]
if not casdoor_code:
    die(f"Casdoor 未返回授权码：{body[:500]}")
print(f"    ← status=ok  上游授权码 code={casdoor_code}")

# ---- [3] 网关回调：换 id_token + 验签 + 建 User → GW_CODE ----
line()
print("[3] Casdoor 回调网关  GET /oauth/callback/casdoor")
cb_q = urllib.parse.urlencode({"code": casdoor_code, "state": uq["state"]})
url3 = f"{GW}/oauth/callback/casdoor?{cb_q}"
print(f"    → {url3}")
print("      网关后端：直连 Casdoor 换 id_token → JWKS 验签 → 校验 nonce → 解析/建 User → 签 GW_CODE")
code_, hdr, body = req("GET", url3)
if code_ != 302:
    die(f"callback 期望 302，实际 {code_}；body={body[:600]}")
loc = hdr.get("Location") or hdr.get("location") or ""
lq = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
if "error" in lq:
    die(f"callback 回跳错误：{loc}")
gw_code = lq.get("code", [""])[0]
ret_state = lq.get("state", [""])[0]
if not gw_code:
    die(f"callback 未带 GW_CODE：{loc}")
if ret_state != state:
    die(f"回环 state 不一致：期望 {state} 实得 {ret_state}")
print(f"    ← 302 回环 {loc.split('?')[0]}")
print(f"      GW_CODE={gw_code}  state 原样回传校验通过 ✓")

# ---- [4] 换取 access/refresh ----
line()
print("[4] 桌面端用 GW_CODE+verifier 换令牌  POST /oauth/token")
tok_body = {
    "grant_type": "authorization_code", "code": gw_code,
    "code_verifier": verifier, "client_id": DESKTOP_CLIENT_ID,
    "redirect_uri": LOOPBACK_REDIRECT,
    "device": {"name": "local-demo", "os": "macOS", "app_version": "0.0.0-demo"},
}
print(f"    → {GW}/oauth/token   (grant_type=authorization_code, 校验 PKCE)")
code_, hdr, body = req("POST", f"{GW}/oauth/token", body=tok_body)
if code_ != 200:
    die(f"/oauth/token 期望 200，实际 {code_}；body={body[:600]}")
tok = json.loads(body)
access, refresh, device_id = tok.get("access_token"), tok.get("refresh_token"), tok.get("device_id")
if not (access and refresh and device_id):
    die(f"token 响应字段缺失：{body[:600]}")
print(f"    ← 200")
print(f"      access_token  = {access}")
print(f"      refresh_token = {refresh}")
print(f"      device_id     = {device_id}  expires_in={tok.get('expires_in')}")
h, claims = jwt_decode(access)
if claims:
    print(f"      JWT header    = {json.dumps(h, ensure_ascii=False)}")
    print(f"      JWT claims    = {json.dumps(claims, ensure_ascii=False)}")

# ---- [5] Bearer 放行 / 无 token 拒绝 ----
line()
print("[5] 受保护端点验证  GET /api/v1/whoami")
code_, hdr, body = req("GET", f"{GW}/api/v1/whoami",
                       headers={"Authorization": f"Bearer {access}"})
if code_ != 200:
    die(f"whoami(Bearer) 期望 200，实际 {code_}；body={body[:400]}")
print(f"    → 带 Bearer  ← 200  {body.strip()}")
code_, hdr, body = req("GET", f"{GW}/api/v1/whoami")
if code_ != 401:
    die(f"whoami(无 token) 期望 401，实际 {code_}；body={body[:200]}")
print(f"    → 无 token   ← 401  {body.strip()[:120]}")

line()
print("✅ PASS — 登录授权完整流程（真实 Casdoor OIDC）端到端走通")
print("═" * 72)
sys.exit(0)
