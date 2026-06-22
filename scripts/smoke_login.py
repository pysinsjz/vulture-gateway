#!/usr/bin/env python3
"""
登录全链路冒烟（服务器内 127.0.0.1 闭环，无需隧道/浏览器）。

模拟桌面端 + 系统浏览器，走真实 Casdoor OIDC（auth.md A1）：
  PKCE → GET /oauth/authorize → 302 Casdoor authorize
       → Casdoor 登录(admin) 一步换 code
       → GET /oauth/callback/casdoor → 302 回环带 GW_CODE
       → POST /oauth/token（GW_CODE+verifier+device）→ access/refresh JWT
       → GET /api/v1/whoami(Bearer) == 200，且无 token == 401

凭据/基址全部经环境变量注入，无硬编码机密。任一步失败 → 退出码 1。
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

GW = os.environ.get("GW_BASE", "http://127.0.0.1:8080")
CASDOOR = os.environ.get("CASDOOR_BASE", "http://127.0.0.1:8000")
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
    """返回 (status, headers_dict, text)，3xx/4xx 不抛异常。"""
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


def die(msg):
    print(f"\n❌ FAIL: {msg}")
    sys.exit(1)


def ok(msg):
    print(f"   ✓ {msg}")


def step(n, msg):
    print(f"\n=== [{n}] {msg} ===")


# ---- PKCE + state ----
verifier = b64url(secrets.token_bytes(40))
challenge = b64url(hashlib.sha256(verifier.encode()).digest())
state = b64url(secrets.token_bytes(16))
print(f"网关={GW}  Casdoor={CASDOOR}")
print(f"PKCE verifier={verifier[:12]}…  challenge={challenge[:12]}…  state={state[:12]}…")

# ---- [1] 桌面端发起 authorize，网关 302 到 Casdoor ----
step(1, "GET /oauth/authorize → 期望 302 跳 Casdoor")
authorize_q = urllib.parse.urlencode({
    "response_type": "code",
    "client_id": DESKTOP_CLIENT_ID,
    "redirect_uri": LOOPBACK_REDIRECT,
    "code_challenge": challenge,
    "code_challenge_method": "S256",
    "state": state,
    "scope": "openid profile",
})
code_, hdr, body = req("GET", f"{GW}/oauth/authorize?{authorize_q}")
if code_ != 302:
    die(f"/oauth/authorize 期望 302，实际 {code_}；body={body[:400]}")
casdoor_authorize = hdr.get("Location") or hdr.get("location")
if not casdoor_authorize:
    die("authorize 响应缺 Location")
ok(f"302 Location → {casdoor_authorize[:90]}…")
cq = urllib.parse.parse_qs(urllib.parse.urlsplit(casdoor_authorize).query)
upstream = {k: v[0] for k, v in cq.items()}
for need in ("client_id", "redirect_uri", "state", "nonce", "response_type"):
    if need not in upstream:
        die(f"Casdoor authorize 缺参数 {need}：{upstream}")
ok(f"上游参数齐：client_id={upstream['client_id']} nonce={upstream['nonce'][:10]}…")

# ---- [2] Casdoor 登录(admin) 一步换授权码 ----
step(2, "POST Casdoor /api/login（admin）一步换 code")
login_q = urllib.parse.urlencode({
    "clientId": upstream["client_id"],
    "responseType": upstream["response_type"],
    "redirectUri": upstream["redirect_uri"],
    "scope": upstream.get("scope", "openid profile"),
    "state": upstream["state"],
    "nonce": upstream["nonce"],
})
login_body = {
    "application": ADMIN_APP,
    "organization": ADMIN_ORG,
    "username": ADMIN_USER,
    "password": ADMIN_PASS,
    "autoSignin": True,
    "type": "code",
}
code_, hdr, body = req("POST", f"{CASDOOR}/api/login?{login_q}", body=login_body)
if code_ != 200:
    die(f"Casdoor /api/login HTTP {code_}；body={body[:500]}")
try:
    j = json.loads(body)
except Exception:
    die(f"Casdoor 登录响应非 JSON：{body[:500]}")
if j.get("status") != "ok":
    die(f"Casdoor 登录失败：{body[:500]}")
casdoor_code = j.get("data") or ""
# 某些版本 data 直接给完整 redirectUri?code=...，做个兜底解析
if casdoor_code.startswith("http"):
    casdoor_code = urllib.parse.parse_qs(
        urllib.parse.urlsplit(casdoor_code).query).get("code", [""])[0]
if not casdoor_code:
    die(f"Casdoor 未返回授权码：{body[:500]}")
ok(f"Casdoor 登录成功，授权码={casdoor_code[:14]}…")

# ---- [3] 回调网关：换 token + 验签 + 建 User → 302 回环带 GW_CODE ----
step(3, "GET /oauth/callback/casdoor → 期望 302 回环带 GW_CODE")
cb_q = urllib.parse.urlencode({"code": casdoor_code, "state": upstream["state"]})
code_, hdr, body = req("GET", f"{GW}/oauth/callback/casdoor?{cb_q}")
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
ok(f"回环 {loc.split('?')[0]} 带 GW_CODE={gw_code[:14]}… state 校验通过")

# ---- [4] 桌面端用 GW_CODE+verifier 换 access/refresh ----
step(4, "POST /oauth/token（authorization_code）→ 期望 200 + JWT")
tok_body = {
    "grant_type": "authorization_code",
    "code": gw_code,
    "code_verifier": verifier,
    "client_id": DESKTOP_CLIENT_ID,
    "redirect_uri": LOOPBACK_REDIRECT,
    "device": {"name": "smoke-test", "os": "linux", "app_version": "0.0.0-smoke"},
}
code_, hdr, body = req("POST", f"{GW}/oauth/token", body=tok_body)
if code_ != 200:
    die(f"/oauth/token 期望 200，实际 {code_}；body={body[:600]}")
tok = json.loads(body)
access = tok.get("access_token")
refresh = tok.get("refresh_token")
device_id = tok.get("device_id")
if not (access and refresh and device_id):
    die(f"token 响应字段缺失：{body[:600]}")
ok(f"access_token={access[:18]}…  refresh={refresh[:10]}…  device_id={device_id}")

# ---- [5] Bearer 放行 + 无 token 拒绝 ----
step(5, "GET /api/v1/whoami：带 token==200，无 token==401")
code_, hdr, body = req("GET", f"{GW}/api/v1/whoami",
                       headers={"Authorization": f"Bearer {access}"})
if code_ != 200:
    die(f"whoami(Bearer) 期望 200，实际 {code_}；body={body[:400]}")
ok(f"whoami 放行 200：{body[:200]}")
code_, hdr, body = req("GET", f"{GW}/api/v1/whoami")
if code_ != 401:
    die(f"whoami(无 token) 期望 401，实际 {code_}；body={body[:200]}")
ok("无 token 正确 401")

print("\n✅ PASS — 登录全链路（真实 Casdoor OIDC）端到端通过")
sys.exit(0)
