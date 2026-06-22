#!/usr/bin/env python3
"""
登录授权完整流程演示（服务器内 127.0.0.1 闭环）——自建身份认证（ADR-0013）。

逐步打印请求/响应与解码后的 JWT，走网关自建登录（邮箱验证码，登录即注册）：
  PKCE → GET /oauth/authorize → 302 跳网关登录页 /oauth/login?lk=…
       → GET /oauth/login 取 CSRF token
       → POST /oauth/send-code（email_code）→ stub 发码器把验证码写入 Redis
       → 从 Redis 读取验证码（otp:code:<email>）
       → POST /oauth/login（lk+csrf+identifier+验证码）→ 302 回环带 GW_CODE
       → POST /oauth/token（GW_CODE+verifier+device）→ access/refresh JWT
       → GET /api/v1/whoami(Bearer)==200，无 token==401

说明：自建后无「公开一步换码」的上游端点，验证码经 stub 发码器落 Redis（dev 默认），
故本演示需在「能访问网关 Redis 的环境」（通常即服务器内）运行。

基址/Redis 连接经环境变量注入：
  VG_GATEWAY   网关地址，默认 http://127.0.0.1:8080
  REDIS_HOST   Redis 主机，默认 127.0.0.1
  REDIS_PORT   Redis 端口，默认 6379
  REDIS_DB     Redis 库（网关 OTP 所在），默认 1
  REDIS_PASS   Redis 密码，默认空
  SMOKE_EMAIL  登录邮箱，默认随机（每次新建号，走登录即注册）
任一步失败 → 退出码 1。
"""
import os
import re
import sys
import json
import socket
import base64
import hashlib
import secrets
import urllib.parse
import urllib.request
import urllib.error

GW = os.environ.get("VG_GATEWAY", "http://127.0.0.1:8080")
DESKTOP_CLIENT_ID = os.environ.get("DESKTOP_CLIENT_ID", "vulture-desktop")
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_DB = int(os.environ.get("REDIS_DB", "1"))
REDIS_PASS = os.environ.get("REDIS_PASS", "")
SMOKE_EMAIL = os.environ.get("SMOKE_EMAIL", f"demo-{secrets.token_hex(4)}@vulture.local")
LOOPBACK_REDIRECT = "http://127.0.0.1:9999/callback"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 不自动跟随，便于从 302 Location 解析


opener = urllib.request.build_opener(_NoRedirect)


def req(method, url, headers=None, body=None, form=None):
    h = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        resp = opener.open(r, timeout=20)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def redis_get(key):
    """最小 RESP 客户端：AUTH（可选）→ SELECT db → GET key。"""
    with socket.create_connection((REDIS_HOST, REDIS_PORT), timeout=5) as s:
        f = s.makefile("rwb")

        def send(*args):
            f.write(f"*{len(args)}\r\n".encode())
            for a in args:
                b = a if isinstance(a, bytes) else str(a).encode()
                f.write(f"${len(b)}\r\n".encode())
                f.write(b)
                f.write(b"\r\n")
            f.flush()

        def read():
            line = f.readline()
            if not line:
                raise RuntimeError("Redis 连接已关闭")
            tag, rest = line[:1], line[1:].rstrip(b"\r\n")
            if tag == b"+":
                return rest.decode()
            if tag == b"-":
                raise RuntimeError("Redis 错误: " + rest.decode())
            if tag == b":":
                return int(rest)
            if tag == b"$":
                n = int(rest)
                if n == -1:
                    return None
                buf = f.read(n)
                f.read(2)
                return buf.decode()
            raise RuntimeError("未支持的 RESP 类型: " + tag.decode())

        if REDIS_PASS:
            send("AUTH", REDIS_PASS)
            read()
        send("SELECT", REDIS_DB)
        read()
        send("GET", key)
        return read()


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
print("  vulture-gateway 登录授权完整流程演示（自建身份认证 · 服务器内闭环）")
print("═" * 72)
print(f"  网关        : {GW}")
print(f"  Redis       : {REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}")
print(f"  登录邮箱    : {SMOKE_EMAIL}（验证码登录即注册）")

verifier = b64url(secrets.token_bytes(40))
challenge = b64url(hashlib.sha256(verifier.encode()).digest())
state = b64url(secrets.token_bytes(16))
print(f"  PKCE verifier  = {verifier}")
print(f"  PKCE challenge = {challenge}  (S256)")
print(f"  state          = {state}")

# ---- [1] /oauth/authorize → 302 跳网关登录页 ----
line()
print("[1] 桌面端发起授权  GET /oauth/authorize")
authorize_q = urllib.parse.urlencode({
    "response_type": "code",
    "client_id": DESKTOP_CLIENT_ID,
    "redirect_uri": LOOPBACK_REDIRECT,
    "code_challenge": challenge,
    "code_challenge_method": "S256",
    "state": state,
})
url1 = f"{GW}/oauth/authorize?{authorize_q}"
print(f"    → {url1}")
code_, hdr, body = req("GET", url1)
if code_ != 302:
    die(f"/oauth/authorize 期望 302，实际 {code_}；body={body[:400]}")
login_loc = hdr.get("Location") or hdr.get("location") or ""
parts = urllib.parse.urlsplit(login_loc)
if parts.path != "/oauth/login":
    die(f"authorize 应跳网关登录页 /oauth/login，实际 {login_loc}")
lk = urllib.parse.parse_qs(parts.query).get("lk", [""])[0]
if not lk:
    die(f"登录页跳转缺 lk：{login_loc}")
print(f"    ← 302 网关暂存 {{state, challenge, redirect_uri}}，跳自建登录页：")
print(f"      {login_loc}")
print(f"      linkedState(lk)={lk}")

# ---- [2] 取登录页拿 CSRF token ----
line()
print("[2] 渲染登录页  GET /oauth/login?lk=…  取 CSRF token")
code_, hdr, body = req("GET", f"{GW}/oauth/login?lk={urllib.parse.quote(lk)}")
if code_ != 200:
    die(f"/oauth/login 期望 200，实际 {code_}；body={body[:300]}")
m = re.search(r'name="csrf"\s+value="([^"]+)"', body)
if not m:
    die("登录页未找到 CSRF token")
csrf = m.group(1)
methods = re.findall(r'name="method"\s+value="([^"]+)"', body)
print(f"    ← 200  登录方式={methods}  CSRF token={csrf}")

# ---- [3] 请求验证码（stub 发码器写入 Redis）----
line()
print("[3] 请求邮箱验证码  POST /oauth/send-code")
print(f"    → body: {{lk, method:email_code, identifier:{SMOKE_EMAIL}}}")
code_, hdr, body = req("POST", f"{GW}/oauth/send-code",
                       form={"lk": lk, "method": "email_code", "identifier": SMOKE_EMAIL})
if code_ != 200:
    die(f"/oauth/send-code 期望 200，实际 {code_}；body={body[:300]}")
print(f"    ← 200  {body.strip()}  （stub 发码器已把验证码写入 Redis）")

# ---- [4] 从 Redis 读取验证码 ----
line()
print(f"[4] 读取验证码  Redis GET otp:code:{SMOKE_EMAIL}")
try:
    otp = redis_get(f"otp:code:{SMOKE_EMAIL}")
except Exception as e:  # noqa: BLE001
    die(f"读取 Redis 验证码失败：{e}（检查 REDIS_HOST/PORT/DB/PASS）")
if not otp or not re.fullmatch(r"\d{6}", otp):
    die(f"Redis 未取到 6 位验证码，实得 {otp!r}")
print(f"    ← 验证码 = {otp}")

# ---- [5] 提交登录 → 302 回环带 GW_CODE ----
line()
print("[5] 提交登录  POST /oauth/login")
print("    网关：校验 CSRF → 验证码校验 → 登录即注册建 User+Identity → 签 GW_CODE")
code_, hdr, body = req("POST", f"{GW}/oauth/login", form={
    "lk": lk, "csrf": csrf, "method": "email_code",
    "identifier": SMOKE_EMAIL, "credential": otp,
})
if code_ != 302:
    die(f"/oauth/login 期望 302，实际 {code_}；body={body[:500]}")
loc = hdr.get("Location") or hdr.get("location") or ""
lq = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
if "error" in lq:
    die(f"登录回跳错误：{loc}")
gw_code = lq.get("code", [""])[0]
ret_state = lq.get("state", [""])[0]
if not gw_code:
    die(f"登录未带 GW_CODE：{loc}")
if ret_state != state:
    die(f"回环 state 不一致：期望 {state} 实得 {ret_state}")
print(f"    ← 302 回环 {loc.split('?')[0]}")
print(f"      GW_CODE={gw_code}  state 原样回传校验通过 ✓")

# ---- [6] 换取 access/refresh ----
line()
print("[6] 桌面端用 GW_CODE+verifier 换令牌  POST /oauth/token")
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
print("    ← 200")
print(f"      access_token  = {access}")
print(f"      refresh_token = {refresh}")
print(f"      device_id     = {device_id}  expires_in={tok.get('expires_in')}")
hh, claims = jwt_decode(access)
if claims:
    print(f"      JWT header    = {json.dumps(hh, ensure_ascii=False)}")
    print(f"      JWT claims    = {json.dumps(claims, ensure_ascii=False)}")

# ---- [7] Bearer 放行 / 无 token 拒绝 ----
line()
print("[7] 受保护端点验证  GET /api/v1/whoami")
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
print("✅ PASS — 登录授权完整流程（网关自建身份认证）端到端走通")
print("═" * 72)
sys.exit(0)
