#!/usr/bin/env python3
"""
LLM 代理全链路冒烟（服务器内 127.0.0.1 闭环，无需浏览器）——验证 litellm 转发 + virtual key 注入。

先走自建身份认证（ADR-0013）登录拿 access JWT（同 smoke_login.py），再打 LLM 代理族（ADR-0005，#23/#24/#26）：
  登录（邮箱验证码，登录即注册）→ access_token
       → GET  /v1/models           (Bearer) == 200，发现可用模型
       → POST /v1/chat/completions  (Bearer，非流式) == 200，取回答内容
       → POST /v1/chat/completions  (Bearer，stream=true) == 200，收 SSE chunk 直到 [DONE]
       → GET  /v1/models            (无 token) == 401（OpenAI 错误体）

网关用自己持有的 litellm virtual key 转发，桌面端拿不到 key。本脚本只持 access JWT，验证的是
"登录用户 → 网关 → litellm" 这条真实链路是否打通（含 virtual key 鉴权是否被 litellm 接受）。

任一步失败 → 退出码 1。

环境变量：
  GW_BASE      网关地址，默认 http://127.0.0.1:8080
  REDIS_HOST   Redis 主机，默认 127.0.0.1
  REDIS_PORT   Redis 端口，默认 6379
  REDIS_DB     Redis 库（网关 OTP 所在），默认 1
  REDIS_PASS   Redis 密码，默认空
  SMOKE_EMAIL  冒烟登录邮箱，默认随机（每次新建号，走登录即注册）
  SMOKE_MODEL  指定对话模型；默认取 /v1/models 第一个
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

GW = os.environ.get("GW_BASE", "http://127.0.0.1:8080")
DESKTOP_CLIENT_ID = os.environ.get("DESKTOP_CLIENT_ID", "vulture-desktop")
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_DB = int(os.environ.get("REDIS_DB", "1"))
REDIS_PASS = os.environ.get("REDIS_PASS", "")
SMOKE_EMAIL = os.environ.get("SMOKE_EMAIL", f"smoke-{secrets.token_hex(4)}@vulture.local")
SMOKE_MODEL = os.environ.get("SMOKE_MODEL", "")
LOOPBACK_REDIRECT = "http://127.0.0.1:9999/callback"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 不自动跟随，便于从 302 Location 解析


opener = urllib.request.build_opener(_NoRedirect)


def req(method, url, headers=None, body=None, form=None):
    """返回 (status, headers_dict, text)。body=JSON；form=application/x-www-form-urlencoded。"""
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
        resp = opener.open(r, timeout=60)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def req_stream(method, url, headers=None, body=None):
    """流式请求：返回 (status, headers_dict, response对象)。调用方负责逐行读取与关闭。"""
    h = dict(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        resp = opener.open(r, timeout=60)
        return resp.status, dict(resp.headers), resp
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e


def redis_get(key):
    """最小 RESP 客户端：AUTH（可选）→ SELECT db → GET key，返回字符串或 None。"""
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
                f.read(2)  # 末尾 CRLF
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


def die(msg):
    print(f"\n❌ FAIL: {msg}")
    sys.exit(1)


def ok(msg):
    print(f"   ✓ {msg}")


def step(n, msg):
    print(f"\n=== [{n}] {msg} ===")


def login() -> str:
    """走自建身份认证全链路（邮箱验证码，登录即注册），返回 access JWT。失败即退出。"""
    verifier = b64url(secrets.token_bytes(40))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    state = b64url(secrets.token_bytes(16))

    step(1, "登录：GET /oauth/authorize → 取 lk")
    authorize_q = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": DESKTOP_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    })
    code_, hdr, body = req("GET", f"{GW}/oauth/authorize?{authorize_q}")
    if code_ != 302:
        die(f"/oauth/authorize 期望 302，实际 {code_}；body={body[:400]}")
    login_parts = urllib.parse.urlsplit(hdr.get("Location") or hdr.get("location") or "")
    lk = urllib.parse.parse_qs(login_parts.query).get("lk", [""])[0]
    if not lk:
        die(f"登录页跳转缺 lk：{login_parts.geturl()}")
    ok(f"lk={lk[:12]}…")

    step(2, "登录：GET /oauth/login → 取 CSRF")
    code_, hdr, body = req("GET", f"{GW}/oauth/login?lk={urllib.parse.quote(lk)}")
    if code_ != 200:
        die(f"/oauth/login 期望 200，实际 {code_}；body={body[:300]}")
    m = re.search(r'name="csrf"\s+value="([^"]+)"', body)
    if not m:
        die("登录页未找到 CSRF token")
    csrf = m.group(1)
    ok(f"CSRF={csrf[:12]}…")

    step(3, "登录：POST /oauth/send-code（email_code）")
    code_, hdr, body = req("POST", f"{GW}/oauth/send-code",
                           form={"lk": lk, "method": "email_code", "identifier": SMOKE_EMAIL})
    if code_ != 200:
        die(f"/oauth/send-code 期望 200，实际 {code_}；body={body[:300]}")
    ok("发码受理")

    step(4, f"登录：Redis GET otp:code:{SMOKE_EMAIL}")
    try:
        otp = redis_get(f"otp:code:{SMOKE_EMAIL}")
    except Exception as e:  # noqa: BLE001
        die(f"读取 Redis 验证码失败：{e}（检查 REDIS_HOST/PORT/DB/PASS）")
    if not otp or not re.fullmatch(r"\d{6}", otp):
        die(f"Redis 未取到 6 位验证码，实得 {otp!r}")
    ok(f"验证码={otp}")

    step(5, "登录：POST /oauth/login → 302 回环带 GW_CODE")
    code_, hdr, body = req("POST", f"{GW}/oauth/login", form={
        "lk": lk, "csrf": csrf, "method": "email_code",
        "identifier": SMOKE_EMAIL, "credential": otp,
    })
    if code_ != 302:
        die(f"/oauth/login 期望 302，实际 {code_}；body={body[:500]}")
    lq = urllib.parse.parse_qs(urllib.parse.urlsplit(hdr.get("Location") or hdr.get("location") or "").query)
    if "error" in lq:
        die(f"登录回跳错误：{lq}")
    gw_code = lq.get("code", [""])[0]
    if not gw_code or lq.get("state", [""])[0] != state:
        die(f"登录回环 code/state 异常：{lq}")
    ok(f"GW_CODE={gw_code[:14]}…")

    step(6, "登录：POST /oauth/token → access JWT")
    code_, hdr, body = req("POST", f"{GW}/oauth/token", body={
        "grant_type": "authorization_code",
        "code": gw_code,
        "code_verifier": verifier,
        "client_id": DESKTOP_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT,
        "device": {"name": "smoke-llm", "os": "linux", "app_version": "0.0.0-smoke"},
    })
    if code_ != 200:
        die(f"/oauth/token 期望 200，实际 {code_}；body={body[:600]}")
    access = json.loads(body).get("access_token")
    if not access:
        die(f"token 响应缺 access_token：{body[:600]}")
    ok(f"access_token={access[:18]}…")
    return access


print(f"网关={GW}  Redis={REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}  邮箱={SMOKE_EMAIL}")

access = login()
auth = {"Authorization": f"Bearer {access}"}

# ---- [7] GET /v1/models 发现可用模型 ----
step(7, "GET /v1/models（Bearer）→ 期望 200 + 模型列表")
code_, hdr, body = req("GET", f"{GW}/v1/models", headers=auth)
if code_ != 200:
    die(f"/v1/models 期望 200，实际 {code_}；body={body[:500]}")
try:
    models = [m.get("id") for m in json.loads(body).get("data", []) if m.get("id")]
except Exception as e:  # noqa: BLE001
    die(f"/v1/models 响应非预期 JSON：{e}；body={body[:300]}")
if not models:
    die(f"/v1/models 未返回任何模型（litellm 是否配置了 model_list？）；body={body[:300]}")
model = SMOKE_MODEL or models[0]
if SMOKE_MODEL and SMOKE_MODEL not in models:
    print(f"   ⚠ SMOKE_MODEL={SMOKE_MODEL} 不在 /v1/models 列表内，仍按指定值尝试")
ok(f"可用模型 {len(models)} 个：{', '.join(models[:5])}{' …' if len(models) > 5 else ''}")
ok(f"本次对话用模型：{model}")

# ---- [8] POST /v1/chat/completions 非流式 ----
step(8, "POST /v1/chat/completions（非流式）→ 期望 200 + 回答内容")
code_, hdr, body = req("POST", f"{GW}/v1/chat/completions", headers=auth, body={
    "model": model,
    "messages": [{"role": "user", "content": "只回复两个字：你好"}],
    "max_tokens": 32,
    "stream": False,
})
if code_ != 200:
    die(f"/v1/chat/completions 非流式期望 200，实际 {code_}；body={body[:600]}")
try:
    content = json.loads(body)["choices"][0]["message"]["content"]
except Exception as e:  # noqa: BLE001
    die(f"非流式响应缺 choices[0].message.content：{e}；body={body[:400]}")
if hdr.get("X-Litellm-Call-Id") or hdr.get("x-litellm-call-id"):
    ok(f"x-litellm-call-id 透传：{hdr.get('X-Litellm-Call-Id') or hdr.get('x-litellm-call-id')}")
if hdr.get("X-Litellm-Response-Cost") or hdr.get("x-litellm-response-cost"):
    die("成本敏感头 x-litellm-response-cost 未被网关剥除（脱敏失效）")
ok(f"回答内容：{content.strip()[:80]!r}")

# ---- [9] POST /v1/chat/completions 流式 SSE ----
step(9, "POST /v1/chat/completions（stream=true）→ 期望 200 + SSE chunk 直到 [DONE]")
code_, hdr, resp = req_stream("POST", f"{GW}/v1/chat/completions", headers=auth, body={
    "model": model,
    "messages": [{"role": "user", "content": "数到三：1 2 3"}],
    "max_tokens": 32,
    "stream": True,
})
if code_ != 200:
    payload = resp.read().decode("utf-8", "replace") if hasattr(resp, "read") else ""
    die(f"/v1/chat/completions 流式期望 200，实际 {code_}；body={payload[:600]}")
ctype = (hdr.get("Content-Type") or hdr.get("content-type") or "")
if "text/event-stream" not in ctype:
    die(f"流式响应 Content-Type 期望 text/event-stream，实际 {ctype!r}")
chunks, saw_done = 0, False
try:
    for raw in resp:
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if payload == "[DONE]":
            saw_done = True
            break
        chunks += 1
finally:
    resp.close()
if chunks == 0:
    die("流式未收到任何 data chunk")
if not saw_done:
    die("流式未收到 [DONE] 终止标记")
ok(f"收到 {chunks} 个 data chunk，并以 [DONE] 正常终止")

# ---- [10] 无 token 拒绝（OpenAI 错误体）----
step(10, "GET /v1/models（无 token）→ 期望 401")
code_, hdr, body = req("GET", f"{GW}/v1/models")
if code_ != 401:
    die(f"/v1/models(无 token) 期望 401，实际 {code_}；body={body[:300]}")
ok(f"无 token 正确 401：{body[:120]}")

print("\n✅ PASS — LLM 代理全链路（登录 → 网关注入 virtual key → litellm 转发，流式/非流式/鉴权）端到端通过")
sys.exit(0)
