#!/usr/bin/env python3
"""
ClawHub 转发全链路冒烟（服务器内 127.0.0.1 闭环，无需浏览器）——验证网关 → 内网 ClawHub 转发。

先走自建身份认证（ADR-0013）登录拿 access JWT（同 smoke_login.py），再打 skill/plugin 族
（ADR-0006，#20）转发端点，验证 "登录用户 → 网关鉴权 → 内网 ClawHub" 这条真实链路是否打通：
  登录（邮箱验证码，登录即注册）→ access_token
       → GET /api/v1/skills    (Bearer) == 200，且响应含 items 数组（ClawHub 列表透传）
       → GET /api/v1/plugins   (Bearer) == 200，且响应含 items 数组
       → GET /api/v1/skills    (无 token) == 401

ClawHub 纯内网无鉴权，鉴权全部由网关 JWTAuth 承担。本脚本只持 access JWT，验证的是
网关能否以正确的 base_url（Convex HTTP Actions 站点口 3211 + /api/v1 前缀）连通 ClawHub。

任一步失败 → 退出码 1。

环境变量（同 smoke_login.py）：
  GW_BASE      网关地址，默认 http://127.0.0.1:8080
  REDIS_HOST/PORT/DB/PASS   Redis 连接（网关 OTP 所在），默认 127.0.0.1:6379 db=1 空密码
  SMOKE_EMAIL  冒烟登录邮箱，默认随机（每次新建号，走登录即注册）
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
        resp = opener.open(r, timeout=20)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


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
    """复用 smoke_login 的自建身份认证流程（邮箱验证码，登录即注册），返回 access JWT。"""
    verifier = b64url(secrets.token_bytes(40))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    state = b64url(secrets.token_bytes(16))

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
    login_loc = hdr.get("Location") or hdr.get("location") or ""
    lk = urllib.parse.parse_qs(urllib.parse.urlsplit(login_loc).query).get("lk", [""])[0]
    if not lk:
        die(f"登录页跳转缺 lk：{login_loc}")

    code_, hdr, body = req("GET", f"{GW}/oauth/login?lk={urllib.parse.quote(lk)}")
    if code_ != 200:
        die(f"/oauth/login 期望 200，实际 {code_}；body={body[:300]}")
    m = re.search(r'name="csrf"\s+value="([^"]+)"', body)
    if not m:
        die("登录页未找到 CSRF token")
    csrf = m.group(1)

    code_, hdr, body = req("POST", f"{GW}/oauth/send-code",
                           form={"lk": lk, "method": "email_code", "identifier": SMOKE_EMAIL})
    if code_ != 200:
        die(f"/oauth/send-code 期望 200，实际 {code_}；body={body[:300]}")

    try:
        otp = redis_get(f"otp:code:{SMOKE_EMAIL}")
    except Exception as e:  # noqa: BLE001
        die(f"读取 Redis 验证码失败：{e}（检查 REDIS_HOST/PORT/DB/PASS）")
    if not otp or not re.fullmatch(r"\d{6}", otp):
        die(f"Redis 未取到 6 位验证码，实得 {otp!r}")

    code_, hdr, body = req("POST", f"{GW}/oauth/login", form={
        "lk": lk, "csrf": csrf, "method": "email_code",
        "identifier": SMOKE_EMAIL, "credential": otp,
    })
    if code_ != 302:
        die(f"/oauth/login 期望 302，实际 {code_}；body={body[:500]}")
    lq = urllib.parse.parse_qs(urllib.parse.urlsplit(hdr.get("Location") or hdr.get("location") or "").query)
    gw_code = lq.get("code", [""])[0]
    if not gw_code:
        die(f"登录未带 GW_CODE：{lq}")

    code_, hdr, body = req("POST", f"{GW}/oauth/token", body={
        "grant_type": "authorization_code",
        "code": gw_code,
        "code_verifier": verifier,
        "client_id": DESKTOP_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT,
        "device": {"name": "smoke-clawhub", "os": "linux", "app_version": "0.0.0-smoke"},
    })
    if code_ != 200:
        die(f"/oauth/token 期望 200，实际 {code_}；body={body[:600]}")
    access = json.loads(body).get("access_token")
    if not access:
        die(f"token 响应缺 access_token：{body[:600]}")
    return access


def get_json(name, path, access, want=200):
    """GET（Bearer）→ 校验状态码并解析 JSON。"""
    code_, hdr, body = req("GET", f"{GW}{path}", headers={"Authorization": f"Bearer {access}"})
    if code_ != want:
        die(f"{name} {path} 期望 {want}，实际 {code_}；body={body[:300]}")
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError:
        die(f"{name} 响应非 JSON：{body[:300]}")


def download_bytes(name, path, access):
    """GET 下载（Bearer）→ 网关反代 ClawHub 流式端点，返回 (status, headers, nbytes)。"""
    req_ = urllib.request.Request(f"{GW}{path}", headers={"Authorization": f"Bearer {access}"}, method="GET")
    try:
        resp = opener.open(req_, timeout=30)
        raw = resp.read()
        return resp.status, dict(resp.headers), len(raw)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), len(e.read())


print(f"网关={GW}  Redis={REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}  邮箱={SMOKE_EMAIL}")

step(1, "自建身份认证登录（邮箱验证码，登录即注册）→ access JWT")
access = login()
ok(f"access_token={access[:18]}…")

# ── Skill 族 ──
step(2, "GET /api/v1/skills（Bearer）→ 200 + items，取首个 skill")
skills = get_json("skills", "/api/v1/skills", access)
items = skills.get("items") or []
if not items:
    die("skills 列表为空，无法验证下游端点（请先发布至少 1 个 skill）")
slug = items[0]["slug"]
sver = (items[0].get("latestVersion") or {}).get("version") or ""
ok(f"items={len(items)}，取 slug={slug} version={sver or 'latest'}")

step(3, f"GET /api/v1/skills/{slug}（detail）/ versions / versions/{{v}} → 各 200")
get_json("skill detail", f"/api/v1/skills/{slug}", access)
vpage = get_json("skill versions", f"/api/v1/skills/{slug}/versions", access)
if sver:
    vd = get_json("skill version", f"/api/v1/skills/{slug}/versions/{sver}", access)
    sha = (vd.get("version") or {}).get("artifact", {}).get("sha256", "")
    ok(f"版本详情 artifact.sha256={sha[:16]}…")
else:
    ok(f"versions={len(vpage.get('items') or [])} 条")

step(4, f"GET /api/v1/skills/{slug}/resolve?hash=（嵌套指纹解析，批次 B）→ 200")
h = "a" * 64
rr = get_json("resolve", f"/api/v1/skills/{slug}/resolve?hash={h}", access)
ok(f"resolve 命中：match={rr.get('match')} latestVersion={rr.get('latestVersion')}")

step(5, f"GET /api/v1/skills/{slug}/download（网关反代 ClawHub /download 流式端点）→ 200 + 字节")
code_, hdr, n = download_bytes("skill download", f"/api/v1/skills/{slug}/download", access)
if code_ != 200 or n <= 0:
    die(f"skill download 期望 200+字节，实际 {code_} / {n} bytes")
ok(f"反代回传 {n} bytes，Content-Type={hdr.get('Content-Type')}，sha256头={hdr.get('X-Clawhub-Artifact-Sha256','(无)')}")

# ── Plugin 族 ──
step(6, "GET /api/v1/plugins（Bearer）→ 200 + items，取首个 plugin")
plugins = get_json("plugins", "/api/v1/plugins", access)
pitems = plugins.get("items") or []
if not pitems:
    die("plugins 列表为空，无法验证下游端点（请先发布至少 1 个 plugin）")
pname = pitems[0]["name"]
pver = pitems[0].get("latestVersion") or ""
ok(f"items={len(pitems)}，取 name={pname} version={pver}")

step(7, f"plugin detail / releases/{{v}}（批次 A 段名别名）/ releases/{{v}}/security → 各 200")
ename = urllib.parse.quote(pname, safe="")
get_json("plugin detail", f"/api/v1/plugins/{ename}", access)
if pver:
    get_json("plugin version", f"/api/v1/plugins/{ename}/versions/{pver}", access)
    get_json("plugin security", f"/api/v1/plugins/{ename}/versions/{pver}/security", access)
    ok("releases 段名别名（version detail + security）转发 200")

step(8, f"GET /api/v1/plugins/{pname}/download（网关反代 ClawHub /packages/{{name}}/download）→ 200 + 字节")
code_, hdr, n = download_bytes("plugin download", f"/api/v1/plugins/{ename}/download", access)
if code_ != 200 or n <= 0:
    die(f"plugin download 期望 200+字节，实际 {code_} / {n} bytes")
ok(f"反代回传 {n} bytes，Content-Type={hdr.get('Content-Type')}")

# ── 遥测 ──
step(9, "POST /api/v1/telemetry/install（批次 B v1 端点）→ 2xx")
report = {"roots": [{"rootId": "smoke-root", "label": "smoke", "skills": [{"slug": slug, "version": sver or "1.0.0"}], "plugins": []}]}
code_, hdr, body = req("POST", f"{GW}/api/v1/telemetry/install",
                       headers={"Authorization": f"Bearer {access}"}, body=report)
if code_ < 200 or code_ >= 300:
    die(f"telemetry install 期望 2xx，实际 {code_}；body={body[:200]}")
ok(f"遥测对账 {code_}：{body[:80]}")

# ── 鉴权边界 ──
step(10, "GET /api/v1/skills（无 token）→ 401")
code_, hdr, body = req("GET", f"{GW}/api/v1/skills")
if code_ != 401:
    die(f"skills(无 token) 期望 401，实际 {code_}；body={body[:200]}")
ok("无 token 正确 401")

print("\n✅ PASS — ClawHub 全链路（网关鉴权 → 列表/详情/版本/resolve/下载反代/遥测）端到端通过")
sys.exit(0)
