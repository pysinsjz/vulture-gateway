#!/usr/bin/env python3
"""
交互式登录（你亲自在浏览器登录，脚本感知成功并取回身份）。

还原真实桌面端体验（auth.md A1，自建身份认证 ADR-0013）：脚本生成 PKCE、
起本地回环监听、自动拉起你的系统浏览器到网关 /oauth/authorize；网关 302
到自建登录页 /oauth/login，你在网关登录页（密码/邮箱验证码/手机验证码）手动
完成登录后，浏览器自动跳回本机回环，脚本捕获授权码、换取网关 JWT、
调用 /api/v1/whoami，并在「终端」与「浏览器页面」双重展示登录身份。

说明：脚本只发起 authorize 并等回环回调，不关心你在哪种页面登录，故对
自建登录页天然兼容；与 Casdoor 委托时期相比逻辑无需改动。

用法：
    python3 scripts/login_interactive.py
环境变量：
    VG_GATEWAY   网关地址，默认 http://8.136.147.138:8080
"""
import os
import sys
import json
import base64
import hashlib
import secrets
import socket
import threading
import webbrowser
import urllib.parse
import urllib.request
import urllib.error
import http.server

GW = os.environ.get("VG_GATEWAY", "http://8.136.147.138:8080")
CLIENT = "vulture-desktop"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# PKCE + state（桌面端本地生成，verifier 永不出本机）
verifier = b64(secrets.token_bytes(40))
challenge = b64(hashlib.sha256(verifier.encode()).digest())
state = b64(secrets.token_bytes(16))

# 取一个空闲回环端口（RFC 8252：host∈{127.0.0.1,[::1]}+path=/callback，端口任意）
_s = socket.socket()
_s.bind(("127.0.0.1", 0))
PORT = _s.getsockname()[1]
_s.close()
REDIRECT = f"http://127.0.0.1:{PORT}/callback"

authorize = f"{GW}/oauth/authorize?" + urllib.parse.urlencode({
    "response_type": "code", "client_id": CLIENT, "redirect_uri": REDIRECT,
    "code_challenge": challenge, "code_challenge_method": "S256",
    "state": state, "scope": "openid profile",
})

result, event = {}, threading.Event()


def _post(url, body, headers=None):
    h = dict(headers or {})
    h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=json.dumps(body).encode(), headers=h, method="POST")
    try:
        resp = urllib.request.urlopen(r, timeout=20)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def exchange(code: str) -> dict:
    """GW_CODE + verifier 换令牌 → whoami → 解码 JWT，返回身份。"""
    st, body = _post(f"{GW}/oauth/token", {
        "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
        "client_id": CLIENT, "redirect_uri": REDIRECT,
        "device": {"name": socket.gethostname(), "os": sys.platform, "app_version": "cli-1.0"},
    })
    if st != 200:
        raise RuntimeError(f"/oauth/token 失败 {st}: {body[:300]}")
    tok = json.loads(body)
    req = urllib.request.Request(f"{GW}/api/v1/whoami",
                                 headers={"Authorization": "Bearer " + tok["access_token"]})
    who = json.loads(urllib.request.urlopen(req, timeout=20).read().decode())
    seg = tok["access_token"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    return {"tok": tok, "who": who, "claims": claims}


_OK = """<!doctype html><meta charset="utf-8"><title>登录成功</title>
<body style="font-family:-apple-system,Segoe UI,sans-serif;background:#0d1117;color:#e6edf3;display:flex;justify-content:center;padding-top:8vh;margin:0">
<div style="max-width:520px;width:90%;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:32px">
<div style="font-size:44px">✅</div>
<h1 style="margin:.2em 0 0">登录成功</h1>
<p style="color:#8b949e">身份已通过 vulture-gateway 验证，可关闭本页返回终端。</p>
<table style="width:100%;border-collapse:collapse;margin-top:18px;font-size:14px">
<tr><td style="color:#8b949e;padding:7px 0;width:90px">用户 ID</td><td><code style="color:#7ee787">{{SUB}}</code></td></tr>
<tr><td style="color:#8b949e;padding:7px 0">设备 ID</td><td><code style="color:#79c0ff">{{DEVICE}}</code></td></tr>
<tr><td style="color:#8b949e;padding:7px 0">签发方</td><td><code>{{ISS}}</code></td></tr>
<tr><td style="color:#8b949e;padding:7px 0">令牌过期</td><td><code>{{EXP}}</code>（Unix 秒）</td></tr>
</table></div></body>"""

_ERR = """<!doctype html><meta charset="utf-8"><title>登录失败</title>
<body style="font-family:sans-serif;background:#0d1117;color:#e6edf3;text-align:center;padding-top:10vh;margin:0">
<div style="font-size:44px">❌</div><h1>登录失败</h1><p style="color:#f85149">{{MSG}}</p></body>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if not self.path.startswith("/callback"):
            self.send_response(404)
            self.end_headers()
            return
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        try:
            if q.get("error", [""])[0]:
                raise RuntimeError(f"上游返回错误：{q['error'][0]} {q.get('error_description', [''])[0]}")
            if q.get("state", [""])[0] != state:
                raise RuntimeError("state 不匹配（可能存在 CSRF）")
            code = q.get("code", [""])[0]
            if not code:
                raise RuntimeError("回调缺少授权码")
            ident = exchange(code)
            result["ident"] = ident
            who, c = ident["who"], ident["claims"]
            page = (_OK.replace("{{SUB}}", str(who.get("sub")))
                       .replace("{{DEVICE}}", str(who.get("device_id")))
                       .replace("{{ISS}}", str(c.get("iss")))
                       .replace("{{EXP}}", str(c.get("exp"))))
        except Exception as e:  # noqa: BLE001
            result["error"] = str(e)
            page = _ERR.replace("{{MSG}}", str(e))
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode())
        event.set()


srv = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

print("═" * 64)
print("  vulture-gateway 交互式登录")
print("═" * 64)
print(f"  网关        : {GW}")
print(f"  本地回环监听: 127.0.0.1:{PORT}")
print("  正在打开系统浏览器，请在网关登录页完成登录…")
print(f"  若未自动打开，手动访问：\n    {authorize}")
print("─" * 64)

webbrowser.open(authorize)

if not event.wait(300):
    print("❌ 超时（5 分钟）未完成登录，已退出。")
    sys.exit(1)

if result.get("error"):
    print(f"\n❌ 登录失败：{result['error']}")
    sys.exit(1)

ident = result["ident"]
tok, who, claims = ident["tok"], ident["who"], ident["claims"]
print("\n✅ 登录成功 —— 身份结果")
print("─" * 64)
print(f"  用户 ID (sub)   : {who.get('sub')}")
print(f"  设备 ID         : {who.get('device_id')}")
print(f"  access_token    : {tok['access_token']}")
print(f"  refresh_token   : {tok['refresh_token']}")
print(f"  expires_in      : {tok.get('expires_in')} 秒")
print(f"  JWT claims      : {json.dumps(claims, ensure_ascii=False)}")
print(f"  whoami 响应     : {json.dumps(who, ensure_ascii=False)}")
print("═" * 64)
sys.exit(0)
