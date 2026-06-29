package handler

// passwordPageTmpl 是网关托管的「设置密码」页（绑定模式，ADR-0015 / #39）。
// 与登录页同构：新密码只在浏览器内经 SubtleCrypto RSA-OAEP(SHA-256) 加密后提交（字段
// encrypted_password），明文绝不进网络/桌面进程。标识由 Password Link 在服务端预填、只读展示。
// 注意：JS 为静态文本（无模板动作），动态值经 DOM 元素/属性传入，避免脚本注入。
const passwordPageTmpl = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>设置密码 · Vulture</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 4rem auto; padding: 0 1rem; }
  .card { border: 1px solid #8883; border-radius: 12px; padding: 1.5rem; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  .field { display: block; margin: 0 0 1rem; font-size: 0.9rem; }
  .field input { display: block; width: 100%; box-sizing: border-box; margin-top: 0.25rem; padding: 0.5rem; border: 1px solid #8886; border-radius: 8px; }
  button.primary { width: 100%; background: #2563eb; color: #fff; border: 0; font-size: 1rem; padding: 0.5rem 0.9rem; border-radius: 8px; cursor: pointer; }
  .error { color: #dc2626; font-size: 0.9rem; }
  .msg { color: #dc2626; font-size: 0.85rem; min-height: 1.1rem; }
  .hint { color: #6b7280; font-size: 0.8rem; }
</style>
</head>
<body>
<main class="card">
  <h1>设置登录密码</h1>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <div id="msg" class="msg"></div>
  <form id="pwForm" method="post" action="/oauth/password">
    <input type="hidden" name="t" value="{{.Token}}">
    <input type="hidden" name="csrf" value="{{.CSRFToken}}">
    <input type="hidden" id="encrypted_password" name="encrypted_password">
    <label class="field">账号
      <input id="identifier" value="{{.Identifier}}" autocomplete="username" readonly>
    </label>
    <label class="field">新密码
      <input id="password" type="password" required autocomplete="new-password">
    </label>
    <label class="field">确认新密码
      <input id="confirm" type="password" required autocomplete="new-password">
    </label>
    <p class="hint">8–64 个字符，须同时包含字母与数字。</p>
    <button type="submit" class="primary">设置密码</button>
  </form>
  <pre id="pubkey" hidden>{{.PublicKeyB64}}</pre>
</main>
<script>
(function(){
  var form = document.getElementById('pwForm');
  var pubB64 = document.getElementById('pubkey').textContent.trim();
  var pw = document.getElementById('password');
  var confirm = document.getElementById('confirm');
  var enc = document.getElementById('encrypted_password');
  var msg = document.getElementById('msg');

  function b64ToBytes(b64){ var bin = atob(b64); var a = new Uint8Array(bin.length); for (var i=0;i<bin.length;i++){ a[i] = bin.charCodeAt(i); } return a; }
  function bufToB64(buf){ var a = new Uint8Array(buf); var s=''; for (var i=0;i<a.length;i++){ s += String.fromCharCode(a[i]); } return btoa(s); }
  async function encryptPassword(plain){
    var key = await crypto.subtle.importKey('spki', b64ToBytes(pubB64), {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt']);
    var ct = await crypto.subtle.encrypt({name:'RSA-OAEP'}, key, new TextEncoder().encode(plain));
    return bufToB64(ct);
  }

  form.addEventListener('submit', async function(e){
    e.preventDefault();
    msg.textContent = '';
    if (pw.value !== confirm.value){ msg.textContent = '两次输入的密码不一致'; return; }
    try { enc.value = await encryptPassword(pw.value); }
    catch (err) { msg.textContent = '加密失败，请更换浏览器或检查 HTTPS'; return; }
    HTMLFormElement.prototype.submit.call(form);
  });
})();
</script>
</body>
</html>`

// passwordResultTmpl 渲染设置密码的结果页（成功/失败终态，不含表单）。
const passwordResultTmpl = `<!doctype html>
<html lang="zh">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>设置密码 · Vulture</title>
<style>body{font-family:system-ui,sans-serif;max-width:24rem;margin:4rem auto;padding:0 1rem;text-align:center}h1{font-size:1.25rem}p{color:#6b7280}</style>
</head>
<body><main><h1>{{.Title}}</h1><p>{{.Message}}</p></main></body>
</html>`
