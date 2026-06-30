package handler

// passwordPageTmpl 是网关托管的「设置 / 修改密码」页（ADR-0015）。secret 空→首设模式（免码）；
// secret 非空→改密模式（RequireCode，渲染发码按钮 + 验证码输入，提交携带 code）。
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
  .coderow { display: flex; gap: 0.5rem; align-items: flex-end; }
  .coderow .field { flex: 1; margin-bottom: 1rem; }
  button.primary { width: 100%; background: #2563eb; color: #fff; border: 0; font-size: 1rem; padding: 0.5rem 0.9rem; border-radius: 8px; cursor: pointer; }
  button.secondary { white-space: nowrap; background: transparent; color: #2563eb; border: 1px solid #2563eb88; font-size: 0.85rem; padding: 0.5rem 0.7rem; border-radius: 8px; cursor: pointer; margin-bottom: 1rem; }
  button.secondary[disabled] { color: #9ca3af; border-color: #9ca3af66; cursor: default; }
  .error { color: #dc2626; font-size: 0.9rem; }
  .msg { color: #dc2626; font-size: 0.85rem; min-height: 1.1rem; }
  .hint { color: #6b7280; font-size: 0.8rem; }
</style>
</head>
<body>
<main class="card">
  <h1>{{if .RequireCode}}修改登录密码{{else}}设置登录密码{{end}}</h1>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <div id="msg" class="msg"></div>
  <form id="pwForm" method="post" action="/oauth/password">
    <input type="hidden" name="t" value="{{.Token}}">
    <input type="hidden" name="csrf" value="{{.CSRFToken}}">
    <input type="hidden" id="encrypted_password" name="encrypted_password">
    <input type="hidden" id="plain_password" name="plain_password">
    <label class="field">账号
      <input id="identifier" value="{{.Identifier}}" autocomplete="username" readonly>
    </label>
    {{if .RequireCode}}
    <div class="coderow">
      <label class="field">验证码
        <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required>
      </label>
      <button type="button" id="sendCode" class="secondary">发送验证码</button>
    </div>
    {{end}}
    <label class="field">新密码
      <input id="password" type="password" required autocomplete="new-password">
    </label>
    <label class="field">确认新密码
      <input id="confirm" type="password" required autocomplete="new-password">
    </label>
    <p class="hint">8–64 个字符，须同时包含字母与数字。</p>
    <button type="submit" class="primary">{{if .RequireCode}}修改密码{{else}}设置密码{{end}}</button>
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
  var plainField = document.getElementById('plain_password');
  var msg = document.getElementById('msg');
  var tok = form.querySelector('input[name="t"]').value;

  function b64ToBytes(b64){ var bin = atob(b64); var a = new Uint8Array(bin.length); for (var i=0;i<bin.length;i++){ a[i] = bin.charCodeAt(i); } return a; }
  function bufToB64(buf){ var a = new Uint8Array(buf); var s=''; for (var i=0;i<a.length;i++){ s += String.fromCharCode(a[i]); } return btoa(s); }
  async function encryptPassword(plain){
    var key = await crypto.subtle.importKey('spki', b64ToBytes(pubB64), {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt']);
    var ct = await crypto.subtle.encrypt({name:'RSA-OAEP'}, key, new TextEncoder().encode(plain));
    return bufToB64(ct);
  }
  // WebCrypto 仅在安全上下文（https:// 或 http://localhost）暴露。非安全上下文 → 走服务端
  // 明文旁路（plain_password，AuthConfig.AllowPlaintextPassword）；旁路未开时由服务端给出可读拒绝。
  function cryptoAvailable(){
    return !!(window.isSecureContext && window.crypto && window.crypto.subtle);
  }
  if (!cryptoAvailable()){
    msg.style.color = '#b45309'; // amber：提示而非红色错误
    msg.textContent = '当前为非安全上下文（HTTPS 或 localhost），将以明文密码提交（仅 dev/test 网关支持）。' +
      '生产环境请通过 https:// 或 http://localhost 重新打开此页。';
  }

  var sendBtn = document.getElementById('sendCode');
  if (sendBtn){
    sendBtn.addEventListener('click', async function(){
      msg.textContent = '';
      sendBtn.disabled = true;
      try {
        var resp = await fetch('/oauth/password/send-code', {
          method: 'POST',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: 't=' + encodeURIComponent(tok)
        });
        if (!resp.ok){ var j = await resp.json().catch(function(){ return {}; }); msg.textContent = j.error || '发送失败，请稍后重试'; sendBtn.disabled = false; return; }
      } catch (err) { msg.textContent = '发送失败，请检查网络'; sendBtn.disabled = false; return; }
      var left = 60;
      sendBtn.textContent = left + 's 后重发';
      var timer = setInterval(function(){
        left -= 1;
        if (left <= 0){ clearInterval(timer); sendBtn.disabled = false; sendBtn.textContent = '发送验证码'; }
        else { sendBtn.textContent = left + 's 后重发'; }
      }, 1000);
    });
  }

  form.addEventListener('submit', async function(e){
    e.preventDefault();
    msg.style.color = '';
    msg.textContent = '';
    if (pw.value !== confirm.value){ msg.textContent = '两次输入的密码不一致'; return; }
    if (cryptoAvailable()){
      try { enc.value = await encryptPassword(pw.value); }
      catch (err) { msg.textContent = '加密失败：' + (err && err.message ? err.message : String(err)); return; }
    } else {
      plainField.value = pw.value;
    }
    HTMLFormElement.prototype.submit.call(form);
  });
})();
</script>
</body>
</html>`

// passwordCodePageTmpl 是登出态「忘记密码」的验证码模式页（ADR-0015 / #41）。与绑定模式页不同：
// 无 Password Link，标识由用户自填（可编辑），靠「页面一次性 CSRF（绑定 sid）+ 提交的标识」授权发码，
// 提交时带标识 + pwreset 验证码证明身份。新密码同样只在浏览器内经 RSA-OAEP(SHA-256) 加密后提交。
// 服务端按该 User 的 secret 空/非空自动判 set/reset，前端不声明。
// 注意：JS 为静态文本（无模板动作），动态值经 DOM 元素/属性传入，避免脚本注入。
const passwordCodePageTmpl = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>重置密码 · Vulture</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 4rem auto; padding: 0 1rem; }
  .card { border: 1px solid #8883; border-radius: 12px; padding: 1.5rem; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  .field { display: block; margin: 0 0 1rem; font-size: 0.9rem; }
  .field input { display: block; width: 100%; box-sizing: border-box; margin-top: 0.25rem; padding: 0.5rem; border: 1px solid #8886; border-radius: 8px; }
  .coderow { display: flex; gap: 0.5rem; align-items: flex-end; }
  .coderow .field { flex: 1; margin-bottom: 1rem; }
  button.primary { width: 100%; background: #2563eb; color: #fff; border: 0; font-size: 1rem; padding: 0.5rem 0.9rem; border-radius: 8px; cursor: pointer; }
  button.secondary { white-space: nowrap; background: transparent; color: #2563eb; border: 1px solid #2563eb88; font-size: 0.85rem; padding: 0.5rem 0.7rem; border-radius: 8px; cursor: pointer; margin-bottom: 1rem; }
  button.secondary[disabled] { color: #9ca3af; border-color: #9ca3af66; cursor: default; }
  .error { color: #dc2626; font-size: 0.9rem; }
  .msg { color: #dc2626; font-size: 0.85rem; min-height: 1.1rem; }
  .hint { color: #6b7280; font-size: 0.8rem; }
</style>
</head>
<body>
<main class="card">
  <h1>重置登录密码</h1>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <div id="msg" class="msg"></div>
  <form id="pwForm" method="post" action="/oauth/password">
    <input type="hidden" name="sid" value="{{.SID}}">
    <input type="hidden" name="csrf" value="{{.CSRFToken}}">
    <input type="hidden" id="encrypted_password" name="encrypted_password">
    <input type="hidden" id="plain_password" name="plain_password">
    <label class="field">邮箱或手机号
      <input id="identifier" name="identifier" value="{{.Identifier}}" autocomplete="username" required placeholder="邮箱或手机号">
    </label>
    <div class="coderow">
      <label class="field">验证码
        <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required>
      </label>
      <button type="button" id="sendCode" class="secondary">发送验证码</button>
    </div>
    <label class="field">新密码
      <input id="password" type="password" required autocomplete="new-password">
    </label>
    <label class="field">确认新密码
      <input id="confirm" type="password" required autocomplete="new-password">
    </label>
    <p class="hint">8–64 个字符，须同时包含字母与数字。</p>
    <button type="submit" class="primary">重置密码</button>
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
  var plainField = document.getElementById('plain_password');
  var msg = document.getElementById('msg');
  var idInput = document.getElementById('identifier');
  var sid = form.querySelector('input[name="sid"]').value;
  var csrf = form.querySelector('input[name="csrf"]').value;

  function b64ToBytes(b64){ var bin = atob(b64); var a = new Uint8Array(bin.length); for (var i=0;i<bin.length;i++){ a[i] = bin.charCodeAt(i); } return a; }
  function bufToB64(buf){ var a = new Uint8Array(buf); var s=''; for (var i=0;i<a.length;i++){ s += String.fromCharCode(a[i]); } return btoa(s); }
  async function encryptPassword(plain){
    var key = await crypto.subtle.importKey('spki', b64ToBytes(pubB64), {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt']);
    var ct = await crypto.subtle.encrypt({name:'RSA-OAEP'}, key, new TextEncoder().encode(plain));
    return bufToB64(ct);
  }
  // WebCrypto 仅在安全上下文（https:// 或 http://localhost）暴露。非安全上下文 → 走服务端
  // 明文旁路（plain_password，AuthConfig.AllowPlaintextPassword）；旁路未开时由服务端给出可读拒绝。
  function cryptoAvailable(){
    return !!(window.isSecureContext && window.crypto && window.crypto.subtle);
  }
  if (!cryptoAvailable()){
    msg.style.color = '#b45309';
    msg.textContent = '当前为非安全上下文（HTTPS 或 localhost），将以明文密码提交（仅 dev/test 网关支持）。' +
      '生产环境请通过 https:// 或 http://localhost 重新打开此页。';
  }

  var sendBtn = document.getElementById('sendCode');
  sendBtn.addEventListener('click', async function(){
    msg.textContent = '';
    if (!idInput.value){ msg.textContent = '请输入邮箱或手机号'; return; }
    sendBtn.disabled = true;
    try {
      var resp = await fetch('/oauth/password/send-code', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams({sid: sid, csrf: csrf, identifier: idInput.value})
      });
      if (!resp.ok){ var j = await resp.json().catch(function(){ return {}; }); msg.textContent = j.error || '发送失败，请稍后重试'; sendBtn.disabled = false; return; }
    } catch (err) { msg.textContent = '发送失败，请检查网络'; sendBtn.disabled = false; return; }
    var left = 60;
    sendBtn.textContent = left + 's 后重发';
    var timer = setInterval(function(){
      left -= 1;
      if (left <= 0){ clearInterval(timer); sendBtn.disabled = false; sendBtn.textContent = '发送验证码'; }
      else { sendBtn.textContent = left + 's 后重发'; }
    }, 1000);
  });

  form.addEventListener('submit', async function(e){
    e.preventDefault();
    msg.style.color = '';
    msg.textContent = '';
    if (pw.value !== confirm.value){ msg.textContent = '两次输入的密码不一致'; return; }
    if (cryptoAvailable()){
      try { enc.value = await encryptPassword(pw.value); }
      catch (err) { msg.textContent = '加密失败：' + (err && err.message ? err.message : String(err)); return; }
    } else {
      plainField.value = pw.value;
    }
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
