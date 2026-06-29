package handler

// loginPageTmpl 是网关自建登录页（最小可用，ADR-0013）。
// 密码方式在浏览器侧用 SubtleCrypto RSA-OAEP(SHA-256) 加密后提交；验证码方式明文提交。
// 注意：JS 为静态文本（无模板动作），动态值经 DOM 元素/属性传入，避免脚本注入。
const loginPageTmpl = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 · Vulture</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 4rem auto; padding: 0 1rem; }
  .card { border: 1px solid #8883; border-radius: 12px; padding: 1.5rem; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  .methods { border: 0; padding: 0; margin: 0 0 1rem; display: flex; gap: 1rem; flex-wrap: wrap; }
  .field { display: block; margin: 0 0 1rem; font-size: 0.9rem; }
  .field input { display: block; width: 100%; box-sizing: border-box; margin-top: 0.25rem; padding: 0.5rem; border: 1px solid #8886; border-radius: 8px; }
  button { padding: 0.5rem 0.9rem; border-radius: 8px; border: 1px solid #8886; cursor: pointer; }
  button.primary { width: 100%; background: #2563eb; color: #fff; border: 0; font-size: 1rem; }
  #sendCode { margin-top: 0.4rem; }
  .error { color: #dc2626; font-size: 0.9rem; }
  .msg { color: #2563eb; font-size: 0.85rem; min-height: 1.1rem; }
  .forgot { margin: 1rem 0 0; font-size: 0.85rem; text-align: center; }
  .forgot a { color: #2563eb; text-decoration: none; }
</style>
</head>
<body>
<main class="card">
  <h1>登录</h1>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <div id="msg" class="msg"></div>
  <form id="loginForm" method="post" action="/oauth/login">
    <input type="hidden" name="lk" value="{{.LinkedState}}">
    <input type="hidden" name="csrf" value="{{.CSRFToken}}">
    <fieldset class="methods">
      {{range .Methods}}
      <label><input type="radio" name="method" value="{{.Name}}" data-code="{{.IsCode}}" {{if .Selected}}checked{{end}}> {{.Label}}</label>
      {{end}}
    </fieldset>
    <label class="field">登录标识
      <input id="identifier" name="identifier" autocomplete="username" required placeholder="邮箱或手机号">
    </label>
    <label class="field"><span id="credLabel">密码</span>
      <input id="credential" name="credential" required autocomplete="off">
      <button type="button" id="sendCode">发送验证码</button>
    </label>
    <button type="submit" class="primary">登录</button>
  </form>
  <p class="forgot"><a href="/oauth/password">忘记密码?</a></p>
  <pre id="pubkey" hidden>{{.PublicKeyB64}}</pre>
</main>
<script>
(function(){
  var form = document.getElementById('loginForm');
  var pubB64 = document.getElementById('pubkey').textContent.trim();
  var radios = form.querySelectorAll('input[name=method]');
  var cred = document.getElementById('credential');
  var credLabel = document.getElementById('credLabel');
  var sendBtn = document.getElementById('sendCode');
  var idInput = document.getElementById('identifier');
  var msg = document.getElementById('msg');

  function selected(){ for (var i=0;i<radios.length;i++){ if (radios[i].checked) return radios[i]; } return null; }
  function isCode(){ var r = selected(); return !!r && r.dataset.code === 'true'; }
  function updateUI(){
    var code = isCode();
    credLabel.textContent = code ? '验证码' : '密码';
    cred.type = code ? 'text' : 'password';
    cred.value = '';
    sendBtn.style.display = code ? 'inline-block' : 'none';
    msg.textContent = '';
  }
  for (var i=0;i<radios.length;i++){ radios[i].addEventListener('change', updateUI); }
  updateUI();

  function b64ToBytes(b64){ var bin = atob(b64); var a = new Uint8Array(bin.length); for (var i=0;i<bin.length;i++){ a[i] = bin.charCodeAt(i); } return a; }
  function bufToB64(buf){ var a = new Uint8Array(buf); var s=''; for (var i=0;i<a.length;i++){ s += String.fromCharCode(a[i]); } return btoa(s); }
  async function encryptPassword(plain){
    var key = await crypto.subtle.importKey('spki', b64ToBytes(pubB64), {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt']);
    var ct = await crypto.subtle.encrypt({name:'RSA-OAEP'}, key, new TextEncoder().encode(plain));
    return bufToB64(ct);
  }

  sendBtn.addEventListener('click', async function(){
    var r = selected(); if (!r) return;
    sendBtn.disabled = true;
    try {
      var res = await fetch('/oauth/send-code', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams({lk: form.lk.value, method: r.value, identifier: idInput.value})});
      var j = {}; try { j = await res.json(); } catch (e) {}
      msg.textContent = res.ok ? '验证码已发送' : (j.error || '发送失败');
    } catch (e) { msg.textContent = '发送失败'; }
    setTimeout(function(){ sendBtn.disabled = false; }, 3000);
  });

  form.addEventListener('submit', async function(e){
    if (isCode()) return; // 验证码方式明文提交
    e.preventDefault();
    try { cred.value = await encryptPassword(cred.value); }
    catch (err) { msg.textContent = '加密失败，请更换浏览器或检查 HTTPS'; return; }
    HTMLFormElement.prototype.submit.call(form);
  });
})();
</script>
</body>
</html>`
