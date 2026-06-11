# 桌面端浏览器中转 PKCE 授权 + 一等 Device

原生桌面应用没有浏览器 cookie 上下文，也不应内嵌各登录渠道。桌面端的认证方式：拉起系统浏览器打开（由 Casdoor 支撑的）托管登录页，随后通过 deeplink / 本地回环端口收回授权码，并以 **PKCE** 换取 JWT access + refresh token。每次授权创建一个**一等、可单独吊销的 Device**，refresh token 绑定其上，使 User 可查看并逐个吊销已授权安装。渠道扩展只改 Web 登录页，绝不动桌面端。

## 备选方案

- **App 内嵌登录** —— 否决：迫使每个渠道做原生集成（尤其微信 / Google OAuth）。
- **Device Authorization Grant（输码流程）** —— 可作备选，但桌面端体验更差。
