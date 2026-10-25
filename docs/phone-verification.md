# 新设备手机号验证

## 接口依据

实现参考 [Doubean 的 VerifyPhoneViewModel](https://github.com/Bumblebee202111/doubean-public/blob/f1b4d9e88eeb17d48ae95c7f2fce96ed3d8e926b/app/src/main/java/com/github/bumblebee202111/doubean/feature/login/VerifyPhoneViewModel.kt)、[LoginViewModel](https://github.com/Bumblebee202111/doubean-public/blob/f1b4d9e88eeb17d48ae95c7f2fce96ed3d8e926b/app/src/main/java/com/github/bumblebee202111/doubean/feature/login/LoginViewModel.kt)，以及作者发布的 [0.13.2 APK](https://github.com/Bumblebee202111/doubean-public/releases/tag/v0.13.2) 中的请求构造与响应模型。公开源码展示短信交互，APK 补充了网络层的字段和 Cookie 初始化顺序。官方 Android 7.136.0 包也包含 `account/login_verify_phone` 路由；其加固登录代码未用于推断请求字段。

1. Frodo `POST /service/auth2/token` 返回 `9000` 时，从 `extra.solution_uri` 中解析 `douban://douban.com/account/login_verify_phone?user_id=…`。只接受该固定路由和数字用户 ID。
2. 使用同一设备 ID 和登录请求的 Cookie，通过 `https://www.douban.com/accounts/auth2_redir?url=…` 初始化 `https://accounts.douban.com/passport/verify_phone?user_id=…&dark_mode=0` 会话。页面仅作为 HTTP 会话初始化；程序不会执行页面脚本。
3. `POST https://accounts.douban.com/j/app/verify_phone/request_phone_code`，表单包含 `user_id`、`apikey`。
4. `POST https://accounts.douban.com/j/app/verify_phone/verify_phone_code`，表单包含 `user_id`、`client_id`、`phone_code`。
5. `status=success` 时，校验接口的 `payload` 包含 `access_token`、`refresh_token`、`douban_user_id`、`expires_in`。验证账号一致后，使用现有 0600 文件和原子写入机制保存。

账号保护接口使用 App WebView 风格的 User-Agent（携带持久化设备 ID）、`X-Requested-With: com.douban.frodo`、对应 Referer 和 Cookie。这些请求沿用显式代理、TLS 校验、超时与限速配置。

## 验证范围

2026-10-25 使用空参数探测两个账号保护端点，分别得到 `account_not_exist` 与 `failed_detect_apikey`，确认端点存在；探测未指定真实账号，也未发送真实短信。正常登录、`9000`、Cookie 延续、验证码错误与重试、超时、恶意跳转、会话过期、CLI 提示、MCP 两步调用及 token 文件权限均由 HTTP mock 测试覆盖。

真实账号短信发送、接收和 token 签发仍需用户运行 `douban-mcp login` 验收。遇到图形验证码时，服务返回固定的 `captcha_required` 提示。原始账号响应、Cookie、密码、验证码与 token 均不进入工具结果或日志；项目未添加 telemetry 或新的运行依赖。
