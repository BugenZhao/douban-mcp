# douban-mcp

基于豆瓣 App Frodo API 的本地 stdio MCP server，支持匿名查询、账号登录与书影音标记。直接通过 HTTPS 请求 `frodo.douban.com`，使用 apiKey + HMAC-SHA1 签名；账号保护验证使用豆瓣账号服务的 HTTP 接口。运行时网络仅用于用户触发的豆瓣请求，项目与运行依赖均无 telemetry/analytics SDK。

## 安装与运行

需要 macOS/Linux、Python 3.11+ 和 uv。

```sh
git clone https://github.com/BugenZhao/douban-mcp.git
cd douban-mcp
uv sync --locked
.venv/bin/douban-mcp
```

默认命令 `serve` 使用 stdio；stdout 专用于 MCP JSON-RPC。部署时直接运行虚拟环境里的可执行文件，依赖安装由 `uv sync` 单独完成。

Grok Bot / MCPHub stdio backend 配置见 [examples/mcp.json](examples/mcp.json)：

```json
{
  "mcpServers": {
    "douban": {
      "command": "/absolute/path/to/douban-mcp/.venv/bin/douban-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

将示例中的绝对路径替换为实际安装路径，并添加到宿主的 MCP 配置。

## 登录

推荐在本机终端输入密码；`getpass` 隐藏输入，登录只输出脱敏状态：

```sh
.venv/bin/douban-mcp login
.venv/bin/douban-mcp status
.venv/bin/douban-mcp refresh
.venv/bin/douban-mcp logout
```

已有豆瓣 App access token 可通过 `.venv/bin/douban-mcp import-token` 隐藏输入，服务会先调用 `/api/v2/~me` 验证，再替换本地凭据。MCP 同时提供 login/import/refresh/logout 工具；工具参数可能进入宿主的聊天或调用历史，建议常规登录使用本机 CLI。

登录请求使用 `/service/auth2/token` 的 password grant；token 保存在本地专用目录 `~/.local/state/douban-mcp/credentials.json`，目录权限 0700、文件权限 0600。密码仅参与当次请求。token 更新使用原子替换及进程锁；已知有效期临近到期时，下一次请求会尝试 refresh grant。设备 ID 持久化在同目录 `device.json`。`logout` 删除本服务的本地 token。

每个状态目录对应一个账号；共享该目录的宿主共享登录状态。多账号部署使用各自独立的 `DOUBAN_STATE_DIR`。

源码中的 apiKey 与 HMAC secret 是 Frodo App 的共享客户端常量。个人 access token、refresh token 和设备 ID 保存在本机状态目录；`.gitignore` 排除这些状态文件。`.gitleaks.toml` 仅对指定源文件中的两项固定 App 常量设置精确白名单，其余默认密钥检测规则保持启用。

遇到账号保护错误 `9000` 时，CLI 自动向绑定手机号发送一次短信，并提示隐藏输入验证码；验证成功后保存 App token。验证码错误时可重新输入，最多尝试 5 次。超时或发送失败会明确报错，重新运行 `login` 可开启新的验证会话。

MCP 的 `douban_login` 支持两步调用：

1. 传入 `username`、`password`。需要短信时返回 `verification_required: true`、`sms_sent: true`、`challenge_id` 和 `expires_at`。
2. 在同一个 MCP 服务进程中，仅传入上一步的 `challenge_id` 和 `sms_code`。成功后返回脱敏登录状态。

验证上下文和 Cookie 仅保存在内存，有效期 10 分钟；重启、退出登录或发起新的登录会使原会话失效。短信发送和校验请求均只发送一次，普通验证码错误可由用户再次提交。密码、验证码和验证 Cookie 都不会写入状态文件。图形验证码返回 `captcha_required`，用户需在官方 App 完成验证后重试。`invalid_device_id` 等其他错误保持明确报错。

短信流程依据和测试范围见 [docs/phone-verification.md](docs/phone-verification.md)。完整短信登录与实际账号写入需要用户在本机使用有效凭据完成端到端验收。

## 工具

| 工具 | 功能 |
|---|---|
| `douban_search` | movie（含电视剧）、book 分类搜索；all 为登录后的综合搜索 |
| `douban_search_suggestions` | 搜索建议 |
| `douban_subject` / `douban_rating` | movie/tv/book/music 详情、评分分布 |
| `douban_comments` / `douban_reviews` | 条目短评、长评列表 |
| `douban_collection` | movie_top250、movie_real_time_hotest、book_top250 等榜单 |
| `douban_user` / `douban_user_interests` / `douban_user_reviews` | 用户公开资料、标记、长评 |
| `douban_me` / `douban_my_interest` | 在线验证当前账号、查询自己的标记 |
| `douban_auth_status` / `douban_login` / `douban_import_token` | 本地状态、密码登录、导入 token |
| `douban_refresh_token` / `douban_logout` | 刷新、清除本地登录 |
| `douban_set_interest` / `douban_delete_interest` | 标记、评分、短评、标签及删除 |

分页参数 `start >= 0`、`1 <= count <= 100`。工具保留 Frodo JSON 结构及分页信息。ID 使用搜索结果里的 `type` 和 `id`；电视剧详情使用 `tv`。

写操作示例：

```json
{
  "subject_type": "movie",
  "subject_id": "3541415",
  "status": "done",
  "rating": 5,
  "comment": "梦境的层次与剪辑很精彩。"
}
```

以上是 `douban_set_interest` 参数示例；执行会写入当前账号。`mark` 表示想看/读/听，`doing` 表示在看/读/听，`done` 表示看/读/听过。评分使用 1–5 星，0 清除评分；省略 rating/comment/tags 会保留已有值，`comment=""` 清空短评，`tags=[]` 清空标签。`share=true` 显式同步广播，默认 false。

写工具带 MCP mutation/destructive annotations。服务提示宿主在用户明确要求对应操作时调用。写请求只发送一次；网络异常或服务端异常可能返回 `outcome_unknown=true`，此时先调用 `douban_my_interest` 核对状态。读后合并更新可保护本服务内的省略字段；跨客户端同时编辑仍可能发生覆盖。

写入后服务再次读取条目，返回 `submitted` 与 `verified`。`verified=false` 表示提交后的状态仍需核对；它可能来自读取失败、状态延迟或服务端忽略了某个字段。

## 配置

| 环境变量 | 默认值 | 用途 |
|---|---|---|
| `DOUBAN_PROXY` | 直接连接 | 显式 HTTP(S) 代理，例如 `http://127.0.0.1:8791` |
| `DOUBAN_STATE_DIR` | `$XDG_STATE_HOME/douban-mcp` 或 `~/.local/state/douban-mcp` | 专用本地状态目录，会设为 0700 |
| `DOUBAN_API_KEY` / `DOUBAN_API_SECRET` | Frodo App 共享常量 | App 密钥轮换时覆盖 |
| `DOUBAN_USER_AGENT` | Frodo Android UA | 客户端版本适配 |
| `DOUBAN_DEVICE_ID` | 自动生成并持久化 | 导入已有设备 ID（20 或 40 位小写十六进制） |
| `DOUBAN_TIMEOUT` | 20 秒 | HTTP 超时 |
| `DOUBAN_REQUEST_INTERVAL` | 1.2 秒 | 单进程请求间隔 |

HTTP 客户端使用显式代理配置。服务默认直连；代理地址按本机网络配置设置。TLS 校验证书，Frodo API 重定向保持关闭；手机号验证初始化只跟随固定豆瓣域名和路径的 HTTPS 跳转，最多 5 次。HTTP 日志关闭；token、密码和完整带签名 URL 均从错误输出中剔除。无后台轮询、远程错误上报或遥测开关。

## 验证

```sh
uv run pytest
uv run ruff check .
uv run python scripts/smoke.py
# 若当前网络需要本地代理：
DOUBAN_PROXY=http://127.0.0.1:8791 uv run python scripts/smoke.py
```

单元测试使用模拟 HTTP，覆盖签名、token 生命周期、凭据权限、写请求参数与错误处理；stdio 集成测试覆盖 MCP 初始化、工具发现与调用。smoke 仅调用匿名查询，使用临时状态目录；用户接口默认查询公开示例账号 `1000001`，可通过 `DOUBAN_SMOKE_USER` 指定其他公开用户 ID。实际登录和账号写入的测试由用户提供凭据和具体写入指令后进行。

2026-10-25 本机验收：36 项自动化测试通过，19 个工具完成 stdio 发现，16/16 项匿名实测通过（直接连接），Ruff 检查及 wheel/sdist 构建通过。电视剧样本使用分类搜索返回的 `tv/35588177`。账号密码登录、refresh grant、真实标记/评分/短评/标签写入仍待账号实测。

## API 依据与边界

- 匿名签名和读接口通过实时请求验证；客户端实现见 [src/douban_mcp/client.py](src/douban_mcp/client.py)。
- 带 token 签名、登录与写入路由参考 [Doubean 源码及发布产物](https://github.com/Bumblebee202111/doubean-public/releases/tag/v0.13.2)，以及 [douban-mini 登录实现](https://github.com/gooliu/douban-mini/blob/main/backend/douban_client.py)。项目实现独立编写。
- 匿名签名输入为 `METHOD&urlencoded_path&timestamp`；登录态为 `METHOD&urlencoded_path&token&timestamp`。POST 的签名参数位于表单中。标记使用 `POST /api/v2/{type}/{id}/{mark|doing|done}`，删除使用 `POST /api/v2/{type}/{id}/unmark`。登录 redirect URI 为 `frodo://app/oauth/callback/`，附带 `disable_account_create=false`。
- MCP 使用[官方 Python SDK](https://github.com/modelcontextprotocol/python-sdk)内置的 `mcp.server.fastmcp`；依赖版本锁定于 `uv.lock`。
- Frodo 属于 App 内部接口，服务端协议与风控会变化。综合搜索需要登录；已知 404 的 `user/{uid}/doulists` 暂未暴露为工具。
