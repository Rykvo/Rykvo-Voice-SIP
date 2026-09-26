# Rykvo Voice SIP 接入接口 v1

## 接入方式

本地网页只需两个输入：接入地址、接入码。

1. 云端创建客户端，点「连接 → 生成接入码」。
2. 用户将两项填写到本地网页。
3. 本地后端调用接入接口，持久化配置，启动 WireGuard，再应用本地 SIP 网络设置。

这是后端到后端的 HTTPS API，不是 SSH，也不是浏览器跨域接口。本地自动配置程序由你实现；云端不会仅凭一次 HTTP 请求自动安装本地软件。

## 请求

POST https://203.0.113.10/api/connect

配置 SIP 域名后，使用云端弹窗返回的完整接入地址；面板域名不作为接入地址。

Headers:
  Authorization: Bearer TOKEN
  Content-Type: application/json

Body:
```json
{"installationId":"5265b565-a018-4961-a914-0fdd12f48076"}
```

installationId：本地首次启动生成并持久化的随机标识，16–64 位字母、数字、下划线或横线。推荐 UUID v4。不是用户名、硬件序列号或每次请求随机生成的 ID。

不发送浏览器 Origin、Cookie 或云端管理员密码。不把接入码放在 URL/query string 中。必须验证 HTTPS 证书；禁止关闭证书验证。不要自动跟随重定向传递 Authorization。

## 成功响应：200

```json
{
  "version": 1,
  "client": {"id": 1, "name": "01"},
  "wireguard": {
    "interface": "sip1",
    "config": "完整的 wg-quick 配置文本，包含该客户端专属密钥与分流路由"
  },
  "sip": {
    "server": "203.0.113.10",
    "bindAddress": "10.77.0.2",
    "publicAddress": "203.0.113.10",
    "portRange": {"start": 20000, "end": 29999},
    "protocols": ["tcp", "udp"]
  },
  "routing": {
    "mode": "source",
    "preserveDefaultRoute": true,
    "preserveDns": true
  }
}
```

此示例不包含真实密钥。成功响应与配置不得写入普通日志，不缓存到浏览器、localStorage 或公开文件目录。

## 本地后端处理约定

- 本地网页先做管理员认证与 CSRF 防护，再提交给自己的后端；接入码通过本地后端转发。
- 限制接入地址：HTTPS、无用户名密码、路径 /api/connect。仅连接管理员明确配置的可信云服务；拒绝环回、内网、链路本地地址和重定向，防止 SSRF。
- 限制响应大小（建议 128 KiB），检查 version=1、接口名符合 ^sip[0-9]+$、地址与端口合法。
- 接口返回的是可信云端的 wg-quick 配置，其中包含路由钩子；只能接受经 HTTPS 验证的指定云端，不执行不可信来源的配置。
- 确保 Ubuntu 已安装 WireGuard。由本地安装程序预装，或由有明确管理权限的本地服务安装；浏览器本身不会安装软件。
- 将 wireguard.config 原子写入 /etc/wireguard/{interface}.conf，文件权限 0600，目录权限 0700。
- 启动对应 wg-quick 服务并设置开机启动。通过参数数组调用进程，不拼接或 eval 任意 shell 字符串。
- 启动前检查接口、策略路由表、优先级是否冲突；失败时回滚本次更改，不覆盖其他 VPN 或默认路由。
- 已保存且正在运行的相同配置不要重复启动；服务重启后直接用本地保存的配置连接，不重复消耗接入码。
- 仅将 SIP / RTP 监听与出站源地址绑定 sip.bindAddress，对外 SIP/SDP 地址采用 sip.publicAddress；SIP 与 RTP 的实际端口均在 portRange 内。
- sip.server 是手机填写的云端 IP/域名；SIP 账号密码与认证域仍由本地 SIP 软件管理，不是接入码。
- 向网页展示「配置中 / 已连接 / 失败」，失败时给出简短原因；判断已连接需 WireGuard 实际握手，而不是 HTTP 200。
- 配置文件已经包含源地址分流。不要再设置系统全局默认路由或 DNS；保留现有 Cloudflare Tunnel 出口。

## 接入码规则

- 接入码长期有效，不设置到期时间；每个云端客户端只保留最新一枚。
- 新生成的接入码保存在服务器权限为 `600` 的配置中，仅登录管理员可通过 `GET /api/clients/{id}/enrollment` 读取；响应不缓存，不使用浏览器持久化存储。
- 旧版本仅保存校验值的接入码继续有效，不自动更换；需要手动生成一次新码后，才支持关闭窗口或重新登录后再次查看。
- 首次成功领取后绑定 installationId；不同 installationId 再次领取返回 409。
- 同一 installationId 可持续重复领取配置，不限制领取时间；仍受接口限流保护。
- 重连直接使用已保存配置，不需要每次调用接口。如需后续同步配置，可将接入码保存在本地后端受保护的凭据存储中；不放入浏览器缓存或日志。
- 点击“生成新的”会立即使旧接入码失效，但不会重置已有 WireGuard 密钥，也不会断开正在运行的连接。
- 一份客户端配置只用于一台本地服务器。迁移前停用旧机，避免两台机器争用同一密钥。
- 删除云端客户端将撤销密钥、端口转发和接入码。

## 错误响应

统一格式：{"error":"简短原因"}

400：请求格式或 installationId 不正确。
401：缺少、错误或已被替换的接入码。
403：浏览器直接调用或访问来源不正确。
409：接入码已绑定其他服务器，或客户端状态已变更。
410：对应客户端已删除。
429：请求过于频繁；同一来源最多 20 次/分钟，等待后再试。
502 / 503：云端配置服务暂不可用；保留同一个 installationId 重试。

网络超时：使用同一接入码、同一 installationId 重试，不更换 installationId。建议最多 3 次，间隔 2 / 5 / 10 秒；旧码被替换或撤销时，再由管理员提供新码。

## 云端管理员接口

以下接口仅用于本面板，要求管理员登录 Cookie、同源 Origin 与 X-CSRF-Token；本地接入程序不使用它们。

POST /api/clients/{id}/enrollment
Body: {}
201: {"endpoint":"https://HOST/api/connect","token":"TOKEN","expiresAt":null}

expiresAt 为 null，表示无到期时间。

DELETE /api/clients/{id}/enrollment
200: {"ok":true}
撤销当前接入码，不影响已有隧道。

GET /api/clients/{id}/config
管理员备份与诊断用的旧配置下载接口保留兼容；日常接入使用 /api/connect。

## 验收边界

云端接口可以独立验证；本地程序完成适配后，仍需验证真实插卡宽带下的 WireGuard 握手、SIP 注册和双向音频。

## 接入地址

格式为 https://SIP域名/api/connect；没有 SIP 域名时使用公网 IP。面板域名仅用于网页管理。SIP 域名保持仅 DNS；保存后自动申请 HTTPS 证书并配置接入接口，独立 SIP 域名不开放管理页面。已有接入码保持有效，更新本地接入地址即可。

请求方法不是 POST 时，返回 `405 Method Not Allowed`、`Allow: POST` 和 `{"error":"Method Not Allowed"}`。HEAD 响应不含正文。
