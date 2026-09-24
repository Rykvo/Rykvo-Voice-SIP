# Rykvo Voice SIP

云端 SIP 端口映射与 WireGuard 客户端管理面板。

## 环境

- Ubuntu 24.04 LTS，amd64 / arm64，systemd，支持 WireGuard 的内核。
- 一台具备公网 IPv4 的云主机；建议使用干净的专用主机。
- TCP `80/443`、UDP `51820`，以及分配给客户端的 TCP/UDP 端口段需在云防火墙放行。
- Docker Engine、Compose 插件、Caddy ≥ 2.11.4、Python 3、WireGuard tools 由脚本检查并安装。
- 不包含本地 Ubuntu 自动配置程序；其对接协议见 [接口文档](app/web/integration.md)。

## 一键部署

仓库为私有仓库。新服务器需先获得 GitHub 仓库读取权限，推荐配置只读 SSH deploy key；不要把 GitHub Token 放进命令或项目文件。

SSH 登录云服务器后执行：

```bash
sudo apt-get update && sudo apt-get install -y git
git clone git@github.com:Rykvo/Rykvo-Voice-SIP.git
cd Rykvo-Voice-SIP
sudo bash install.sh
```

已下载源码时，只需：

```bash
sudo bash install.sh
```

脚本检测出口网卡，确认公网 IP，安装服务，最后交互填写管理员账号和密码。密码输入不回显，最低 8 位；仓库不含默认管理员密码。

完成后访问 `https://你的公网IP/`。证书由 Caddy 自动申请及续期；首次签发需要时间，并依赖公网 80/443 可达。IP 证书使用 Let's Encrypt 短期证书，不关闭 TLS 验证。

仅检查环境，不修改系统：

```bash
sudo bash install.sh --check
```

## 卸载

```bash
sudo bash uninstall.sh
```

确认后停止并移除本项目服务、容器、端口规则和启动项。**默认保留账号、客户端、密钥、证书与配置**，再次安装可复用。

连同本项目数据一起删除，需要额外输入 `DELETE` 确认：

```bash
sudo bash uninstall.sh --purge
```

不会卸载共享的 Docker、Caddy、Python 等系统软件，也不会清空整台机器的防火墙或删除其他容器。

## 更新

```bash
git pull --ff-only
sudo bash install.sh
```

仅支持由此安装器管理的实例。保留原账号和数据，不重复设置密码；应用源码保留一份回滚副本。安装器检测到无安装标记的现有部署时会停止，避免覆盖已有业务。

## 域名

| 用途 | Cloudflare 设置 |
| --- | --- |
| SIP 域名 / 本地接入接口 | 仅 DNS |
| 面板域名 | 可开启代理，SSL/TLS 使用完全（严格） |

域名 A 记录指向云主机。面板保存后自动配置 HTTPS；代理识别不等于回源验证。更换 SIP 域名后，本地接入地址、WireGuard Endpoint 和手机 SIP 设置需要相应更新。

本地填写的接入地址为 `https://SIP域名/api/connect`，未配置 SIP 域名时使用公网 IP。浏览器直接打开此接口只显示 404；本地程序以 POST + 接入码调用。

## 维护

```bash
sudo systemctl status sip-simple-panel sip-caddy sip-portmap sip-wireguard
sudo journalctl -u sip-simple-panel -n 50 --no-pager
sudo journalctl -u sip-caddy -n 50 --no-pager
sudo docker logs --tail 50 sip-wg-easy
```

数据目录：`/opt/sip-tunnel`。备份此目录须加密保存，其中包含密钥、内部服务凭据和客户端数据。不要提交至 Git。

账号、证书和客户端都是安装时生成的独立数据；源码不包含任何线上服务器数据。

## 验证

```bash
python3 -B tests/test_server.py
python3 -B -m unittest discover -s tests -p 'test_deploy.py'
node tests/ui.cjs
bash -n install.sh uninstall.sh
```

自动化测试覆盖账号、会话、接入码、域名检查、配置导出、页面结构和安装器边界。首次在新主机部署后，仍需进行本地隧道与实际 SIP 双向通话验收。

依赖来源：[Docker](https://docs.docker.com/engine/install/ubuntu/)、[Caddy](https://caddyserver.com/docs/install)、[wg-easy](https://github.com/wg-easy/wg-easy)。wg-easy 固定为已使用的 `15.4.0`，不使用浮动 `latest`。
