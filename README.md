# Rykvo Voice SIP

Ubuntu 24.04 LTS · amd64 / arm64

## 一键部署

```bash
curl -fsSL https://raw.githubusercontent.com/Rykvo/Rykvo-Voice-SIP/main/deploy.sh | sudo bash -s -- install
```

仓库公开后可用。在 SSH 终端执行，按提示填写管理员账号和密码；完成后访问 `https://服务器IP`。

## 一键更新

```bash
sudo rykvo-sip update
```

## 一键卸载

```bash
sudo rykvo-sip uninstall
```

完整删除本项目程序、配置和全部数据，执行前需确认。Docker、Caddy 等共享依赖保留。
