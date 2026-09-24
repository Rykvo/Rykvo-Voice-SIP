#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ${1:-} == --help ]]; then
  echo 'sudo bash install.sh [--check]'
  exit 0
fi
[[ $EUID == 0 ]] || { echo '请使用 sudo bash install.sh'; exit 1; }
command -v python3 >/dev/null || { echo '请先安装 python3。'; exit 1; }
python3 -B deploy/manage.py preflight
[[ ${1:-} != --check ]] || exit 0
[[ $# == 0 ]] || { echo '未知参数。'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg iproute2 iptables kmod python3 wireguard-tools
if ! command -v docker >/dev/null; then
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL --retry 3 https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod 0644 /etc/apt/keyrings/docker.asc
  # Supported releases are checked before adding repositories.
  source /etc/os-release
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" > /etc/apt/sources.list.d/rykvo-docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
docker compose version >/dev/null || { echo '请安装 Docker Compose v2 插件后重试。'; exit 1; }
if ! command -v caddy >/dev/null; then
  curl -fsSL --retry 3 https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/rykvo-caddy.gpg
  curl -fsSL --retry 3 https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt |
    sed 's@/usr/share/keyrings/caddy-stable-archive-keyring.gpg@/usr/share/keyrings/rykvo-caddy.gpg@g' > /etc/apt/sources.list.d/rykvo-caddy.list
  chmod 0644 /usr/share/keyrings/rykvo-caddy.gpg
  apt-get update
  apt-get install -y caddy
  systemctl disable --now caddy
fi
dpkg --compare-versions "$(caddy version | awk '{print $1}' | sed 's/^v//')" ge 2.11.4 || {
  echo '需要 Caddy 2.11.4 或更新版本。'; exit 1;
}
systemctl enable --now docker
modprobe wireguard
python3 -B deploy/manage.py install
