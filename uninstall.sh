#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ${1:-} == --help ]]; then
  echo 'sudo bash uninstall.sh [--purge]'
  echo '默认保留账号、配置、密钥、证书和客户端数据；--purge 需要再次确认。'
  exit 0
fi
[[ $EUID == 0 ]] || { echo '请使用 sudo bash uninstall.sh'; exit 1; }
[[ $# == 0 || ( $# == 1 && $1 == --purge ) ]] || { echo '未知参数。'; exit 1; }
python3 -B deploy/manage.py uninstall "$@"
