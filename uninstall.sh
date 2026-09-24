#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ${1:-} == --help ]]; then
  echo 'sudo bash uninstall.sh'
  echo '完整删除本项目程序和全部数据，执行前需确认。'
  exit 0
fi
[[ $EUID == 0 ]] || { echo '请使用 sudo bash uninstall.sh'; exit 1; }
[[ $# == 0 ]] || { echo '未知参数。'; exit 1; }
python3 -B deploy/manage.py uninstall
