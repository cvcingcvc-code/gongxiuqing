#!/usr/bin/env bash
# 跨平台一键启动（Linux / macOS / Windows Git Bash）
# Windows 用户更推荐直接双击 run.bat
set -e
cd "$(dirname "$0")"

# 选择 python 命令
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi

venv_bin() { if [ -d ".venv/Scripts" ]; then echo ".venv/Scripts"; else echo ".venv/bin"; fi; }

BIN="$(venv_bin)"
if [ ! -e "$BIN/python" ] && [ ! -e "$BIN/python.exe" ]; then
  echo "[1/3] 创建虚拟环境并安装依赖…"
  "$PY" -m venv .venv
  BIN="$(venv_bin)"
  "$BIN/python" -m pip install -q --upgrade pip
  "$BIN/python" -m pip install -q -r requirements.txt
else
  echo "[1/3] 已存在虚拟环境，跳过安装。"
fi

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "[2/3] 已生成 .env（默认离线规则模式；填入 DEEPSEEK_API_KEY 可启用大模型）。"
else
  echo "[2/3] 已存在 .env。"
fi

PORT="${APP_PORT:-8000}"
echo "[3/3] 启动哨兵：http://localhost:${PORT}"
exec "$BIN/python" -m uvicorn backend.main:app --host 0.0.0.0 --port "${PORT}"
