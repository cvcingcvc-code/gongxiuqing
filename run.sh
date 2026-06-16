#!/usr/bin/env bash
# 一键启动脚本
set -e
cd "$(dirname "$0")"

# 1) 准备虚拟环境
if [ ! -d ".venv" ]; then
  echo "[1/3] 创建虚拟环境并安装依赖…"
  python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
else
  echo "[1/3] 已存在虚拟环境，跳过创建。"
fi

# 2) 准备 .env
if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "[2/3] 已生成 .env（默认离线规则模式；填入 DEEPSEEK_API_KEY 可启用大模型研判）。"
else
  echo "[2/3] 已存在 .env。"
fi

# 3) 启动
PORT="${APP_PORT:-8000}"
echo "[3/3] 启动哨兵：http://localhost:${PORT}"
exec ./.venv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port "${PORT}"
