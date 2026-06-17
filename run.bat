@echo off
chcp 65001 >nul
cd /d "%~dp0"
title 哨兵 Sentinel · 网络安全流量分析智能体
echo ============================================
echo    哨兵 Sentinel 网络安全流量分析智能体
echo ============================================
echo.

REM ---- 1) 选择 Python 命令 ----
set "PY="
where python >nul 2>nul && set "PY=python"
if not defined PY ( where py >nul 2>nul && set "PY=py -3" )
if not defined PY (
  echo [错误] 未检测到 Python。请先安装 Python 3.10+，安装时务必勾选 "Add Python to PATH"。
  echo 下载地址: https://www.python.org/downloads/
  pause & exit /b 1
)

REM ---- 2) 创建虚拟环境并安装依赖 ----
if not exist ".venv\Scripts\python.exe" (
  echo [1/3] 首次运行：创建虚拟环境并安装依赖（可能需要几分钟）...
  %PY% -m venv .venv || ( echo [错误] 创建虚拟环境失败。 & pause & exit /b 1 )
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt || ( echo [错误] 依赖安装失败，请检查网络。 & pause & exit /b 1 )
) else (
  echo [1/3] 虚拟环境已存在，跳过安装。
)

REM ---- 3) 准备 .env ----
if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo [2/3] 已生成 .env（默认离线规则模式；填入 DEEPSEEK_API_KEY 可启用大模型研判）。
) else (
  echo [2/3] 已存在 .env。
)

REM ---- 4) 启动服务并打开浏览器 ----
echo [3/3] 启动服务：http://localhost:8000   （按 Ctrl+C 可停止）
start "" cmd /c "timeout /t 3 >nul && start http://localhost:8000"
".venv\Scripts\python.exe" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
echo.
echo 服务已停止。
pause
