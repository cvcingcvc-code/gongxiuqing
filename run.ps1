# 哨兵 Sentinel · Windows PowerShell 启动脚本
# 用法：在项目目录右键 -> 用 PowerShell 运行；或终端执行  .\run.ps1
# 若提示脚本被禁止运行，先执行： Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   哨兵 Sentinel 网络安全流量分析智能体" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# 1) 选择 Python
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) {
  Write-Host "[错误] 未检测到 Python，请先安装 Python 3.10+ 并勾选 Add to PATH。" -ForegroundColor Red
  Read-Host "按回车退出"; exit 1
}

# 2) 虚拟环境 + 依赖
$venvPy = ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
  Write-Host "[1/3] 首次运行：创建虚拟环境并安装依赖（可能需要几分钟）..."
  & $py.Source -m venv .venv
  & $venvPy -m pip install --upgrade pip
  & $venvPy -m pip install -r requirements.txt
} else {
  Write-Host "[1/3] 虚拟环境已存在，跳过安装。"
}

# 3) .env
if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "[2/3] 已生成 .env（默认离线模式；可填 DEEPSEEK_API_KEY 启用大模型）。"
} else {
  Write-Host "[2/3] 已存在 .env。"
}

# 4) 启动
Write-Host "[3/3] 启动服务：http://localhost:8000  （Ctrl+C 停止）" -ForegroundColor Green
Start-Job { Start-Sleep 3; Start-Process "http://localhost:8000" } | Out-Null
& $venvPy -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
