@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 正在启动流量抓取脚本（建议右键选择"以管理员身份运行"以获得最佳抓包效果）...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0capture_traffic.ps1"
echo.
pause
