# 哨兵 Sentinel · Windows 流量抓取脚本
#
# 用法：
#   1) 右键 -> 用 PowerShell 运行，或在终端执行：
#        .\capture_traffic.ps1                 (默认抓 30 秒)
#        .\capture_traffic.ps1 -Duration 60     (抓 60 秒)
#        .\capture_traffic.ps1 -Interface "WLAN" (指定网卡，配合 tshark)
#
#   2) 跑完会在当前目录生成一个 traffic_capture_*.csv 文件，
#      把它【粘贴内容】或【上传文件】到哨兵网页里即可分析。
#
# 设计说明（安全）：
#   - 本脚本只产出【结构化 CSV 文本】，绝不生成/保留 .pcap 二进制包，
#     避免原始抓包文件可能携带的恶意载荷被直接喂给智能体。
#   - 优先使用 tshark（随 Wireshark 安装）做真实抓包并直接输出字段化文本；
#     若未安装 Wireshark，则自动降级为「网络连接快照」模式：
#     通过系统自带的 Get-NetTCPConnection 轮询记录所有 TCP 连接
#     （本地/远程 IP、端口、状态、进程），无需安装任何工具、无需管理员权限。

param(
  [int]$Duration = 30,
  [string]$Interface = ""
)

$ErrorActionPreference = "Stop"
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = "traffic_capture_$ts.csv"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   哨兵 Sentinel · 流量抓取" -ForegroundColor Cyan
Write-Host "============================================`n"

# ---------- 尝试定位 tshark ----------
function Find-Tshark {
  $cmd = Get-Command tshark -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $candidates = @(
    "$env:ProgramFiles\Wireshark\tshark.exe",
    "${env:ProgramFiles(x86)}\Wireshark\tshark.exe"
  )
  foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
  return $null
}

$tshark = Find-Tshark

if ($tshark) {
  Write-Host "[模式] 检测到 tshark，使用真实抓包：$tshark" -ForegroundColor Green

  # 列出网卡，方便用户选择
  if (-not $Interface) {
    Write-Host "`n可用网卡列表：" -ForegroundColor Yellow
    & $tshark -D
    $Interface = Read-Host "`n请输入要抓取的网卡编号或名称（直接回车使用默认/第一个）"
  }

  $ifaceArg = @()
  if ($Interface) { $ifaceArg = @("-i", $Interface) } else { $ifaceArg = @("-i", "1") }

  Write-Host "`n[抓包] 开始抓取 $Duration 秒…（需以管理员身份运行 PowerShell 才能成功抓包）" -ForegroundColor Yellow

  # 直接输出结构化字段为 CSV，全程不落地 .pcap 二进制文件
  $tmpRaw = "$env:TEMP\sentinel_raw_$ts.csv"
  & $tshark @ifaceArg -a duration:$Duration -T fields -E header=y -E separator="," -E quote=d `
      -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport `
      -e _ws.col.Protocol -e frame.len -e tcp.flags.str -e http.request.method -e http.request.uri -e http.user_agent `
      2>$null | Out-File -Encoding utf8 $tmpRaw

  # 整理表头为智能体可直接识别的字段名
  $lines = Get-Content $tmpRaw
  if ($lines.Count -gt 1) {
    $header = "timestamp,src_ip,dst_ip,src_port,dst_port,udp_srcport,udp_dstport,protocol,bytes,flags,method,url,user_agent"
    $body = $lines | Select-Object -Skip 1
    @($header) + $body | Out-File -Encoding utf8 $outFile
    Remove-Item $tmpRaw -ErrorAction SilentlyContinue
    Write-Host "`n[完成] 已生成结构化流量日志：$outFile" -ForegroundColor Green
    Write-Host "共 $($body.Count) 条记录。请将该文件内容粘贴或上传到哨兵网页进行分析。" -ForegroundColor Green
  } else {
    Write-Host "`n[警告] 未抓到任何数据包。请确认：" -ForegroundColor Red
    Write-Host "  1) 是否以【管理员身份】运行了 PowerShell"
    Write-Host "  2) 选择的网卡是否正确（当前网络活动的网卡）"
    Write-Host "  3) 抓包期间是否有访问网络的活动（可以打开几个网页试试）"
    Remove-Item $tmpRaw -ErrorAction SilentlyContinue
  }

} else {
  Write-Host "[模式] 未检测到 Wireshark/tshark，使用【网络连接快照】模式（无需安装任何工具）" -ForegroundColor Yellow
  Write-Host "提示：此模式记录的是 TCP 连接状态快照，不含 HTTP 载荷内容，仍可用于检测端口扫描/异常连接等行为。`n"
  Write-Host "若需更全面的攻击特征检测（如 SQL 注入/XSS 等 HTTP 层攻击），建议安装 Wireshark 后重新运行本脚本：" -ForegroundColor Cyan
  Write-Host "  https://www.wireshark.org/download.html`n"

  "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,status,process" | Out-File -Encoding utf8 $outFile

  $endTime = (Get-Date).AddSeconds($Duration)
  $seen = New-Object System.Collections.Generic.HashSet[string]
  Write-Host "[抓取] 开始记录 $Duration 秒的网络连接…" -ForegroundColor Yellow

  while ((Get-Date) -lt $endTime) {
    try {
      $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    } catch { $conns = @() }

    foreach ($c in $conns) {
      if (-not $c.RemoteAddress -or $c.RemoteAddress -eq "0.0.0.0" -or $c.RemoteAddress -eq "::") { continue }
      $procName = ""
      try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
      $key = "$($c.LocalAddress):$($c.LocalPort)-$($c.RemoteAddress):$($c.RemotePort)-$($c.State)"
      if ($seen.Add($key)) {
        $now = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        "$now,$($c.LocalAddress),$($c.LocalPort),$($c.RemoteAddress),$($c.RemotePort),TCP,$($c.State),$procName" |
          Out-File -Encoding utf8 -Append $outFile
      }
    }
    Start-Sleep -Milliseconds 800
  }

  $count = (Get-Content $outFile | Measure-Object -Line).Lines - 1
  Write-Host "`n[完成] 已生成结构化流量日志：$outFile（共 $count 条去重后的连接记录）" -ForegroundColor Green
  Write-Host "请将该文件内容粘贴或上传到哨兵网页进行分析。" -ForegroundColor Green
}

Write-Host "`n文件位置：$(Resolve-Path $outFile)`n"
