# 哨兵 Sentinel · Windows 流量抓取脚本
#
# 用法：
#   .\capture_traffic.ps1                  (默认抓 30 秒)
#   .\capture_traffic.ps1 -Duration 60     (抓 60 秒)
#   .\capture_traffic.ps1 -Interface "WLAN"
#
# 安全说明：本脚本只产出结构化 CSV 文本，绝不生成 .pcap 二进制包。
# 优先使用 tshark（随 Wireshark 安装）；未安装时自动降级为
# Get-NetTCPConnection 连接快照模式，无需安装/无需管理员权限。

param(
  [int]$Duration = 30,
  [string]$Interface = ""
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path (Get-Location) "traffic_capture_$ts.csv"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Sentinel - Traffic Capture" -ForegroundColor Cyan
Write-Host "   哨兵 · 流量抓取" -ForegroundColor Cyan
Write-Host "============================================`n"

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
  Write-Host "[Mode] tshark detected: $tshark" -ForegroundColor Green
  Write-Host "[模式] 检测到 tshark，使用真实抓包" -ForegroundColor Green

  if (-not $Interface) {
    Write-Host "`n可用网卡列表 / Available interfaces:" -ForegroundColor Yellow
    & $tshark -D
    $Interface = Read-Host "`n请输入网卡编号或名称（直接回车使用 1）"
    if (-not $Interface) { $Interface = "1" }
  }

  Write-Host "`n[Capture] 抓取 $Duration 秒（建议以管理员身份运行）..." -ForegroundColor Yellow

  $tmpRaw = Join-Path $env:TEMP "sentinel_raw_$ts.csv"
  & $tshark -i $Interface -a "duration:$Duration" -T fields -E header=y -E separator="," -E quote=d `
      -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport `
      -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e frame.len `
      -e tcp.flags.str -e http.request.method -e http.request.uri -e http.user_agent `
      2>$null | Out-File -Encoding utf8 $tmpRaw

  if (Test-Path $tmpRaw) {
    $lines = Get-Content $tmpRaw
    if ($lines.Count -gt 1) {
      $header = "timestamp,src_ip,dst_ip,src_port,dst_port,udp_srcport,udp_dstport,protocol,bytes,flags,method,url,user_agent"
      $body = $lines | Select-Object -Skip 1
      @($header) + $body | Out-File -Encoding utf8 $outFile
      Remove-Item $tmpRaw -ErrorAction SilentlyContinue
      Write-Host "`n[OK] 已生成: $outFile" -ForegroundColor Green
      Write-Host "共 $($body.Count) 条记录。请把文件内容粘贴或上传到哨兵网页分析。" -ForegroundColor Green
    } else {
      Write-Host "`n[Warn] 未抓到数据包。请确认：" -ForegroundColor Red
      Write-Host "  1) 是否以管理员身份运行 PowerShell"
      Write-Host "  2) 网卡编号是否正确"
      Write-Host "  3) 抓包期间是否有网络活动"
      Remove-Item $tmpRaw -ErrorAction SilentlyContinue
    }
  } else {
    Write-Host "[Error] tshark 未输出文件，可能权限不足或网卡编号错误。" -ForegroundColor Red
  }

} else {
  Write-Host "[Mode] 未检测到 Wireshark/tshark，使用连接快照模式" -ForegroundColor Yellow
  Write-Host "提示：此模式不含 HTTP 载荷，但能检测端口扫描/异常外联。" -ForegroundColor Cyan
  Write-Host "如需检测 SQLi/XSS 等应用层攻击，请安装 Wireshark:" -ForegroundColor Cyan
  Write-Host "  https://www.wireshark.org/download.html`n"

  "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,status,process" | Out-File -Encoding utf8 $outFile

  $endTime = (Get-Date).AddSeconds($Duration)
  $seen = New-Object System.Collections.Generic.HashSet[string]
  Write-Host "[Capture] 记录 $Duration 秒的网络连接..." -ForegroundColor Yellow

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
  Write-Host "`n[OK] 已生成: $outFile（共 $count 条连接记录）" -ForegroundColor Green
  Write-Host "请把文件内容粘贴或上传到哨兵网页分析。" -ForegroundColor Green
}

Write-Host "`n文件位置: $outFile`n"
