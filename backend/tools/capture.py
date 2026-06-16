"""抓包工具：监测指定端口的流量并产出【结构化文本事件】。

双轨设计（CAPTURE_BACKEND 控制）：
  - scapy   : 用 scapy 嗅探（需安装 scapy + libpcap + root 权限）
  - tcpdump : 调用系统 tcpdump 抓包再解析（需 root）
  - simulate: 生成贴近真实的模拟攻击流量（用于沙箱/演示，无需权限）
  - auto    : 依次尝试 scapy -> tcpdump，都不可用则回退 simulate

关键安全准则：无论哪种后端，最终交给大模型/检测引擎的都是【结构化文本】，
绝不把原始二进制载荷喂给模型，规避「文件带毒」风险。
"""
from __future__ import annotations

import random
import shutil
import subprocess
import time
from datetime import datetime, timedelta

from .. import config


def _now_iso(offset_sec: float = 0.0) -> str:
    return (datetime.now() + timedelta(seconds=offset_sec)).strftime("%Y-%m-%dT%H:%M:%S")


# ---------------- scapy 后端 ----------------
def _capture_scapy(port: int, iface, duration: int, max_pkts: int):
    try:
        from scapy.all import sniff, IP, TCP, UDP, Raw  # type: ignore
    except Exception:
        return None  # scapy 不可用

    bpf = f"tcp port {port} or udp port {port}"
    pkts = sniff(filter=bpf, iface=iface, timeout=duration, count=max_pkts)
    events = []
    for p in pkts:
        if IP not in p:
            continue
        l4 = p[TCP] if TCP in p else (p[UDP] if UDP in p else None)
        flags = str(p[TCP].flags) if TCP in p else None
        payload = ""
        if Raw in p:
            try:
                payload = bytes(p[Raw].load).decode("utf-8", "replace")[:300]
            except Exception:
                payload = ""
        events.append({
            "timestamp": datetime.fromtimestamp(float(p.time)).strftime("%Y-%m-%dT%H:%M:%S"),
            "src_ip": p[IP].src, "dst_ip": p[IP].dst,
            "src_port": int(l4.sport) if l4 else None,
            "dst_port": int(l4.dport) if l4 else None,
            "protocol": "TCP" if TCP in p else ("UDP" if UDP in p else "IP"),
            "flags": flags,
            "bytes": len(p),
            "url": _extract_http_uri(payload),
            "raw": payload.replace("\r\n", " ").strip()[:300] or f"{p[IP].src}->{p[IP].dst}:{port}",
        })
    return events


def _extract_http_uri(payload: str):
    """从 HTTP 明文载荷里提取请求行（仅文本，不含二进制）。"""
    if not payload:
        return None
    first = payload.splitlines()[0] if payload.splitlines() else ""
    parts = first.split()
    if len(parts) >= 2 and parts[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"):
        return parts[1]
    return None


# ---------------- tcpdump 后端 ----------------
def _capture_tcpdump(port: int, iface, duration: int, max_pkts: int):
    if not shutil.which("tcpdump"):
        return None
    cmd = ["tcpdump", "-nn", "-l", "-q", "-c", str(max_pkts),
           "port", str(port)]
    if iface:
        cmd += ["-i", iface]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 2)
    except (subprocess.TimeoutExpired, PermissionError, OSError):
        return None
    events = []
    for line in proc.stdout.splitlines():
        # 形如: 12:00:01.123 IP 1.2.3.4.5555 > 10.0.0.1.80: tcp 0
        try:
            ts, rest = line.split(" IP ", 1)
            left, right = rest.split(" > ", 1)
            s_ip, s_port = left.rsplit(".", 1)
            r_part = right.split(":", 1)[0]
            d_ip, d_port = r_part.rsplit(".", 1)
            events.append({
                "timestamp": _now_iso(),
                "src_ip": s_ip, "dst_ip": d_ip,
                "src_port": int(s_port) if s_port.isdigit() else None,
                "dst_port": int(d_port) if d_port.isdigit() else None,
                "protocol": "TCP", "raw": line.strip(),
            })
        except (ValueError, IndexError):
            continue
    return events


# ---------------- 模拟后端 ----------------
_SIM_ATTACKERS = [
    ("113.108.182.66", "sqlmap/1.7.2#stable (http://sqlmap.org)"),
    ("221.226.13.45", "Mozilla/5.0 (compatible; Nmap Scripting Engine)"),
    ("45.155.205.99", "Mozilla/5.0 (X11; Linux x86_64)"),
    ("171.12.66.190", "python-requests/2.31.0"),
]
_SIM_BENIGN = [("59.110.23.88", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")]

_SIM_PAYLOADS = [
    ("GET", "/product?id=1' UNION SELECT username,password FROM users--", 200),
    ("GET", "/search?q=<script>alert(document.cookie)</script>", 200),
    ("GET", "/download?file=../../../../etc/passwd", 404),
    ("POST", "/admin/login", 401),
    ("GET", "/.env", 404),
    ("GET", "/.git/config", 404),
    ("GET", "/api/v1/ping?host=127.0.0.1;cat /etc/passwd", 500),
    ("GET", "/wp-login.php", 403),
]


def _capture_simulate(port: int, target_host, duration: int):
    """生成贴近真实的模拟攻击流量（结构化）。"""
    events = []
    dst_ip = "10.0.0.10"
    base = 0.0
    # 正常流量
    for _ in range(15):
        ip, ua = random.choice(_SIM_BENIGN)
        events.append({
            "timestamp": _now_iso(base), "src_ip": ip, "dst_ip": dst_ip,
            "src_port": random.randint(20000, 60000), "dst_port": port,
            "protocol": "HTTP", "method": "GET", "url": random.choice(["/", "/index.html", "/api/v1/products", "/static/app.js"]),
            "status": 200, "user_agent": ua, "bytes": random.randint(200, 4000),
            "host": target_host or "demo.local",
        })
        base += random.uniform(0.3, 1.5)

    # 端口扫描（同源大量不同端口）
    scanner_ip = "221.226.13.45"
    for p in random.sample(range(1, 1024), 25):
        events.append({
            "timestamp": _now_iso(base), "src_ip": scanner_ip, "dst_ip": dst_ip,
            "src_port": random.randint(40000, 60000), "dst_port": p,
            "protocol": "TCP", "flags": "S", "bytes": 60,
            "raw": f"{scanner_ip}.{random.randint(40000,60000)} > {dst_ip}.{p}: Flags [S]",
        })
        base += 0.1

    # Web 攻击载荷
    for method, url, status in _SIM_PAYLOADS:
        ip, ua = random.choice(_SIM_ATTACKERS)
        events.append({
            "timestamp": _now_iso(base), "src_ip": ip, "dst_ip": dst_ip,
            "src_port": random.randint(20000, 60000), "dst_port": port,
            "protocol": "HTTP", "method": method, "url": url, "status": status,
            "user_agent": ua, "bytes": random.randint(150, 800),
            "host": target_host or "demo.local",
            "raw": f'{ip} - - "{method} {url} HTTP/1.1" {status} - "{ua}"',
        })
        base += random.uniform(0.2, 0.8)

    # 暴力破解
    bf_ip = "171.12.66.190"
    for _ in range(12):
        events.append({
            "timestamp": _now_iso(base), "src_ip": bf_ip, "dst_ip": dst_ip,
            "src_port": random.randint(20000, 60000), "dst_port": port,
            "protocol": "HTTP", "method": "POST", "url": "/admin/login",
            "status": 401, "user_agent": "python-requests/2.31.0", "bytes": 120,
            "raw": f'{bf_ip} - - "POST /admin/login HTTP/1.1" 401 -',
        })
        base += 0.4

    events.sort(key=lambda e: e["timestamp"])
    return events


def capture_port(port: int, iface=None, duration=None, target_host=None) -> tuple[list[dict], dict]:
    """监测指定端口，返回 (结构化事件, 抓包元信息)。"""
    duration = duration or config.CAPTURE_TIMEOUT
    max_pkts = config.CAPTURE_MAX_PACKETS
    iface = iface or config.CAPTURE_IFACE
    backend = config.CAPTURE_BACKEND
    meta = {"requested_backend": backend, "port": port, "iface": iface,
            "duration": duration, "simulated": False}

    chain = []
    if backend == "scapy":
        chain = [("scapy", _capture_scapy)]
    elif backend == "tcpdump":
        chain = [("tcpdump", _capture_tcpdump)]
    elif backend == "simulate":
        chain = []
    else:  # auto
        chain = [("scapy", _capture_scapy), ("tcpdump", _capture_tcpdump)]

    for name, fn in chain:
        try:
            if name == "scapy":
                events = fn(port, iface, duration, max_pkts)
            else:
                events = fn(port, iface, duration, max_pkts)
        except Exception:
            events = None
        if events:
            meta.update(used_backend=name, simulated=False, event_count=len(events))
            return events, meta

    # 回退：模拟
    events = _capture_simulate(port, target_host, duration)
    meta.update(used_backend="simulate", simulated=True, event_count=len(events))
    return events, meta
