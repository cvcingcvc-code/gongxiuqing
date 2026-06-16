"""日志解析工具：把多种结构化文本日志归一化为 TrafficEvent 列表。

支持格式（自动嗅探）：
- Nginx / Apache 访问日志（combined / common）
- JSON Lines（每行一个 JSON 对象）
- CSV（带表头，常用于抓包导出：timestamp,src_ip,dst_ip,src_port,dst_port,protocol,...）
- 通用 key=value（防火墙/syslog 风格）

注意：本工具只处理【文本】。二进制 PCAP 由上层在入口处拦截，不会流到这里。
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Optional
from urllib.parse import urlparse

# Nginx/Apache combined 日志正则
_NGINX_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>[^"]*?)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

_INT_FIELDS = {"src_port", "dst_port", "status", "bytes"}


def _to_int(val) -> Optional[int]:
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return None


def _norm_record(d: dict) -> dict:
    """把任意字典中的常见别名映射到统一字段名。"""
    alias = {
        "source_ip": "src_ip", "sourceip": "src_ip", "client_ip": "src_ip",
        "clientip": "src_ip", "remote_addr": "src_ip", "ip": "src_ip",
        "saddr": "src_ip", "src": "src_ip",
        "dest_ip": "dst_ip", "destination_ip": "dst_ip", "daddr": "dst_ip",
        "dst": "dst_ip", "server_ip": "dst_ip",
        "sport": "src_port", "source_port": "src_port",
        "dport": "dst_port", "destination_port": "dst_port", "port": "dst_port",
        "proto": "protocol", "request_method": "method", "verb": "method",
        "uri": "url", "request": "url", "path": "url",
        "useragent": "user_agent", "ua": "user_agent", "agent": "user_agent",
        "status_code": "status", "code": "status", "response": "status",
        "size": "bytes", "length": "bytes", "len": "bytes", "bytes_sent": "bytes",
        "time": "timestamp", "ts": "timestamp", "datetime": "timestamp",
        "@timestamp": "timestamp", "date": "timestamp",
        "tcp_flags": "flags", "tcpflags": "flags",
    }
    out: dict = {}
    for k, v in d.items():
        key = alias.get(str(k).strip().lower(), str(k).strip().lower())
        out[key] = v
    # request 形如 "GET /a?b HTTP/1.1" 需要拆分
    if "url" in out and isinstance(out["url"], str) and out["url"].startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")):
        parts = out["url"].split()
        if len(parts) >= 2:
            out.setdefault("method", parts[0])
            out["url"] = parts[1]
    # 类型修正
    for f in _INT_FIELDS:
        if f in out:
            out[f] = _to_int(out[f])
    return {k: v for k, v in out.items() if v not in (None, "", "-")}


def _parse_nginx(text: str) -> list[dict]:
    events: list[dict] = []
    for line in text.splitlines():
        m = _NGINX_RE.search(line)
        if not m:
            continue
        g = m.groupdict()
        url = g.get("url") or ""
        host = None
        if url.startswith("http"):
            host = urlparse(url).netloc
        events.append({
            "timestamp": g.get("time"),
            "src_ip": g.get("ip"),
            "method": g.get("method"),
            "url": url,
            "host": host,
            "status": _to_int(g.get("status")),
            "bytes": _to_int(g.get("bytes")),
            "user_agent": g.get("ua"),
            "protocol": "HTTP",
            "dst_port": 80,
            "raw": line.strip(),
        })
    return events


def _parse_jsonl(text: str) -> list[dict]:
    events: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rec = _norm_record(obj)
            rec["raw"] = line
            events.append(rec)
    return events


def _parse_json_array(text: str) -> list[dict]:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(obj, dict):
        obj = obj.get("events") or obj.get("data") or obj.get("logs") or [obj]
    if not isinstance(obj, list):
        return []
    out = []
    for item in obj:
        if isinstance(item, dict):
            rec = _norm_record(item)
            rec["raw"] = json.dumps(item, ensure_ascii=False)
            out.append(rec)
    return out


def _parse_csv(text: str) -> list[dict]:
    try:
        sample = text[:2048]
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        return []
    events = []
    for row in reader:
        rec = _norm_record({k: v for k, v in row.items() if k})
        rec["raw"] = ",".join(str(v) for v in row.values() if v is not None)
        events.append(rec)
    return events


def _parse_kv(text: str) -> list[dict]:
    """通用 key=value（防火墙/syslog）。"""
    kv_re = re.compile(r'(\w[\w\-.]*)=("[^"]*"|\S+)')
    events = []
    for line in text.splitlines():
        if "=" not in line:
            continue
        pairs = {k: v.strip('"') for k, v in kv_re.findall(line)}
        if not pairs:
            continue
        rec = _norm_record(pairs)
        if rec:
            rec["raw"] = line.strip()
            events.append(rec)
    return events


def sniff_format(text: str) -> str:
    head = "\n".join(text.strip().splitlines()[:5])
    if not head:
        return "unknown"
    if head.lstrip().startswith(("{", "[")):
        # 可能是 jsonl 或 json array
        first = head.lstrip()[0]
        return "json_array" if first == "[" else "jsonl"
    if _NGINX_RE.search(head):
        return "nginx"
    # CSV：首行有逗号/分号/制表分隔且像表头
    first_line = head.splitlines()[0]
    if any(sep in first_line for sep in (",", ";", "\t", "|")) and "=" not in first_line:
        return "csv"
    if "=" in first_line:
        return "kv"
    return "unknown"


def parse_logs(text: str) -> tuple[list[dict], str]:
    """解析日志文本，返回 (事件列表, 识别到的格式)。

    采用「嗅探 + 多解析器兜底」策略：先按嗅探结果解析，若产出为空再依次尝试其他解析器。
    """
    if not text or not text.strip():
        return [], "empty"

    fmt = sniff_format(text)
    parsers = {
        "nginx": _parse_nginx,
        "jsonl": _parse_jsonl,
        "json_array": _parse_json_array,
        "csv": _parse_csv,
        "kv": _parse_kv,
    }
    order = [fmt] + [k for k in parsers if k != fmt]
    for name in order:
        fn = parsers.get(name)
        if not fn:
            continue
        events = fn(text)
        if events:
            return events, name
    return [], fmt
