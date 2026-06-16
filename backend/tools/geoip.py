"""IP 溯源工具：把攻击者 IP 定位到归属地（至少省份级）。

多级数据源，按可靠性/可用性回退：
  1) ip2region 离线 xdb（若配置了路径）—— 纯离线、最快、省份级
  2) 在线 API ip-api.com（若允许联网）—— 免费、无需 key、含省份(regionName)
  3) 内置演示映射 ip_demo_map.json —— 保证沙箱/离线也能出结果
  4) 私网/保留地址识别
"""
from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from typing import Optional

import requests

from .. import config

_DEMO_MAP_CACHE: Optional[dict] = None
_XDB_SEARCHER = None
_XDB_TRIED = False


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def _load_demo_map() -> dict:
    global _DEMO_MAP_CACHE
    if _DEMO_MAP_CACHE is None:
        path = config.GEOIP_DIR / "ip_demo_map.json"
        try:
            _DEMO_MAP_CACHE = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            _DEMO_MAP_CACHE = {}
    return _DEMO_MAP_CACHE


def _get_xdb_searcher():
    """惰性加载 ip2region xdb（需安装 ip2region 包并配置 xdb 路径）。"""
    global _XDB_SEARCHER, _XDB_TRIED
    if _XDB_TRIED:
        return _XDB_SEARCHER
    _XDB_TRIED = True
    if not config.IP2REGION_XDB_PATH:
        return None
    try:
        from ip2region.xdbSearcher import XdbSearcher  # type: ignore

        cb = XdbSearcher.loadContentFromFile(dbfile=config.IP2REGION_XDB_PATH)
        _XDB_SEARCHER = XdbSearcher(contentBuff=cb)
    except Exception:
        _XDB_SEARCHER = None
    return _XDB_SEARCHER


def _from_xdb(ip: str) -> Optional[dict]:
    searcher = _get_xdb_searcher()
    if not searcher:
        return None
    try:
        # 返回格式：国家|区域|省份|城市|ISP
        region = searcher.search(ip)
        if not region:
            return None
        parts = region.split("|")
        parts += ["0"] * (5 - len(parts))
        clean = lambda x: None if x in ("0", "", None) else x
        return {
            "country": clean(parts[0]),
            "province": clean(parts[2]),
            "city": clean(parts[3]),
            "isp": clean(parts[4]),
            "source": "ip2region",
        }
    except Exception:
        return None


def _from_online(ip: str) -> Optional[dict]:
    if not config.GEOIP_ONLINE_ENABLED:
        return None
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"lang": "zh-CN",
                    "fields": "status,country,regionName,city,isp,query"},
            timeout=5,
        )
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "country": data.get("country"),
            "province": data.get("regionName"),   # 省/州 —— 满足省份级溯源
            "city": data.get("city"),
            "isp": data.get("isp"),
            "source": "online",
        }
    except Exception:
        return None


def _from_demo(ip: str) -> Optional[dict]:
    info = _load_demo_map().get(ip)
    if not info:
        return None
    return {**info, "source": "demo"}


@lru_cache(maxsize=2048)
def geolocate_ip(ip: str) -> dict:
    """溯源单个 IP，返回 GeoInfo 结构字典。"""
    base = {"ip": ip, "is_private": False, "country": None, "province": None,
            "city": None, "isp": None, "source": "unknown"}
    if not ip or ip == "未知":
        base["source"] = "unknown"
        return base
    if _is_private(ip):
        base.update(is_private=True, country="内网/保留地址",
                    province="内网", source="private")
        return base

    for provider in (_from_xdb, _from_demo, _from_online):
        info = provider(ip)
        if info and info.get("province"):
            base.update(info)
            base["ip"] = ip
            return base
    return base


def geolocate_many(ips) -> dict[str, dict]:
    """批量溯源，去重。"""
    result: dict[str, dict] = {}
    for ip in dict.fromkeys(ips):   # 保序去重
        if ip:
            result[ip] = geolocate_ip(ip)
    return result
