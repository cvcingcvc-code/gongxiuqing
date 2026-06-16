"""全局配置：从环境变量 / .env 读取。"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# 项目根目录
ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")

# 数据目录
DATA_DIR = ROOT_DIR / "backend" / "data"
SAMPLE_DIR = DATA_DIR / "samples"
UPLOAD_DIR = DATA_DIR / "uploads"
CAPTURE_DIR = DATA_DIR / "captures"
GEOIP_DIR = DATA_DIR / "geoip"
for _d in (UPLOAD_DIR, CAPTURE_DIR, GEOIP_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def _get_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


# ---- DeepSeek ----
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "").strip()
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1").strip()
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip()
LLM_ENABLED = bool(DEEPSEEK_API_KEY)

# ---- GeoIP ----
GEOIP_ONLINE_ENABLED = _get_bool("GEOIP_ONLINE_ENABLED", True)
IP2REGION_XDB_PATH = os.getenv("IP2REGION_XDB_PATH", "").strip()

# ---- 抓包 ----
CAPTURE_BACKEND = os.getenv("CAPTURE_BACKEND", "auto").strip().lower()
CAPTURE_IFACE = os.getenv("CAPTURE_IFACE", "").strip() or None
CAPTURE_TIMEOUT = int(os.getenv("CAPTURE_TIMEOUT", "15"))
CAPTURE_MAX_PACKETS = int(os.getenv("CAPTURE_MAX_PACKETS", "2000"))

# ---- 服务 ----
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", "8000"))

# 允许上传的结构化文本日志后缀；明确不接收 .pcap/.pcapng 二进制包
ALLOWED_LOG_SUFFIXES = {".log", ".txt", ".csv", ".json", ".jsonl", ".ndjson"}
BLOCKED_SUFFIXES = {".pcap", ".pcapng", ".cap", ".exe", ".bin", ".dll", ".sh", ".dmp"}
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20MB
