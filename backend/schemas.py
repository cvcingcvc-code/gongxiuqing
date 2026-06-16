"""Pydantic 数据模型：贯穿前后端的请求/响应结构。"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class TrafficEvent(BaseModel):
    """归一化后的单条流量事件（来自日志解析或抓包）。"""

    timestamp: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None
    host: Optional[str] = None
    status: Optional[int] = None
    user_agent: Optional[str] = None
    bytes: Optional[int] = None
    flags: Optional[str] = None
    raw: Optional[str] = None


class Finding(BaseModel):
    """检测引擎产出的一条攻击发现。"""

    type: str                      # 中文攻击类型，如「SQL 注入」
    type_en: str                   # 英文标识，如 sql_injection
    severity: Literal["critical", "high", "medium", "low", "info"]
    src_ips: list[str] = Field(default_factory=list)
    dst_ports: list[int] = Field(default_factory=list)
    count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: str = ""
    mitre: Optional[str] = None    # MITRE ATT&CK 技术编号
    evidence: list[str] = Field(default_factory=list)  # 代表性原始证据


class GeoInfo(BaseModel):
    ip: str
    is_private: bool = False
    country: Optional[str] = None
    province: Optional[str] = None   # 省份（至少溯源到此级别）
    city: Optional[str] = None
    isp: Optional[str] = None
    source: str = "unknown"          # 数据来源：ip2region/online/demo/private


class AnalyzeRequest(BaseModel):
    """从前端发起的分析请求。"""

    mode: Literal["log", "port", "chat"] = "log"
    thread_id: str = "default"
    message: Optional[str] = None        # 用户自然语言指令
    log_content: Optional[str] = None    # 直接粘贴的日志文本
    upload_id: Optional[str] = None      # 已上传文件 id
    # 端口监测模式
    port: Optional[int] = None
    iface: Optional[str] = None
    duration: Optional[int] = None
    target_host: Optional[str] = None


class Report(BaseModel):
    """最终安全分析报告。"""

    report_id: str
    generated_at: str
    verdict: str                    # 总体研判结论
    risk_level: str                 # 风险等级
    attack_detected: bool
    summary: str                    # 智能体撰写的概述
    time_range: dict[str, Optional[str]] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    attacker_origins: list[GeoInfo] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    llm_powered: bool = False       # 是否由大模型生成研判
