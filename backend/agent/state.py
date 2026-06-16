"""LangGraph 工作流状态定义。

状态在各节点之间流转，并通过 checkpointer 持久化，实现「记忆/上下文」。
"""
from __future__ import annotations

from typing import Annotated, Any, Optional, TypedDict

from langgraph.graph.message import add_messages


class AgentState(TypedDict, total=False):
    # 对话历史（记忆）：add_messages 负责增量合并
    messages: Annotated[list, add_messages]

    # 路由与意图
    input_type: str               # "port" | "log" | "chat"
    target: dict[str, Any]        # {port, host, iface, duration, ...}

    # 数据
    raw_input: str                # 原始日志文本 / 抓包产出
    structured_events: list[dict] # 归一化流量事件
    capture_meta: dict[str, Any]  # 抓包元信息（后端、是否模拟等）

    # 分析结果
    findings: list[dict]          # 攻击发现
    geo_results: dict[str, dict]  # ip -> GeoInfo
    report: dict[str, Any]        # 最终报告

    # 控制
    error: Optional[str]
    notes: list[str]              # 执行过程中的提示/日志（回显给前端）
