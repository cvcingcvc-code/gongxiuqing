"""LangGraph 工作流：智能体的核心编排。

   START
     │
   triage ──(chat)──► respond ──► END
     │
     ├─(port)─► capture ─┐
     └─(log)──► parse  ──┤
                         ▼
                       detect ──► geolocate ──► report ──► END

每个节点是一个「工具插件」的调用点；状态通过 checkpointer 持久化形成「记忆」。
"""
from __future__ import annotations

from functools import lru_cache

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph

from ..tools import capture as capture_tool
from ..tools import detector, geoip, parser, reporter
from . import prompts
from .llm import get_llm
from .memory import get_checkpointer
from .state import AgentState


# ----------------- 节点实现 -----------------
def triage_node(state: AgentState) -> dict:
    """意图分流：根据请求决定走端口抓包 / 日志解析 / 普通对话。"""
    target = state.get("target") or {}
    notes = []
    if target.get("port"):
        notes.append(f"识别为【端口监测】模式，目标端口 {target['port']}，准备抓包。")
        return {"input_type": "port", "notes": notes}
    if (state.get("raw_input") or "").strip():
        notes.append("识别为【日志分析】模式，开始解析结构化流量日志。")
        return {"input_type": "log", "notes": notes}
    return {"input_type": "chat", "notes": ["未提供流量数据，进入对话模式。"]}


def capture_node(state: AgentState) -> dict:
    target = state.get("target") or {}
    events, meta = capture_tool.capture_port(
        port=int(target.get("port")),
        iface=target.get("iface"),
        duration=target.get("duration"),
        target_host=target.get("host"),
    )
    note = (f"抓包完成：后端={meta.get('used_backend')}"
            f"{'（沙箱模拟数据）' if meta.get('simulated') else ''}，"
            f"共 {len(events)} 条流量事件。")
    return {"structured_events": events, "capture_meta": meta,
            "notes": state.get("notes", []) + [note]}


def parse_node(state: AgentState) -> dict:
    events, fmt = parser.parse_logs(state.get("raw_input", ""))
    note = (f"日志解析完成：识别格式={fmt}，成功归一化 {len(events)} 条事件。"
            if events else f"未能从输入解析出流量事件（格式={fmt}）。")
    return {"structured_events": events,
            "capture_meta": {"log_format": fmt, "simulated": False},
            "notes": state.get("notes", []) + [note]}


def detect_node(state: AgentState) -> dict:
    events = state.get("structured_events", [])
    findings = detector.detect_attacks(events)
    note = (f"检测引擎完成：命中 {len(findings)} 类攻击特征。"
            if findings else "检测引擎完成：未命中已知攻击特征。")
    return {"findings": findings, "notes": state.get("notes", []) + [note]}


def geolocate_node(state: AgentState) -> dict:
    findings = state.get("findings", [])
    ips = [ip for f in findings for ip in f.get("src_ips", [])]
    geo = geoip.geolocate_many(ips)
    resolved = sum(1 for g in geo.values() if g.get("province"))
    note = f"IP 溯源完成：{resolved}/{len(geo)} 个攻击源解析到省份级归属地。"
    return {"geo_results": geo, "notes": state.get("notes", []) + [note]}


def report_node(state: AgentState) -> dict:
    report = reporter.build_report(
        events=state.get("structured_events", []),
        findings=state.get("findings", []),
        geo_results=state.get("geo_results", {}),
        capture_meta=state.get("capture_meta", {}),
    )
    engine = "DeepSeek 大模型" if report.get("llm_powered") else "内置规则模板（离线模式）"
    msg = (f"✅ 安全分析报告已生成（研判引擎：{engine}）。\n"
           f"研判结论：{report['verdict']}\n风险等级：{report['risk_level']}")
    return {"report": report,
            "messages": [AIMessage(content=msg)],
            "notes": state.get("notes", []) + ["报告生成完成。"]}


def respond_node(state: AgentState) -> dict:
    """对话模式：用大模型回应，无 key 时给出引导语。"""
    llm = get_llm()
    user_msg = ""
    for m in reversed(state.get("messages", [])):
        if getattr(m, "type", "") == "human":
            user_msg = m.content
            break
    if llm:
        try:
            from langchain_core.messages import HumanMessage, SystemMessage

            resp = llm.invoke([
                SystemMessage(content=prompts.SYSTEM_PROMPT),
                SystemMessage(content=prompts.CHAT_PROMPT),
                HumanMessage(content=user_msg or "你好"),
            ])
            return {"messages": [AIMessage(content=resp.content)]}
        except Exception:
            pass
    fallback = ("你好，我是网络安全流量分析智能体「哨兵」。请通过以下任一方式发起分析：\n"
                "1) 粘贴或上传结构化流量日志（Nginx/防火墙/抓包导出的 CSV、JSON、日志文本）；\n"
                "2) 指定要监测的端口（如 80/443），我将抓包后自动分析。\n"
                "出于安全考虑，我不直接解析 PCAP 二进制包，请先转换为结构化文本。")
    return {"messages": [AIMessage(content=fallback)]}


# ----------------- 路由 -----------------
def route_after_triage(state: AgentState) -> str:
    return {"port": "capture", "log": "parse"}.get(state.get("input_type"), "respond")


# ----------------- 构建图 -----------------
@lru_cache(maxsize=1)
def get_graph():
    g = StateGraph(AgentState)
    g.add_node("triage", triage_node)
    g.add_node("capture", capture_node)
    g.add_node("parse", parse_node)
    g.add_node("detect", detect_node)
    g.add_node("geolocate", geolocate_node)
    g.add_node("report", report_node)
    g.add_node("respond", respond_node)

    g.add_edge(START, "triage")
    g.add_conditional_edges("triage", route_after_triage,
                            {"capture": "capture", "parse": "parse", "respond": "respond"})
    g.add_edge("capture", "detect")
    g.add_edge("parse", "detect")
    g.add_edge("detect", "geolocate")
    g.add_edge("geolocate", "report")
    g.add_edge("report", END)
    g.add_edge("respond", END)

    return g.compile(checkpointer=get_checkpointer())
