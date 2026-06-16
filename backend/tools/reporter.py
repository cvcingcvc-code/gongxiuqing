"""报告生成工具：汇总检测/溯源结果，产出安全分析报告。

研判与建议优先由 DeepSeek 生成；无 key 时回退到内置模板，保证完整可用。
"""
from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import datetime

from ..agent import prompts
from ..agent.llm import extract_json, get_llm

_RISK_BY_SEVERITY = {
    "critical": "严重", "high": "高危", "medium": "中危",
    "low": "低危", "info": "无明显风险",
}

# 各攻击类型的兜底处置建议（离线模式使用）
_REMEDIATION = {
    "sql_injection": "对所有数据库查询使用参数化/预编译语句；部署 WAF 拦截 SQL 注入特征；最小化数据库账号权限。",
    "xss": "对用户输入做输出编码与 CSP 策略；过滤危险标签与事件属性；对 Cookie 启用 HttpOnly。",
    "path_traversal": "对文件路径做白名单校验与规范化；禁止 ../ 等穿越序列；限制 Web 进程的文件系统权限。",
    "command_injection": "禁止将用户输入拼接进系统命令；使用安全 API；对参数做严格白名单校验。",
    "webshell": "排查并清除可疑脚本文件；限制上传目录执行权限；核查近期文件变更与登录记录。",
    "scanner_tool": "在边界封禁来源 IP；启用速率限制与 Bot 防护；隐藏服务指纹信息。",
    "sensitive_path_probe": "移除/保护 .git、.env、备份等敏感文件；对管理后台做 IP 白名单与强认证。",
    "port_scan": "在防火墙限制对外暴露端口；启用 IDS/IPS 告警；对扫描源 IP 进行封禁或限速。",
    "brute_force": "启用账户锁定与登录失败限速；强制强密码与多因素认证；封禁高频失败来源 IP。",
    "dos_cc": "启用限流与人机校验；接入抗 D/CDN；对异常高频来源做自动封禁。",
}


def _time_range(events: list[dict]) -> dict:
    ts = [e.get("timestamp") for e in events if e.get("timestamp")]
    ts = sorted(str(t) for t in ts)
    return {"start": ts[0] if ts else None, "end": ts[-1] if ts else None}


def _build_stats(events, findings, geo_results) -> dict:
    src_counter = Counter(e.get("src_ip") for e in events if e.get("src_ip"))
    return {
        "total_events": len(events),
        "unique_src_ips": len(src_counter),
        "finding_count": len(findings),
        "attack_types": sorted({f["type"] for f in findings}),
        "top_sources": src_counter.most_common(5),
        "geo_resolved": sum(1 for g in geo_results.values() if g.get("province")),
    }


def _template_narrative(findings, geo_results, stats) -> dict:
    """无大模型时的兜底研判。"""
    if not findings:
        return {
            "verdict": "未在所提供的流量中发现明显攻击特征。",
            "risk_level": "无明显风险",
            "summary": f"共分析 {stats['total_events']} 条流量事件、{stats['unique_src_ips']} 个来源 IP，"
                       "规则引擎未命中已知攻击特征或异常行为阈值。建议持续监测。",
            "recommendations": ["保持日志留存与定期审计。", "持续监测异常流量与登录行为。"],
        }
    top_sev = findings[0]["severity"]
    types = "、".join(sorted({f["type"] for f in findings}))
    # 攻击者归属地
    origins = []
    for g in geo_results.values():
        if g.get("province") and not g.get("is_private"):
            loc = "".join(filter(None, [g.get("country"), g.get("province"), g.get("city")]))
            origins.append(f"{g['ip']}（{loc}）")
    origin_text = "；".join(origins[:5]) if origins else "暂未解析到公网归属地"
    recs = []
    for f in findings:
        rec = _REMEDIATION.get(f["type_en"])
        if rec and rec not in recs:
            recs.append(rec)
    recs.append("封禁/限速上述攻击来源 IP，并留存证据用于追溯。")
    return {
        "verdict": f"检测到 {types} 等攻击行为，研判为真实攻击。",
        "risk_level": _RISK_BY_SEVERITY.get(top_sev, "中危"),
        "summary": f"在 {stats['total_events']} 条流量中命中 {len(findings)} 类攻击特征（{types}）。"
                   f"主要攻击来源：{origin_text}。请尽快按建议处置。",
        "recommendations": recs[:6],
    }


def _llm_narrative(findings, geo_results, stats):
    llm = get_llm()
    if not llm:
        return None
    try:
        from langchain_core.messages import HumanMessage, SystemMessage

        msg = prompts.VERDICT_PROMPT.format(
            stats=json.dumps(stats, ensure_ascii=False, default=str),
            findings=json.dumps(findings, ensure_ascii=False)[:6000],
            geo=json.dumps(list(geo_results.values()), ensure_ascii=False)[:3000],
        )
        resp = llm.invoke([
            SystemMessage(content=prompts.SYSTEM_PROMPT),
            HumanMessage(content=msg),
        ])
        data = extract_json(resp.content)
        if data and data.get("verdict"):
            return data
    except Exception:
        return None
    return None


def build_report(events, findings, geo_results, capture_meta=None) -> dict:
    stats = _build_stats(events, findings, geo_results)
    narrative = _llm_narrative(findings, geo_results, stats)
    llm_powered = narrative is not None
    if narrative is None:
        narrative = _template_narrative(findings, geo_results, stats)

    attacker_origins = []
    attacker_ips = {ip for f in findings for ip in f.get("src_ips", [])}
    for ip in attacker_ips:
        g = geo_results.get(ip)
        if g:
            attacker_origins.append(g)

    report = {
        "report_id": f"SENTINEL-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:6].upper()}",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "verdict": narrative.get("verdict", ""),
        "risk_level": narrative.get("risk_level", "未知"),
        "attack_detected": bool(findings),
        "summary": narrative.get("summary", ""),
        "time_range": _time_range(events),
        "findings": findings,
        "attacker_origins": attacker_origins,
        "recommendations": narrative.get("recommendations", []),
        "stats": stats,
        "llm_powered": llm_powered,
        "capture_meta": capture_meta or {},
    }
    return report
