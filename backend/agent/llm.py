"""DeepSeek 大模型封装（OpenAI 兼容接口）。

设计要点：未配置 API Key 时返回 None，全流程降级为「离线规则模式」，
保证没有 key 也能完整跑通检测/溯源/报告。
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Optional

from .. import config


@lru_cache(maxsize=1)
def get_llm():
    """返回可用的 ChatOpenAI（指向 DeepSeek），未配置则返回 None。"""
    if not config.LLM_ENABLED:
        return None
    try:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=config.DEEPSEEK_MODEL,
            api_key=config.DEEPSEEK_API_KEY,
            base_url=config.DEEPSEEK_BASE_URL,
            temperature=0.2,
            timeout=60,
            max_retries=2,
        )
    except Exception:
        return None


def llm_available() -> bool:
    return get_llm() is not None


def extract_json(text: str) -> Optional[dict]:
    """从模型输出中稳健地抽取 JSON 对象（容忍 ```json 代码块、前后缀文字）。"""
    if not text:
        return None
    # 去掉代码块围栏
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        brace = re.search(r"\{.*\}", text, re.DOTALL)
        candidate = brace.group(0) if brace else None
    if candidate is None:
        return None
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None
