"""记忆 / 上下文：基于 LangGraph checkpointer。

按 thread_id 维护多轮对话与分析上下文。默认使用内存型 checkpointer；
如需持久化，可替换为 SqliteSaver（见文末说明）。
"""
from __future__ import annotations

from functools import lru_cache

from langgraph.checkpoint.memory import MemorySaver


@lru_cache(maxsize=1)
def get_checkpointer():
    """全局唯一的 checkpointer，保证同一进程内 thread 记忆一致。"""
    return MemorySaver()


def thread_config(thread_id: str) -> dict:
    """构造 LangGraph 调用所需的线程配置。"""
    return {"configurable": {"thread_id": thread_id or "default"}}


# 持久化方案（可选）：
#   from langgraph.checkpoint.sqlite import SqliteSaver
#   return SqliteSaver.from_conn_string("backend/data/memory.sqlite")
# 即可让对话/分析记忆在重启后依然保留。
