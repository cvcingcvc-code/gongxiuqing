"""FastAPI 服务入口：API 路由 + 静态前端托管。"""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from langchain_core.messages import HumanMessage

from . import config
from .agent.graph import get_graph
from .agent.llm import llm_available
from .agent.memory import thread_config
from .schemas import AnalyzeRequest

app = FastAPI(title="哨兵 · 网络安全流量分析智能体", version="1.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

FRONTEND_DIR = config.ROOT_DIR / "frontend"


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "llm": "DeepSeek 已接入" if llm_available() else "离线规则模式（未配置 DEEPSEEK_API_KEY）",
        "llm_available": llm_available(),
        "capture_backend": config.CAPTURE_BACKEND,
        "geoip_online": config.GEOIP_ONLINE_ENABLED,
    }


@app.get("/api/samples")
def list_samples():
    """列出内置示例日志，便于前端一键体验。"""
    out = []
    if config.SAMPLE_DIR.exists():
        for p in sorted(config.SAMPLE_DIR.glob("*")):
            if p.is_file():
                out.append({"id": p.name, "name": p.name,
                            "size": p.stat().st_size})
    return {"samples": out}


@app.get("/api/samples/{name}")
def get_sample(name: str):
    path = (config.SAMPLE_DIR / name).resolve()
    if not str(path).startswith(str(config.SAMPLE_DIR.resolve())) or not path.is_file():
        raise HTTPException(404, "示例不存在")
    return {"name": name, "content": path.read_text(encoding="utf-8", errors="replace")}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    """上传结构化文本日志。明确拒绝 PCAP/二进制，规避文件带毒风险。"""
    suffix = Path(file.filename or "").suffix.lower()
    if suffix in config.BLOCKED_SUFFIXES:
        raise HTTPException(
            400,
            f"出于安全考虑，智能体不接收 {suffix} 二进制/可执行文件（可能包含恶意载荷）。"
            "请先用 `tshark -r x.pcap -T fields -e ...` 或 `tcpdump -nn -r x.pcap` "
            "将其转换为结构化文本日志后再上传。",
        )
    if suffix not in config.ALLOWED_LOG_SUFFIXES:
        raise HTTPException(
            400, f"仅支持结构化文本日志：{', '.join(sorted(config.ALLOWED_LOG_SUFFIXES))}")
    data = await file.read()
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(400, "文件过大（上限 20MB）。")
    # 二次校验：内容必须是可解码文本，杜绝伪装后缀的二进制
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("gbk")
        except UnicodeDecodeError:
            raise HTTPException(400, "文件内容非文本，疑似二进制，已拒绝。")
    upload_id = f"{uuid.uuid4().hex}{suffix}"
    (config.UPLOAD_DIR / upload_id).write_text(text, encoding="utf-8")
    preview = "\n".join(text.splitlines()[:8])
    return {"upload_id": upload_id, "filename": file.filename,
            "lines": len(text.splitlines()), "preview": preview}


def _read_upload(upload_id: str) -> str:
    path = (config.UPLOAD_DIR / upload_id).resolve()
    if not str(path).startswith(str(config.UPLOAD_DIR.resolve())) or not path.is_file():
        raise HTTPException(404, "上传文件不存在或已过期。")
    return path.read_text(encoding="utf-8", errors="replace")


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    """核心分析入口：构造工作流输入并运行 LangGraph。"""
    raw_input = ""
    target: dict = {}

    if req.mode == "port":
        if not req.port:
            raise HTTPException(400, "端口监测模式需提供 port。")
        target = {"port": req.port, "iface": req.iface,
                  "duration": req.duration, "host": req.target_host}
    elif req.mode == "log":
        if req.upload_id:
            raw_input = _read_upload(req.upload_id)
        elif req.log_content:
            raw_input = req.log_content
        else:
            raise HTTPException(400, "日志模式需提供 log_content 或 upload_id。")

    user_text = req.message or (
        f"请监测端口 {req.port} 的流量并分析是否存在攻击。" if req.mode == "port"
        else "请分析这批流量日志是否存在攻击。" if req.mode == "log"
        else "")

    state_in = {
        "messages": [HumanMessage(content=user_text)] if user_text else [],
        "raw_input": raw_input,
        "target": target,
        "notes": [],
    }
    graph = get_graph()
    try:
        result = graph.invoke(state_in, config=thread_config(req.thread_id))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"分析过程出错：{e}")

    reply = ""
    for m in reversed(result.get("messages", [])):
        if getattr(m, "type", "") == "ai":
            reply = m.content
            break

    return JSONResponse({
        "input_type": result.get("input_type"),
        "reply": reply,
        "notes": result.get("notes", []),
        "report": result.get("report"),
        "event_count": len(result.get("structured_events", [])),
    })


# ---- 前端静态托管（放在最后，避免覆盖 /api 路由）----
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def index():
        return FileResponse(str(FRONTEND_DIR / "index.html"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host=config.APP_HOST, port=config.APP_PORT, reload=False)
