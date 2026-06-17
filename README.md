# 哨兵 Sentinel · 网络安全流量分析智能体

一个基于 **DeepSeek + LangGraph** 的网络安全智能体：用户上传**结构化流量日志**或指定**待监测端口**，
智能体自动完成 **攻击检测 → 攻击类型判定 → 攻击者 IP 溯源（至少到省份）→ 生成安全分析报告**。

> 🔒 安全设计：智能体**只分析结构化文本流量日志**，**拒绝直接解析 PCAP 二进制包 / 可执行文件**，
> 从源头规避「文件可能携带恶意载荷」的风险。需要分析 PCAP 时，请先用 `tshark`/`tcpdump` 转成结构化文本。

---

## ✨ 功能特性

| 能力 | 说明 |
| --- | --- |
| 多种输入 | 粘贴日志 / 上传日志文件 / 指定端口（自动抓包） |
| 攻击检测 | SQL 注入、XSS、目录遍历、命令注入、WebShell、端口扫描、暴力破解、CC/DDoS、扫描器指纹等 |
| 攻击溯源 | 攻击者 IP 定位到**省份级**归属地（ip2region 离线库 / 在线 API / 内置演示映射）|
| 安全报告 | 含研判结论、风险等级、时间范围、攻击明细（含 MITRE ATT&CK）、溯源、处置建议，可下载 JSON |
| 智能研判 | DeepSeek 大模型撰写专业研判与建议；**未配置 key 时自动降级为离线规则模式**，功能依旧完整 |
| 抓包双轨 | 真实抓包（scapy / tcpdump，需本机权限）+ 模拟流量（沙箱/演示）|
| 记忆上下文 | 基于 LangGraph checkpointer，按会话维护多轮上下文 |

---

## 🏗️ 架构

```
前端（原生 HTML+JS 单页）
  对话交互 · 文件上传 · 端口输入 · 报告渲染/下载
        │  REST (/api/*)
        ▼
后端（FastAPI）
        │
        ▼
智能体核心（LangGraph 工作流）
  START → triage(意图分流)
            ├─(port)→ capture(抓包) ─┐
            ├─(log) → parse(解析)  ──┤
            │                        ▼
            │                     detect(检测) → geolocate(溯源) → report(报告) → END
            └─(chat)→ respond(对话) → END

  ├─ 提示词/指令     backend/agent/prompts.py
  ├─ 大模型(DeepSeek) backend/agent/llm.py
  ├─ 记忆/上下文      backend/agent/memory.py（checkpointer）
  └─ 工具插件         backend/tools/{capture,parser,detector,geoip,reporter}.py
```

### 目录结构
```
backend/
  main.py            FastAPI 入口与路由（/api/health,/samples,/upload,/analyze）
  config.py          配置（.env）
  schemas.py         Pydantic 数据模型
  agent/
    graph.py         LangGraph 工作流（核心编排）
    state.py         工作流状态
    prompts.py       提示词/指令
    llm.py           DeepSeek 封装（含离线降级）
    memory.py        记忆/上下文（checkpointer）
  tools/
    capture.py       抓包（scapy/tcpdump/模拟）
    parser.py        日志解析归一化（Nginx/CSV/JSON/KV）
    detector.py      攻击检测规则引擎
    geoip.py         IP 溯源（省份级，多源回退）
    reporter.py      报告生成
  data/
    samples/         内置示例日志
    geoip/           内置演示 IP 映射 / ip2region xdb 位置
frontend/            index.html · style.css · app.js
tests/               单元测试
```

---

## 🚀 快速开始

### Windows（推荐）
1. 确保已安装 **Python 3.10+**（安装时勾选 *Add Python to PATH*）。
2. 在项目文件夹里**双击 `run.bat`**，或在终端执行：
   ```bat
   .\run.bat
   ```
   首次运行会自动建虚拟环境、装依赖、生成 `.env` 并启动，随后自动打开 http://localhost:8000 。
   - 也可用 PowerShell：`.\run.ps1`（若提示禁止运行：先执行 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`）。

### Linux / macOS（或 Windows Git Bash）
```bash
./run.sh
# 浏览器打开 http://localhost:8000
```

或手动：
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # 按需填写 DEEPSEEK_API_KEY
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### 配置 DeepSeek（可选但推荐）
在 `.env` 中填入：
```
DEEPSEEK_API_KEY=sk-xxxxxxxx
```
未配置也能完整运行——研判与建议改用内置规则模板（离线模式）。

### 配置 IP 溯源（生产环境）
- **离线（推荐）**：下载 [ip2region.xdb](https://github.com/lionsoul2014/ip2region) 并设置 `IP2REGION_XDB_PATH`，再 `pip install ip2region`。
- **在线**：保持 `GEOIP_ONLINE_ENABLED=true`，需放通 `ip-api.com` 的出网访问。
- 二者皆无时，使用内置演示映射（覆盖示例数据）。

### 真实抓包（生产环境）
在你自己的服务器/电脑上：`pip install scapy`，设置 `CAPTURE_BACKEND=scapy`（或 `tcpdump`），
并以足够权限运行（抓包通常需要 root / CAP_NET_RAW）。云端沙箱无网卡权限，会自动回退到**模拟流量**演示完整流程。

---

## 🧪 测试
```bash
. .venv/bin/activate
python tests/test_pipeline.py      # 或 python -m pytest tests/ -v
```

---

## 📡 API 速览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查与运行模式 |
| GET | `/api/samples` | 列出内置示例日志 |
| POST | `/api/upload` | 上传结构化文本日志（拒绝 pcap/二进制）|
| POST | `/api/analyze` | 核心分析（mode = `log` / `port` / `chat`）|

`/api/analyze` 请求示例：
```json
{ "mode": "log", "thread_id": "u1", "log_content": "113.108.182.66 - - [..] \"GET /p?id=1 UNION SELECT..\" 200 .." }
{ "mode": "port", "thread_id": "u1", "port": 80, "duration": 15 }
```

---

## ⚠️ 合规声明
本工具仅用于**防御性**安全分析与教学。请仅在获得授权的资产上使用，溯源结果（尤其在线/离线库）存在误差，
仅供研判参考，不构成法律证据。
