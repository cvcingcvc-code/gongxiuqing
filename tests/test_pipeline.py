"""核心流程单元测试（离线，无需 DeepSeek key 即可运行）。

运行：  . .venv/bin/activate && python -m pytest tests/ -v
或：    python tests/test_pipeline.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.tools import detector, geoip, parser, reporter  # noqa: E402


def test_parse_nginx():
    log = '1.2.3.4 - - [15/Jun/2026:10:21:07 +0800] "GET /a?id=1 HTTP/1.1" 200 100 "-" "curl/8"'
    events, fmt = parser.parse_logs(log)
    assert fmt == "nginx"
    assert events[0]["src_ip"] == "1.2.3.4"
    assert events[0]["status"] == 200


def test_parse_csv():
    csv = "timestamp,src_ip,dst_port,protocol\n2026-01-01T00:00:00,9.9.9.9,22,TCP"
    events, fmt = parser.parse_logs(csv)
    assert fmt == "csv"
    assert events[0]["src_ip"] == "9.9.9.9"
    assert events[0]["dst_port"] == 22


def test_detect_sql_injection():
    log = '1.1.1.1 - - [15/Jun/2026:10:00:00 +0800] "GET /p?id=1 UNION SELECT password FROM users-- HTTP/1.1" 200 1 "-" "x"'
    events, _ = parser.parse_logs(log)
    findings = detector.detect_attacks(events)
    types = {f["type_en"] for f in findings}
    assert "sql_injection" in types


def test_detect_port_scan():
    rows = ["timestamp,src_ip,dst_port,protocol,flags"]
    for p in range(1, 30):
        rows.append(f"2026-06-15T03:05:0{p % 10},5.5.5.5,{p},TCP,S")
    events, _ = parser.parse_logs("\n".join(rows))
    findings = detector.detect_attacks(events)
    assert any(f["type_en"] == "port_scan" for f in findings)


def test_detect_brute_force():
    lines = []
    for i in range(10):
        lines.append(f'7.7.7.7 - - [15/Jun/2026:02:11:0{i} +0800] "POST /admin/login HTTP/1.1" 401 1 "-" "x"')
    events, _ = parser.parse_logs("\n".join(lines))
    findings = detector.detect_attacks(events)
    assert any(f["type_en"] == "brute_force" for f in findings)


def test_geolocate_private_and_demo():
    g = geoip.geolocate_ip("10.0.0.1")
    assert g["is_private"] is True
    g2 = geoip.geolocate_ip("113.108.182.66")  # 在内置演示映射中
    assert g2["province"] == "广东省"


def test_build_report_offline():
    log = '1.1.1.1 - - [15/Jun/2026:10:00:00 +0800] "GET /p?id=1 UNION SELECT a FROM b-- HTTP/1.1" 200 1 "-" "sqlmap"'
    events, _ = parser.parse_logs(log)
    findings = detector.detect_attacks(events)
    geo = geoip.geolocate_many([ip for f in findings for ip in f["src_ips"]])
    report = reporter.build_report(events, findings, geo)
    assert report["attack_detected"] is True
    assert report["risk_level"] in {"严重", "高危", "中危", "低危"}
    assert report["recommendations"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
