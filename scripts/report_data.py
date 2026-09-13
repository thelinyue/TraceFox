"""读取 TraceFox 新旧离线报告中的完整 JSON 数据。"""

import base64
import gzip
import json
from pathlib import Path


PAYLOAD_PREFIX = "gzip-base64-v1:"


def loads_report_html(html: str):
    """兼容 Gzip Base64 报告、未压缩测试夹具和历史报告。"""
    marker = "const reportPayload="
    if marker in html:
        payload, _ = json.JSONDecoder().raw_decode(html.split(marker, 1)[1])
        if isinstance(payload, dict):
            return payload
        if not isinstance(payload, str) or not payload.startswith(PAYLOAD_PREFIX):
            raise ValueError("报告数据格式不受支持")
        encoded = payload[len(PAYLOAD_PREFIX) :]
        try:
            compressed = base64.b64decode(encoded, validate=True)
            return json.loads(gzip.decompress(compressed).decode("utf-8"))
        except (ValueError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"报告数据解压或解析失败：{error}") from error

    legacy_marker = "const report="
    if legacy_marker in html:
        report, _ = json.JSONDecoder().raw_decode(html.split(legacy_marker, 1)[1])
        return report
    raise ValueError("没有找到 TraceFox 报告数据")


def load_report(path: Path):
    return loads_report_html(path.read_text(encoding="utf-8"))
