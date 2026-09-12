"""本地验收：逐包运行真实 EXE，保存性能与规则输出统计，不上传诊断内容。"""
import argparse
import json
import pathlib
import subprocess
import time

import psutil

parser = argparse.ArgumentParser()
parser.add_argument("samples", type=pathlib.Path)
parser.add_argument("--exe", type=pathlib.Path, default=pathlib.Path("target/release/TraceFox.exe"))
parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("validation/samples.json"))
args = parser.parse_args()
args.output.parent.mkdir(parents=True, exist_ok=True)
results = []
for archive in sorted(args.samples.glob("*.tgz")):
    started = time.monotonic()
    with (args.output.parent / (archive.stem + ".log")).open("wb") as log:
        proc = subprocess.Popen([str(args.exe.resolve()), "--analyze", str(archive)], stdout=log, stderr=log)
        peak = 0
        process = psutil.Process(proc.pid)
        while proc.poll() is None:
            try:
                info = process.memory_info()
                peak = max(peak, getattr(info, "peak_wset", info.rss))
            except psutil.NoSuchProcess:
                pass
            time.sleep(0.1)
    result = {"package": archive.name, "exit": proc.returncode, "seconds": round(time.monotonic()-started, 2), "peak_mb": round(peak/1048576, 1)}
    html = archive.with_suffix("") / "report.html"
    if proc.returncode == 0:
        text = html.read_text(encoding="utf-8")
        report, _ = json.JSONDecoder().raw_decode(text.split("const report=", 1)[1])
        result.update(report_mb=round(html.stat().st_size/1048576, 2), events=len(report["events"]), hits=sum(f["count"] for f in report["findings"]), system_rows={t["id"]:len(t["rows"]) for t in report["system"]}, warnings=report["warnings"])
    results.append(result)
    args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True), flush=True)
if any(result["exit"] != 0 for result in results):
    raise SystemExit(1)
