"""对隔离样本副本测量正式处理链，保存分阶段耗时、内存和完整报告数据。"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'validation/python_deps'))
import psutil

parser = argparse.ArgumentParser()
parser.add_argument('runner', type=Path, help='Release performance 测试可执行文件')
parser.add_argument('sample', type=Path)
parser.add_argument('output', type=Path, help='新的隔离输出目录')
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
results = []
for repeat in range(3):
    folder = args.output / str(repeat)
    folder.mkdir()
    archive = folder / args.sample.name
    shutil.copyfile(args.sample, archive)
    for mode in ('fresh', 'overwrite'):
        env = dict(os.environ, TRACEFOX_PERF_PACKAGE=str(archive.resolve()))
        log = folder / f'{mode}.log'
        with log.open('wb') as stream:
            proc = subprocess.Popen([str(args.runner.resolve()), '--ignored', '--nocapture'],
                                    env=env, stdout=stream, stderr=subprocess.STDOUT)
            process = psutil.Process(proc.pid)
            peak = 0
            while proc.poll() is None:
                try:
                    info = process.memory_info()
                    peak = max(peak, getattr(info, 'peak_wset', info.rss))
                except psutil.NoSuchProcess:
                    pass
                time.sleep(0.01)
        if proc.returncode:
            raise RuntimeError(log.read_text(encoding='utf-8'))
        measurement = next(line[5:] for line in log.read_text(encoding='utf-8').splitlines()
                           if line.startswith('PERF '))
        result = dict(json.loads(measurement), repeat=repeat, mode=mode, peak_mb=peak/1048576)
        html = (archive.with_suffix('') / 'report.html').read_text(encoding='utf-8')
        report, _ = json.JSONDecoder().raw_decode(html.split('const report=', 1)[1])
        report.pop('generated')
        (folder / f'{mode}-report.json').write_text(json.dumps(report, ensure_ascii=False), encoding='utf-8')
        results.append(result)
        (args.output / 'measurements.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
        print(json.dumps(result), flush=True)
