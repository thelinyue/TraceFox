"""在隔离目录验证安装、规则草稿、升级与卸载；不读取真实诊断包或个人设置。"""
import io
import json
import os
from pathlib import Path
import site
import subprocess
import sys
import tarfile
import time

root = Path(__file__).resolve().parents[1]
deps = root / "validation/python_deps"
site.addsitedir(str(deps))
sys.path.extend([str(deps / "win32"), str(deps / "win32/lib")])
os.add_dll_directory(str(deps / "pywin32_system32"))
from pywinauto import Desktop

sys.stdout.reconfigure(encoding="utf-8")
folder = root / "validation/release-0.0.1/install"
folder.mkdir(parents=True, exist_ok=True)
installer = Path(sys.argv[1]).resolve()
exe = folder / "TraceFox.exe"
rules_path = folder / "assets/default-rules.json"
env = os.environ.copy()
env["LOCALAPPDATA"] = str(folder / "profile")
env["SLINT_SCALE_FACTOR"] = "1"


def install():
    subprocess.run([str(installer), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                    "/NOICONS", f"/DIR={folder}", f"/LOG={folder / 'setup.log'}"], check=True)
    assert exe.is_file() and rules_path.is_file()


def click(window, name):
    buttons = [b for b in window.descendants(control_type="Button")
               if b.window_text() == name and b.is_visible() and b.is_enabled()]
    assert buttons, name
    buttons[-1].invoke()
    time.sleep(0.3)


def check_authored_values(saved, authored):
    # Rust 会补全默认字段，因此逐项核对内置文件明确提供的值。
    if isinstance(authored, dict):
        for key, value in authored.items():
            check_authored_values(saved[key], value)
    elif isinstance(authored, list):
        assert len(saved) == len(authored)
        for actual, expected in zip(saved, authored):
            check_authored_values(actual, expected)
    else:
        assert saved == authored


def launch_editor():
    proc = subprocess.Popen([str(exe)], env=env, cwd=folder)
    app = Desktop(backend="uia").window(title="TraceFox", process=proc.pid)
    app.wait("visible", timeout=15)
    click(app, "关键词与报告规则")
    editor = Desktop(backend="uia").window(title="TraceFox · 规则编辑", process=proc.pid)
    editor.wait("visible", timeout=15)
    Desktop(backend="win32").window(handle=editor.handle).move_window(x=10, y=10, width=1100, height=740)
    return proc, editor


install()
custom = json.loads(rules_path.read_text(encoding="utf-8"))
custom["rules"][0]["name"] = "安装验证自定义规则"
rules_path.write_text(json.dumps(custom, ensure_ascii=False), encoding="utf-8")
before = rules_path.read_bytes()
proc, editor = launch_editor()
try:
    click(editor, "还原默认规则")
    assert rules_path.read_bytes() == before, "还原不应立即落盘"
    click(editor, "取消")
    assert rules_path.read_bytes() == before, "取消应保留原规则"
finally:
    proc.terminate()
    proc.wait(timeout=10)

proc, editor = launch_editor()
try:
    click(editor, "还原默认规则")
    click(editor, "保存全部")
    editor.wait_not("visible", timeout=10)
    defaults = json.loads((root / "assets/default-rules.json").read_text(encoding="utf-8"))
    saved = json.loads(rules_path.read_text(encoding="utf-8"))
    check_authored_values(saved, defaults)
finally:
    proc.terminate()
    proc.wait(timeout=10)

proc, editor = launch_editor()
try:
    assert proc.poll() is None, "保存后应可正常重新启动"
    click(editor, "取消")
finally:
    proc.terminate()
    proc.wait(timeout=10)

# 只使用生成的最小 TGZ，验证安装产物能完成真实分析路径。
sample = folder / "sample.tgz"
with tarfile.open(sample, "w:gz") as archive:
    payload = b"Linux version 6.1.0\n"
    entry = tarfile.TarInfo("log/syslog")
    entry.size = len(payload)
    archive.addfile(entry, io.BytesIO(payload))
subprocess.run([str(exe), "--analyze", str(sample)], env=env, check=True)
assert (folder / "sample/report.html").is_file()

rules_path.write_bytes(before)
install()
assert rules_path.read_bytes() == before, "升级应保留自定义规则"
subprocess.run([str(folder / "unins000.exe"), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"], check=True)
for _ in range(50):
    if not exe.exists():
        break
    time.sleep(0.2)
assert not exe.exists(), "卸载应移除主程序"
assert rules_path.read_bytes() == before, "卸载应保留规则"
result = dict(install=True, restore_cancel=True, restore_save=True, restart=True,
              analyze=True, upgrade_preserves_rules=True, uninstall_preserves_rules=True)
(folder.parent / "installer.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps(result))
