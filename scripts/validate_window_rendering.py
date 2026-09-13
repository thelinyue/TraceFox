"""验证窗口在尺寸、焦点和多显示器位置变化后仍能完整重绘。"""

import json
import os
import site
import subprocess
import tempfile
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
deps = root / "validation/python_deps"
site.addsitedir(str(deps))
import sys

sys.path.extend([str(deps / "win32"), str(deps / "win32/lib")])
os.add_dll_directory(str(deps / "pywin32_system32"))

from pywinauto import Desktop
import win32api
import win32con
import win32gui

out = root / "target/window-rendering-validation"
out.mkdir(parents=True, exist_ok=True)


def button(window, name):
    matches = [
        control
        for control in window.descendants(control_type="Button")
        if control.window_text() == name and control.is_visible()
    ]
    assert matches, f"找不到按钮：{name}"
    return matches[-1]


def move_to_monitor(window, monitor):
    work = win32api.GetMonitorInfo(monitor)["Work"]
    left, top, right, bottom = work
    width = min(window.rectangle().width(), right - left - 40)
    height = min(window.rectangle().height(), bottom - top - 40)
    win32gui.MoveWindow(window.handle, left + 20, top + 20, width, height, True)
    time.sleep(0.6)


def assert_rendered(window, label):
    image = window.capture_as_image().convert("RGB")
    extrema = image.getextrema()
    assert any(high - low > 12 for low, high in extrema), f"{label}截图接近空白"
    assert any(
        control.is_visible() and control.is_enabled()
        for control in window.descendants(control_type="Button")
    ), f"{label}没有可见按钮"


def check_window(window, label, monitors):
    for index, monitor in enumerate(monitors):
        move_to_monitor(window, monitor)
        assert_rendered(window, f"{label} 显示器 {index + 1}")
        window.capture_as_image().save(str(out / f"{label}-{index + 1}.png"))
    # 即使测试机只有一个显示器，也覆盖一次尺寸变化和重绘路径。
    bounds = window.rectangle()
    win32gui.MoveWindow(window.handle, bounds.left, bounds.top, bounds.width() + 20, bounds.height() + 20, True)
    time.sleep(0.6)
    assert_rendered(window, f"{label} 调整尺寸后")


monitors = [handle for handle, _, _ in win32api.EnumDisplayMonitors()]
proc = None
try:
    with tempfile.TemporaryDirectory(prefix="tracefox-window-rendering-") as folder:
        profile = Path(folder) / "profile"
        (profile / "TraceFox").mkdir(parents=True)
        (profile / "TraceFox/settings.json").write_text(
            json.dumps({"directory": "", "watching": False}), encoding="utf-8"
        )
        proc = subprocess.Popen(
            [str(root / "target/debug/TraceFox.exe")],
            env=dict(os.environ, LOCALAPPDATA=str(profile)),
        )
        app = Desktop(backend="uia").window(title="TraceFox", process=proc.pid)
        app.wait("visible", timeout=30)
        check_window(app, "main", monitors)

        button(app, "关键词与报告规则").invoke()
        editor = Desktop(backend="uia").window(
            title="TraceFox · 规则编辑", process=proc.pid
        )
        editor.wait("visible", timeout=15)
        check_window(editor, "editor", monitors)

        button(editor, "系统信息").invoke()
        button(editor, "套用参考配置").invoke()
        preview = Desktop(backend="uia").window(
            title="TraceFox · 导入预览", process=proc.pid
        )
        preview.wait("visible", timeout=15)
        check_window(preview, "import", monitors)
        print(
            f"PASS 窗口重绘：检查 {len(monitors)} 个显示器，主窗口/规则编辑/导入预览均通过",
            flush=True,
        )
finally:
    if proc is not None:
        proc.terminate()
        proc.wait(timeout=10)
