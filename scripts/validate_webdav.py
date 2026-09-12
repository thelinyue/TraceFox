"""在隔离配置、临时系统凭据及本地 HTTP 服务中验收 WebDAV 弹窗。"""
import base64
import json
import os
from pathlib import Path
import site
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.stdout.reconfigure(encoding="utf-8")
root = Path(__file__).resolve().parents[1]
deps = root / "validation/python_deps"
site.addsitedir(str(deps))
sys.path.extend([str(deps / "win32"), str(deps / "win32/lib")])
os.add_dll_directory(str(deps / "pywin32_system32"))
from pywinauto import Desktop
import win32cred

out = root / "target/webdav-validation"
out.mkdir(parents=True, exist_ok=True)
requests = []
response = {"status": 200, "delay": 0}
remote_rules = json.loads((root / "assets/default-rules.json").read_text(encoding="utf-8"))

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = json.dumps(remote_rules).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_HEAD(self):
        requests.append((self.command, self.path, self.headers.get("Authorization")))
        delay, status = response["delay"], response["status"]
        time.sleep(delay)
        self.send_response(status)
        self.end_headers()
    def log_message(self, *args):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{server.server_port}/dav/"
keys = [url + "#rules.json", url + "#other.json"]

def controls(e, kind):
    return [c for c in e.descendants(control_type=kind) if c.is_visible() and c.is_enabled() and c.rectangle().width() > 0]

def button(e, name):
    return [c for c in controls(e, "Button") if c.window_text() == name][-1]

def click(e, name):
    button(e, name).invoke()
    time.sleep(.2)

def edit(e, i, value):
    controls(e, "Edit")[i].set_edit_text(value)

def texts(e):
    return "\n".join(c.window_text() for c in e.descendants(control_type="Text") if c.is_visible())

def wait_for(test, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if test():
            return
        time.sleep(.1)
    raise AssertionError("等待界面状态超时")

def credential(key):
    try:
        return win32cred.CredRead(key, win32cred.CRED_TYPE_GENERIC)["CredentialBlob"]
    except Exception as error:
        if error.winerror == 1168:
            return None
        raise

proc = None
try:
    with tempfile.TemporaryDirectory(prefix="tracefox-webdav-") as profile:
        env = os.environ.copy()
        env["LOCALAPPDATA"] = profile
        env["SLINT_SCALE_FACTOR"] = "1"
        settings = Path(profile) / "TraceFox/settings.json"
        executable = Path(profile) / "bin/TraceFox.exe"
        executable.parent.mkdir()
        shutil.copy2(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / "target/debug/TraceFox.exe", executable)
        rules_path = executable.parent / "assets/default-rules.json"
        def launch():
            global proc
            proc = subprocess.Popen([str(executable)], env=env)
            app = Desktop(backend="uia").window(title="TraceFox", process=proc.pid)
            app.wait("visible", timeout=15)
            click(app, "关键词与报告规则")
            e = Desktop(backend="uia").window(title="TraceFox · 规则编辑", process=proc.pid)
            e.wait("visible", timeout=10)
            Desktop(backend="win32").window(handle=e.handle).move_window(x=20, y=20, width=900, height=640)
            return e
        e = launch()
        initial = settings.read_bytes() if settings.exists() else None
        def unchanged():
            assert (settings.read_bytes() if settings.exists() else None) == initial
        for tab in ["关键词", "系统信息", "时间线", "报告样式"]:
            click(e, tab)
            assert button(e, "＋ 添加 WebDAV 服务器").is_enabled()
            assert not any(c.window_text() in ["WebDAV 测试", "测试连接"] for c in controls(e, "Button"))
        click(e, "＋ 添加 WebDAV 服务器")
        assert controls(e, "Edit")[1].get_value() == "rules.json"
        assert not any(c.window_text() == "保存全部" for c in controls(e, "Button"))
        click(e, "保存")
        assert "保存失败" in texts(e)
        unchanged()
        edit(e, 0, url)
        edit(e, 2, "tester")
        edit(e, 3, "test-secret")
        click(e, "测试连接")
        wait_for(lambda: "连接成功" in texts(e))
        assert requests[-1] == ("HEAD", "/dav/rules.json", "Basic " + base64.b64encode(b"tester:test-secret").decode())
        unchanged()
        assert credential(keys[0]) is None
        e.capture_as_image().save(str(out / "webdav-minimum.png"))
        for _ in range(14):
            e.type_keys("{TAB}")
            focused = [c.window_text() for c in e.descendants() if c.has_keyboard_focus()]
            assert not any(n in ["保存全部", "关键词", "系统信息", "时间线", "报告样式"] for n in focused)
        e.type_keys("{ESC}")
        time.sleep(.2)
        assert button(e, "＋ 添加 WebDAV 服务器").has_keyboard_focus()
        unchanged()
        click(e, "＋ 添加 WebDAV 服务器")
        assert controls(e, "Edit")[0].get_value() == ""
        edit(e, 0, url)
        edit(e, 2, "tester")
        edit(e, 3, "test-secret")
        # 文件写入失败必须撤销新建凭据，并保留表单。
        blocked = settings.with_name("settings.json.tmp")
        blocked.mkdir(parents=True)
        click(e, "保存")
        assert "配置文件保存失败" in texts(e)
        assert credential(keys[0]) is None
        unchanged()
        blocked.rmdir()
        count = len(requests)
        click(e, "保存")
        assert len(requests) == count
        assert button(e, "编辑 WebDAV 服务器").is_enabled()
        assert "test-secret" not in settings.read_text(encoding="utf-8")
        assert credential(keys[0]) == b"test-secret"
        initial = settings.read_bytes()
        proc.terminate(); proc.wait(timeout=10)
        e = launch()
        click(e, "编辑 WebDAV 服务器")
        assert controls(e, "Edit")[0].get_value() == url
        assert controls(e, "Edit")[3].get_value() == ""
        click(e, "测试连接")
        wait_for(lambda: "连接成功" in texts(e))
        assert requests[-1][2].endswith(base64.b64encode(b"tester:test-secret").decode())
        # 已有凭据也必须在配置文件保存失败后恢复。
        edit(e, 3, "replacement")
        blocked.mkdir()
        click(e, "保存")
        assert "配置文件保存失败" in texts(e)
        assert credential(keys[0]) == b"test-secret"
        unchanged()
        blocked.rmdir()
        # 凭据写入失败不应写入配置。
        edit(e, 3, "x" * 3000)
        click(e, "保存")
        assert "密码保存失败" in texts(e)
        unchanged()
        assert credential(keys[0]) == b"test-secret"
        edit(e, 3, "")
        response["status"] = 401
        click(e, "测试连接")
        wait_for(lambda: "连接失败" in texts(e))
        unchanged()
        response.update(status=200, delay=2)
        click(e, "测试连接")
        click(e, "取消")
        click(e, "编辑 WebDAV 服务器")
        time.sleep(2.3)
        assert "连接成功" not in texts(e)
        response["delay"] = 0
        edit(e, 1, "other.json")
        click(e, "保存")
        assert credential(keys[1]) == b"test-secret"
        # 下载及同步必须写入程序旁规则；落盘失败不能报告成功或替换旧规则。
        remote_rules["rules"][0]["name"] = "WebDAV 下载验证"
        click(e, "下载规则")
        assert "规则已下载并保存" in texts(e)
        assert json.loads(rules_path.read_text(encoding="utf-8"))["rules"][0]["name"] == "WebDAV 下载验证"
        previous = rules_path.read_bytes()
        blocked_rules = rules_path.with_suffix(".json.tmp")
        blocked_rules.mkdir()
        remote_rules["rules"][0]["name"] = "WebDAV 同步验证"
        click(e, "下载规则")
        assert "下载失败" in texts(e)
        assert rules_path.read_bytes() == previous
        blocked_rules.rmdir()
        click(e, "双向同步")
        assert "规则已下载并保存" in texts(e)
        assert json.loads(rules_path.read_text(encoding="utf-8"))["rules"][0]["name"] == "WebDAV 同步验证"
        assert not settings.with_name("rules.json").exists()
        # 150% 缩放下检查最小窗口、按钮可见及关闭路径。
        proc.terminate(); proc.wait(timeout=10)
        env["SLINT_SCALE_FACTOR"] = "1.5"
        e = launch()
        Desktop(backend="win32").window(handle=e.handle).move_window(x=20, y=20, width=1350, height=960)
        click(e, "编辑 WebDAV 服务器")
        for name in ["保存", "取消", "测试连接"]:
            r = button(e, name).rectangle(); outer = e.rectangle()
            assert outer.top <= r.top < r.bottom <= outer.bottom
        e.capture_as_image().save(str(out / "webdav-150.png"))
        e.type_keys("%{F4}")
        time.sleep(.3)
        assert button(e, "编辑 WebDAV 服务器").is_enabled()
        print("PASS: 独立弹窗、测试不落盘、保存与回滚、下载/同步路径一致、写入失败保留旧规则、重启/密码保留、失败提示、焦点/Esc、100%/150%最小窗口")
        proc.terminate(); proc.wait(timeout=10); proc = None
finally:
    if proc is not None:
        proc.terminate(); proc.wait(timeout=10)
    for key in keys:
        if credential(key) is not None:
            win32cred.CredDelete(key, win32cred.CRED_TYPE_GENERIC)
    server.shutdown()
