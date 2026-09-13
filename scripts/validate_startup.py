"""隔离配置验证设置、自启参数及截图；启动项在 finally 中恢复原值。"""
import os, sys, site, subprocess, time, json, tempfile, winreg
from pathlib import Path
root=Path(__file__).resolve().parents[1]
deps=root/'validation/python_deps'
site.addsitedir(str(deps));sys.path.extend([str(deps/'win32'),str(deps/'win32/lib')]);os.add_dll_directory(str(deps/'pywin32_system32'))
from pywinauto import Desktop, mouse
import win32gui, win32con
sys.stdout.reconfigure(encoding='utf-8')
out=root/'target/startup-validation';out.mkdir(parents=True,exist_ok=True)
run=winreg.CreateKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Run')
try: original=winreg.QueryValueEx(run,'TraceFox')
except FileNotFoundError: original=None
proc=None

def control(app,name,kind='Button'):
    return [c for c in app.descendants(control_type=kind) if c.window_text()==name and c.is_visible()][-1]
def click(app,name):
    control(app,name).invoke();time.sleep(.3)
def check(app,name,value):
    c=control(app,name,'CheckBox')
    if bool(c.get_toggle_state())!=value: c.toggle();time.sleep(.2)
def stop():
    global proc
    if proc is not None: proc.terminate();proc.wait(timeout=10);proc=None

try:
    with tempfile.TemporaryDirectory(prefix='tracefox-startup-') as folder:
        base=Path(folder);profile=base/'profile';(profile/'TraceFox').mkdir(parents=True)
        config=profile/'TraceFox/settings.json'
        initial=dict(directory='',watching=False)
        config.write_text(json.dumps(initial),encoding='utf-8')
        for scale in [1,1.5]:
            env=dict(os.environ,LOCALAPPDATA=str(profile),SLINT_SCALE_FACTOR=str(scale))
            proc=subprocess.Popen([str(root/'target/debug/TraceFox.exe')],env=env)
            app=Desktop(backend='uia').window(title='TraceFox',process=proc.pid);app.wait('visible',timeout=30)
            app.capture_as_image().save(str(out/'caption-debug.png'))
            bounds=app.rectangle()
            start=(bounds.left+120,bounds.top+int(18*scale))
            mouse.press(coords=start);mouse.move(coords=(start[0]+6,start[1]+6));time.sleep(.3);mouse.move(coords=(start[0]+45,start[1]+25));time.sleep(.3);mouse.release(coords=(start[0]+45,start[1]+25));time.sleep(.3)
            moved=app.rectangle();assert moved.left!=bounds.left or moved.top!=bounds.top,'标题栏无法拖动'
            edge=(moved.right-2,moved.top+int(moved.height()/2))
            mouse.press(coords=edge);mouse.move(coords=(edge[0]+40,edge[1]));time.sleep(.3);mouse.release(coords=(edge[0]+40,edge[1]));time.sleep(.3)
            assert app.rectangle().width()>moved.width(),'窗口边缘无法缩放'
            win32gui.MoveWindow(app.handle,bounds.left,bounds.top,bounds.width(),bounds.height(),True)
            click(app,'最大化');assert win32gui.GetWindowPlacement(app.handle)[1]==win32con.SW_SHOWMAXIMIZED
            click(app,'还原窗口');assert win32gui.GetWindowPlacement(app.handle)[1]!=win32con.SW_SHOWMAXIMIZED
            r=app.rectangle();mouse.double_click(coords=(r.left+120,r.top+int(18*scale)));time.sleep(.5)
            assert win32gui.GetWindowPlacement(app.handle)[1]==win32con.SW_SHOWMAXIMIZED
            click(app,'还原窗口')
            click(app,'最小化');assert win32gui.IsIconic(app.handle)
            win32gui.ShowWindow(app.handle,win32con.SW_RESTORE);time.sleep(.5)
            app.capture_as_image().save(str(out/f'main-{scale}.png'))
            click(app,'设置')
            assert not control(app,'导入诊断包').is_enabled()
            before=config.read_bytes()
            check(app,'开机自启',True);check(app,'开机自动最小化到托盘',True)
            click(app,'取消');assert config.read_bytes()==before
            click(app,'设置');app.type_keys('{ESC}');assert control(app,'导入诊断包').is_enabled()
            assert config.read_bytes()==before
            click(app,'设置');check(app,'开机自启',True);check(app,'开机自动最小化到托盘',True)
            app.capture_as_image().save(str(out/f'settings-{scale}.png'))
            click(app,'保存')
            saved=json.loads(config.read_text(encoding='utf-8'));assert saved['autostart'] and saved['start_minimized']
            value,kind=winreg.QueryValueEx(run,'TraceFox');assert value==f'"{root / "target/debug/TraceFox.exe"}" --startup' and kind==winreg.REG_SZ
            stop()
            proc=subprocess.Popen([str(root/'target/debug/TraceFox.exe'),'--startup'],env=env)
            time.sleep(3);assert proc.poll() is None
            assert not [w for w in Desktop(backend='uia').windows(process=proc.pid) if w.window_text()=='TraceFox' and w.is_visible()]
            stop()
            proc=subprocess.Popen([str(root/'target/debug/TraceFox.exe')],env=env)
            app=Desktop(backend='uia').window(title='TraceFox',process=proc.pid);app.wait('visible',timeout=30)
            click(app,'设置');check(app,'开机自动最小化到托盘',False);click(app,'保存')
            stop()
            proc=subprocess.Popen([str(root/'target/debug/TraceFox.exe'),'--startup'],env=env)
            app=Desktop(backend='uia').window(title='TraceFox',process=proc.pid);app.wait('visible',timeout=30)
            click(app,'设置');check(app,'开机自启',False);click(app,'保存')
            try: winreg.QueryValueEx(run,'TraceFox');raise AssertionError('启动项未删除')
            except FileNotFoundError: pass
            assert not json.loads(config.read_text(encoding='utf-8'))['autostart']
            before=config.read_bytes()
            blocker=config.with_name('settings.json.tmp');blocker.mkdir()
            click(app,'设置');check(app,'开机自启',True);click(app,'保存')
            assert config.read_bytes()==before
            assert any('保存设置失败' in c.window_text() for c in app.descendants(control_type='Text'))
            try: winreg.QueryValueEx(run,'TraceFox');raise AssertionError('保存失败后启动项未回滚')
            except FileNotFoundError: pass
            click(app,'取消');blocker.rmdir()
            click(app,'关闭到托盘');app.wait_not('visible',timeout=10);assert proc.poll() is None
            stop()
            print(f'PASS 设置取消/保存、启动项、开机隐藏与手动显示：{scale}',flush=True)
finally:
    stop()
    if original is None:
        try: winreg.DeleteValue(run,'TraceFox')
        except FileNotFoundError: pass
    else: winreg.SetValueEx(run,'TraceFox',0,original[1],original[0])
    winreg.CloseKey(run)
