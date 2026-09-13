"""真实 Windows 通知验收：隔离样本，通知点击后验证窗口或浏览器。"""
import os, sys, site, subprocess, time, json, io, tarfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
deps=root/'validation/python_deps'
site.addsitedir(str(deps));sys.path.extend([str(deps/'win32'),str(deps/'win32/lib')]);os.add_dll_directory(str(deps/'pywin32_system32'))
from pywinauto import Desktop
sys.stdout.reconfigure(encoding='utf-8')
base=root/'target/notification-validation';base.mkdir(parents=True,exist_ok=True)
profile=base/'profile';(profile/'TraceFox').mkdir(parents=True,exist_ok=True)
watch=base/str(time.time_ns());watch.mkdir()
(profile/'TraceFox/settings.json').write_text(json.dumps(dict(directory=str(watch),watching=True,autostart=False,start_minimized=True)),encoding='utf-8')
log=(base/'application.log').open('w',encoding='utf-8')
proc=subprocess.Popen([str(root/'target/debug/TraceFox.exe'),'--startup'],env=dict(os.environ,LOCALAPPDATA=str(profile)),stdout=log,stderr=log)
bad=f'通知验证-损坏-{proc.pid}.tgz'
good=f'通知验证 & 成功-{proc.pid}.tgz'
try:
    time.sleep(3)
    assert proc.poll() is None
    (watch/bad).write_bytes(b'broken gzip')
    for attempt in range(70):
        windows=Desktop(backend='uia').windows()
        matches=[w for w in windows if w.element_info.class_name=='Windows.UI.Core.CoreWindow' and '通知' in w.window_text()]
        if matches:
            w=matches[-1]
            values=[c.window_text() for c in w.descendants()]
            if any(bad in v for v in values):
                print('TOAST',w.window_text(),values,flush=True)
                time.sleep(.8);w.capture_as_image().save(str(base/'failure-toast.png'))
                targets=[c for c in w.descendants() if bad in c.window_text()]
                w.click_input(coords=(140,65))
                app=Desktop(backend='uia').window(title='TraceFox',process=proc.pid);app.wait('visible',timeout=10)
                app.capture_as_image().save(str(base/'failure-selected.png'))
                print('PASS 失败通知从开机托盘状态恢复主窗口',flush=True)
                break
        time.sleep(.3)
    else:
        print([(w.window_text(),w.element_info.class_name) for w in windows],flush=True)
        raise AssertionError('未找到失败通知')
    app.close();time.sleep(.5)
    with tarfile.open(watch/good,'w:gz') as tar:
        data=b'{"model":"Notification test"}';entry=tarfile.TarInfo('sysinfo.json');entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
    for attempt in range(70):
        matches=[w for w in Desktop(backend='uia').windows() if w.element_info.class_name=='Windows.UI.Core.CoreWindow' and '通知' in w.window_text()]
        for w in matches:
            targets=[c for c in w.descendants() if good in c.window_text()]
            if targets:
                time.sleep(.8);w.capture_as_image().save(str(base/'success-toast.png'))
                w.click_input(coords=(140,65));time.sleep(2)
                deadline=time.time()+15
                expected=str(watch/Path(good).stem/'report.html').replace('\\','/')
                verified=False
                from urllib.parse import unquote
                while time.time()<deadline:
                    for browser in Desktop(backend='uia').windows():
                        if browser.element_info.class_name!='Chrome_WidgetWin_1': continue
                        for edit in browser.descendants(control_type='Edit'):
                            address=unquote(edit.window_text()).replace('\\','/')
                            if expected.lower() in address.lower():
                                verified=True
                                print('PASS 成功通知打开准确报告地址',flush=True)
                                break
                    if verified:break
                    time.sleep(.5)
                if not verified:
                    print('WINDOWS',[(x.window_text(),x.element_info.class_name) for x in Desktop(backend='uia').windows() if x.element_info.process_id==proc.pid],flush=True)
                    raise AssertionError('成功通知未打开对应浏览器报告')
                
                raise SystemExit(0)
        time.sleep(.3)
    raise AssertionError('未找到成功通知')
finally:
    proc.terminate();proc.wait(timeout=10);log.close()
