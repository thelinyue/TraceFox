"""隔离配置下检查紧凑窗口和控件尺寸；应用缩放不改变 Windows 全局设置。"""
import os, sys, site, subprocess, time, json, io, tarfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
deps=root/'validation/python_deps'
site.addsitedir(str(deps));sys.path.extend([str(deps/'win32'),str(deps/'win32/lib')]);os.add_dll_directory(str(deps/'pywin32_system32'))
from pywinauto import Desktop
out=root/'target/compact-validation';out.mkdir(parents=True,exist_ok=True)
def click(w,name):
    [c for c in w.descendants(control_type='Button') if c.window_text()==name and c.is_visible() and c.is_enabled()][-1].invoke();time.sleep(.4)
def capture(w,name):w.capture_as_image().save(str(out/name))
def bounds(w, names=None):
    r=w.rectangle()
    for c in w.descendants(control_type='Button'):
        if c.is_visible() and c.rectangle().bottom>w.rectangle().top and (names is None or c.window_text() in names):
            b=c.rectangle()
            assert r.left<=b.left and b.right<=r.right and r.top<=b.top and b.bottom<=r.bottom,(c.window_text(),b,r)
for scale in [1,1.5]:
    label=str(int(scale*100));profile=out/('profile-'+label);(profile/'TraceFox').mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,LOCALAPPDATA=str(profile),SLINT_SCALE_FACTOR=str(scale))
    proc=subprocess.Popen([str(root/'target/debug/TraceFox.exe')],env=env)
    try:
        time.sleep(2);app=Desktop(backend='uia').window(title='TraceFox',process=proc.pid);app.wait('visible',timeout=10)
        print('main',scale,app.rectangle(),flush=True)
        bounds(app)
        for c in app.descendants(control_type='Button'):
            assert c.rectangle().height()<=40*scale,(c.window_text(),c.rectangle())
        capture(app,'main-'+label+'.png')
        click(app,'关键词与报告规则');e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid);e.wait('visible',timeout=10)
        bounds(e,['关键词','系统信息','时间线','报告样式','保存全部','取消','导入','导出 ▾']);capture(e,'editor-'+label+'.png')
        click(e,'系统信息');click(e,'套用参考配置')
        preview=Desktop(backend='uia').window(title='TraceFox · 导入预览',process=proc.pid);preview.wait('visible',timeout=10);bounds(preview);capture(preview,'import-'+label+'.png');click(preview,'取消')
        click(e,'＋ 添加 WebDAV 服务器');capture(e,'webdav-'+label+'.png');click(e,'取消');click(e,'取消')
        archive=out/('sample-'+label+'.tgz')
        with tarfile.open(archive,'w:gz') as tar:
            data=b'{"model":"compact test"}';info=tarfile.TarInfo('sysinfo.json');info.size=len(data);tar.addfile(info,io.BytesIO(data))
        click(app,'导入诊断包');dialog=Desktop(backend='uia').window(class_name='#32770',process=proc.pid);dialog.wait('visible',timeout=10)
        dialog.child_window(auto_id='1148',control_type='Edit').set_edit_text(str(archive));dialog.child_window(auto_id='1',control_type='Button').invoke()
        for _ in range(40):
            time.sleep(.25)
            if any(c.window_text()=='打开 HTML' for c in app.descendants(control_type='Button')):break
        assert any(c.window_text()=='打开 HTML' for c in app.descendants(control_type='Button'))
        bounds(app)
        for c in app.descendants(control_type='Button'):
            assert c.rectangle().height()<=40*scale,(c.window_text(),c.rectangle())
        capture(app,'reports-'+label+'.png')
        native=Desktop(backend='win32').window(handle=app.handle)
        native.move_window(x=30,y=30,width=round(700*scale),height=round(600*scale));time.sleep(.3)
        for c in app.descendants(control_type='Button'):
            assert c.rectangle().height()<=40*scale,(c.window_text(),c.rectangle())
        capture(app,'reports-resized-'+label+'.png')
        print('PASS compact main, editor, preview, WebDAV and package import scale='+label,flush=True)
    finally:proc.terminate();proc.wait(timeout=10)
