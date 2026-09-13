"""隔离配置下检查最小窗口、应用缩放、长列表和拖动自动滚动。"""
import os, sys, site, json, subprocess, time, shutil, ctypes
from pathlib import Path
root=Path(__file__).resolve().parents[1]
deps=root/'validation/python_deps'
site.addsitedir(str(deps));sys.path.extend([str(deps/'win32'),str(deps/'win32/lib')]);os.add_dll_directory(str(deps/'pywin32_system32'))
from pywinauto import Desktop, mouse
out=root/'target/display-validation'

def find(e,kind,name):
    return [c for c in e.descendants(control_type=kind) if c.window_text()==name and c.is_visible() and c.is_enabled()][-1]
def click(e,name):find(e,'Button',name).invoke();time.sleep(.3)
def capture(e,name):e.capture_as_image().save(str(out/name))

for scale in [1,1.5]:
    label=str(int(scale*100));profile=out/('editor-layout-'+label);(profile/'TraceFox').mkdir(parents=True,exist_ok=True)
    rules=json.loads((root/'assets/default-rules.json').read_text(encoding='utf-8'));base=rules['rules'][0]
    long_name='连接超时：验证很长的规则名称能够正常省略而不挤压操作按钮 '+('网络服务 ' * 12)
    rules['rules']=[dict(base,id='layout-'+str(i),name=long_name if i==0 else '规则 '+str(i),group='网络连接' if i<30 else '磁盘与存储',terms=['timeout','connection timed out','resolve failed'],target='keywords') for i in range(60)]
    exe=profile/'bin/TraceFox.exe';exe.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/'target/debug/TraceFox.exe',exe);config=exe.parent/'assets/default-rules.json';config.parent.mkdir(exist_ok=True);config.write_text(json.dumps(rules,ensure_ascii=False),encoding='utf-8');initial=config.read_bytes()
    env=os.environ.copy();env['LOCALAPPDATA']=str(profile);env['SLINT_SCALE_FACTOR']=str(scale)
    proc=subprocess.Popen([str(exe)],env=env)
    try:
        time.sleep(2);app=Desktop(backend='uia').window(title='TraceFox',process=proc.pid);click(app,'规则管理')
        e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid);e.wait('visible',timeout=10)
        native=Desktop(backend='win32').window(handle=e.handle)
        native.move_window(x=30,y=30,width=round(800*scale),height=round(580*scale));time.sleep(.5)
        capture(e,'editor-minimum-'+label+'.png')
        save=find(e,'Button','保存全部').rectangle();rect=e.rectangle();assert rect.top<=save.top<save.bottom<=rect.bottom
        # 长短名称共享列宽；展开后操作列与名称区域不移位。
        name_rect=find(e,'Button',long_name).rectangle()
        short_rect=find(e,'Button','规则 1').rectangle()
        assert abs(name_rect.width()-short_rect.width())<=2
        toggles=[c.rectangle() for c in e.descendants(control_type='Button') if c.window_text() in ['已启用','已禁用'] and c.is_visible()]
        assert toggles and max(r.left for r in toggles)-min(r.left for r in toggles)<=2
        click(e,long_name)
        expanded_rect=find(e,'Button',long_name).rectangle()
        assert abs(expanded_rect.left-name_rect.left)<=2 and abs(expanded_rect.right-name_rect.right)<=2
        capture(e,'editor-aligned-buttons-'+label+'.png')
        click(e,'编辑');capture(e,'editor-long-dialog-'+label+'.png')
        finish=find(e,'Button','完成').rectangle();assert rect.top<=finish.top<finish.bottom<=rect.bottom
        # Tab 不能进入被弹窗屏蔽的背景。
        e.set_focus();e.type_keys('{TAB}'*24,pause=.01)
        focused=[c for c in e.descendants() if c.has_keyboard_focus()]
        assert all(c.window_text() not in ['保存全部','关键词','系统信息','时间线','报告样式'] for c in focused)
        click(e,'取消');assert config.read_bytes()==initial
        # 长列表在拖动到下边缘时持续滚动，松手才提交。
        e.set_focus();bounds=e.rectangle();footer=find(e,'Button','保存全部').rectangle().top
        initially_visible={c.window_text() for c in e.descendants(control_type='Button') if bounds.top<=c.rectangle().top<footer and (c.window_text()==long_name or c.window_text().startswith('规则 '))}
        src=find(e,'Button',long_name).rectangle();start=(round(src.left-24*scale),(src.top+src.bottom)//2)
        end=(start[0],round(e.rectangle().bottom-84*scale))
        mouse.press(coords=start)
        for n in range(1,12):mouse.move(coords=(start[0],round(start[1]+(end[1]-start[1])*n/11)));time.sleep(.04)
        time.sleep(2.0);capture(e,'editor-autoscroll-'+label+'.png');mouse.release(coords=end);time.sleep(.5)
        click(e,'保存全部');saved=json.loads(config.read_text(encoding='utf-8'));position=next(i for i,r in enumerate(saved['rules']) if r['id']=='layout-0')
        # 卡片高度随关键词数变化；验证确实拖到了初始视口之外，不假定固定行高。
        assert position>0 and saved['rules'][position-1]['name'] not in initially_visible, (position,initially_visible)
        assert len(saved['rules'])==60 and len({r['id'] for r in saved['rules']})==60
        print('PASS: minimum window, long text, modal/tab, edge autoscroll; scale='+label,flush=True)
    except Exception:
        if 'e' in locals():
            try: capture(e,'editor-layout-failure-'+label+'.png')
            except Exception: pass
        raise
    finally:
        proc.terminate();proc.wait(timeout=10)
