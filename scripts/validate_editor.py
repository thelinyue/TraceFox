"""隔离配置验证文件工作区、共享规则、行内编辑、抽屉与缩放，不接触正式配置。"""
import os, sys, site, json, subprocess, time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
deps=root/'validation/python_deps'
site.addsitedir(str(deps));sys.path.extend([str(deps/'win32'),str(deps/'win32/lib')]);os.add_dll_directory(str(deps/'pywin32_system32'))
from pywinauto import Desktop, mouse
out=root/'target/display-validation';out.mkdir(parents=True,exist_ok=True)

def controls(e,kind):
    return [c for c in e.descendants(control_type=kind) if c.is_visible() and c.is_enabled() and c.rectangle().width()>0]
def button(e,name):
    found=[c for c in controls(e,'Button') if c.window_text()==name]
    assert found, ('missing',name,[c.window_text() for c in controls(e,'Button')])
    return found[-1]
def click(e,name):
    b=button(e,name)
    if name in ['已启用','已禁用']: b.iface_toggle.Toggle()
    else: b.invoke()
    time.sleep(.4)
def capture(e,name):e.capture_as_image().save(str(out/name))
def input_value(e,value):return next(c for c in controls(e,'Edit') if c.get_value()==value)
def set_value(e,old,new):
    c=input_value(e,old);c.set_focus();c.set_edit_text(new);c.type_keys('{ENTER}');time.sleep(.4)
def menu(e,name):
    r=button(e,name).rectangle()
    next(b for b in controls(e,'Button') if b.window_text()=='规则更多操作' and r.top<=b.rectangle().top<r.bottom).invoke();time.sleep(.3)
def open_rule(e,name):menu(e,name);click(e,'编辑规则')
def rule_toggle(e,name):
    r=button(e,name).rectangle()
    return next(b for b in controls(e,'Button') if b.window_text() in ['已启用','已禁用'] and r.top<=b.rectangle().top<r.bottom)
def scroll(e,amount):
    r=e.rectangle();mouse.scroll(coords=(r.right-80,r.bottom-160),wheel_dist=amount);time.sleep(.4)

for scale in [1,1.5]:
    label=str(int(scale*100));profile=out/('file-workspace-'+label);(profile/'TraceFox').mkdir(parents=True,exist_ok=True)
    rules=json.loads((root/'assets/default-rules.json').read_text(encoding='utf-8'));base=rules['rules'][0]
    rules['rules']=[dict(base,id='shared',name='共享规则',group='网络连接',terms=['timeout'],sources=[dict(pattern='syslog',mode='prefix'),dict(pattern='kernel.log',mode='exact')],target='both'),dict(base,id='second',name='第二条规则',group='另一报告分组',terms=['error'],sources=[dict(pattern='syslog',mode='prefix')],target='keywords')]
    config=profile/'TraceFox/rules.json';config.write_text(json.dumps(rules,ensure_ascii=False),encoding='utf-8');initial=config.read_bytes()
    env=os.environ.copy();env['LOCALAPPDATA']=str(profile);env['SLINT_SCALE_FACTOR']=str(scale)
    proc=subprocess.Popen([str(root/'target/debug/TraceFox.exe')],env=env)
    try:
        time.sleep(2);app=Desktop(backend='uia').window(title='TraceFox',process=proc.pid);click(app,'关键词与报告规则')
        e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid);e.wait('visible',timeout=10)
        native=Desktop(backend='win32').window(handle=e.handle)
        native.move_window(x=0,y=0,width=round(1100*scale),height=round(700*scale));time.sleep(.5)
        e.set_focus()
        capture(e,'file-workspace-'+label+'.png')
        # 按钮式开关支持鼠标、键盘及读屏状态；取消列表和抽屉编辑均可撤回。
        toggle=rule_toggle(e,'共享规则');original_toggle=toggle.rectangle()
        assert toggle.iface_toggle.CurrentToggleState==1
        toggle.set_focus();toggle.click_input();time.sleep(.3)
        toggle=rule_toggle(e,'共享规则');assert toggle.window_text()=='已禁用' and toggle.iface_toggle.CurrentToggleState==0
        assert toggle.rectangle().width()==original_toggle.width()
        toggle.set_focus();toggle.type_keys('{SPACE}');time.sleep(.3)
        assert rule_toggle(e,'共享规则').window_text()=='已启用'
        rule_toggle(e,'共享规则').iface_toggle.Toggle();time.sleep(.3);click(e,'取消');assert config.read_bytes()==initial
        click(app,'关键词与报告规则');e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid)
        assert rule_toggle(e,'共享规则').window_text()=='已启用'
        open_rule(e,'共享规则');click(e,'已启用');click(e,'取消')
        assert rule_toggle(e,'共享规则').window_text()=='已启用'
        open_rule(e,'共享规则');click(e,'已启用');click(e,'完成')
        assert rule_toggle(e,'共享规则').window_text()=='已禁用'
        click(e,'共享规则')
        assert not any(c.get_value()=='timeout' for c in controls(e,'Edit'))
        click(e,'共享规则');assert input_value(e,'timeout')
        click(e,'共享规则');assert not any(c.get_value()=='timeout' for c in controls(e,'Edit'))
        click(e,'共享规则')
        set_value(e,'timeout','changed')
        # Typed text must survive opening the full editor before pressing Enter.
        c=input_value(e,'changed');c.set_focus();c.set_edit_text('pending')
        open_rule(e,'共享规则');time.sleep(.4)
        assert input_value(e,'pending');click(e,'取消');assert input_value(e,'pending')
        set_value(e,'pending','changed')
        click(e,'kernel.log  ·  1');assert input_value(e,'changed');assert len([b for b in controls(e,'Button') if b.window_text()=='共享规则'])==1
        c=input_value(e,'changed');c.set_focus();c.set_edit_text('discard');c.type_keys('{ESC}');time.sleep(.3);assert input_value(e,'changed')
        # Drawer text edits go only to its private copy; closing restores the main draft.
        open_rule(e,'共享规则');click(e,'选择已有报告分组');click(e,'网络连接');assert len([c for c in controls(e,'Edit') if c.get_value()=='网络连接'])==1
        assert not any(b.window_text()=='保存全部' for b in controls(e,'Button'))
        # Logical control dimensions and the label gutter must agree at both display scales.
        aligned=[input_value(e,'共享规则'), input_value(e,'syslog;kernel.log'), input_value(e,'changed')]
        aligned += [c for c in controls(e,'ComboBox') if c.rectangle().top < button(e,'完成').rectangle().top]
        expected=round(320*scale)
        assert all(abs(c.rectangle().width()-expected)<=2 for c in aligned), [(c.window_text(),c.rectangle()) for c in aligned]
        assert max(c.rectangle().left for c in aligned)-min(c.rectangle().left for c in aligned)<=2
        group=input_value(e,'网络连接').rectangle();arrow=button(e,'选择已有报告分组').rectangle()
        assert abs(arrow.right-group.left-expected)<=2

        input_value(e,'changed').set_edit_text('drawer-cancel');capture(e,'file-drawer-'+label+'.png');click(e,'取消');assert input_value(e,'changed')
        open_rule(e,'共享规则');input_value(e,'changed').set_edit_text('drawer-saved');click(e,'完成');assert input_value(e,'drawer-saved')
        assert config.read_bytes()==initial
        # Add and remove a term without replacing the rule entity.
        edits=controls(e,'Edit');blank=[c for c in edits if c.get_value()==''][-1]
        blank.set_edit_text('extra');blank.type_keys('{ENTER}');time.sleep(.3);assert input_value(e,'extra')
        next(b for b in controls(e,'Button') if b.window_text()=='删除匹配内容' and abs(b.rectangle().top-input_value(e,'extra').rectangle().top)<5).invoke();time.sleep(.3)
        assert not any(c.get_value()=='extra' for c in controls(e,'Edit'))
        click(e,'保存全部');saved=json.loads(config.read_text(encoding='utf-8'));assert len(saved['rules'])==2;assert saved['rules'][0]['terms']==['drawer-saved'];assert saved['rules'][0]['group']=='网络连接';assert saved['rules'][0]['sources']==rules['rules'][0]['sources']
        assert saved['rules'][0]['enabled'] is False
        assert saved['rules'][0]['name']==rules['rules'][0]['name'] and saved['rules'][0]['note']==rules['rules'][0]['note']
        click(app,'关键词与报告规则');e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid)
        assert rule_toggle(e,'共享规则').window_text()=='已禁用'
        if scale==1 and '--rule-controls-only' not in sys.argv:
            # Native actions: reorder across report groups, copy/cancel, delete, wizard and preview.
            menu(e,'共享规则');click(e,'下移')
            assert [b.window_text() for b in controls(e,'Button') if b.window_text() in ['共享规则','第二条规则']]==['第二条规则','共享规则']
            menu(e,'共享规则');click(e,'复制');click(e,'取消')
            menu(e,'共享规则');click(e,'复制');click(e,'完成')
            scroll(e,-5);menu(e,'共享规则 副本');click(e,'删除');scroll(e,20)
            click(e,'添加规则到此日志文件');assert input_value(e,'syslog')
            click(e,'下一步');assert any('请填写' in c.window_text() for c in e.descendants(control_type='Text'))
            controls(e,'Edit')[0].set_edit_text('新增测试');click(e,'下一步')
            controls(e,'Edit')[0].set_edit_text('test-term');click(e,'上一步');assert input_value(e,'新增测试')
            click(e,'下一步');assert input_value(e,'test-term');click(e,'下一步');click(e,'完成添加')
            scroll(e,-10);open_rule(e,'新增测试');scroll(e,-20)
            test_button=next(b for b in controls(e,'Button') if '用样例测试' in b.window_text());test_button.invoke();time.sleep(.3);scroll(e,-20)
            controls(e,'Edit')[-1].set_edit_text('test-term sample');click(e,'预览效果');assert (profile/'TraceFox/rule-preview.html').exists();assert json.loads(config.read_text(encoding='utf-8'))==saved
            click(e,'取消');scroll(e,20)
            # A save error keeps the draft available for retry.
            backup=config.with_suffix('.backup');config.rename(backup);config.mkdir()
            try:
                click(e,'保存全部');assert any('无法保存' in c.window_text() for c in e.descendants(control_type='Text'))
            finally:
                config.rmdir();backup.rename(config)
            click(e,'保存全部');saved=json.loads(config.read_text(encoding='utf-8'))
            assert [r['id'] for r in saved['rules'][:2]]==['second','shared'];assert [r['group'] for r in saved['rules'][:2]]==['另一报告分组','网络连接'];assert len(saved['rules'])==3
            click(app,'关键词与报告规则');e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid)
            click(e,'系统信息');click(e,'添加规则到此日志文件')
            controls(e,'Edit')[0].set_edit_text('新系统字段');click(e,'下一步');click(e,'＋ 添加字段')
            edits=controls(e,'Edit');edits[1].set_edit_text('型号');edits[2].set_edit_text('model');capture(e,'uniform-system-fields.png')
            click(e,'下一步');click(e,'完成添加');click(e,'保存全部')
            saved=json.loads(config.read_text(encoding='utf-8'));assert next(r for r in saved['system'] if r['name']=='新系统字段')['fields'][0]['path']=='model'
            click(app,'关键词与报告规则');e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid)
            click(e,'报告样式');spinner=controls(e,'Spinner')[-1];r=spinner.rectangle();mouse.click(coords=(r.right-10,r.top+10));time.sleep(.3);click(e,'保存全部')
            saved=json.loads(config.read_text(encoding='utf-8'));assert saved['layout']['log_lines_per_batch']!=rules.get('layout',{}).get('log_lines_per_batch',200)
            click(app,'关键词与报告规则');e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid)
        # Small window uses the file picker; all drawer actions remain visible.
        native=Desktop(backend='win32').window(handle=e.handle);native.move_window(x=0,y=0,width=round(800*scale),height=round(580*scale));time.sleep(.4)
        assert controls(e,'ComboBox');capture(e,'file-compact-'+label+'.png')
        open_rule(e,'共享规则');capture(e,'file-full-editor-'+label+'.png')
        rect=e.rectangle();finish=button(e,'完成').rectangle();assert rect.top<=finish.top<finish.bottom<=rect.bottom
        click(e,'取消');click(e,'取消');assert json.loads(config.read_text(encoding='utf-8'))==saved
        print('PASS: shared identity, inline commit/Escape, drawer cancel/complete, save/reopen, compact layout; scale='+label,flush=True)
    except Exception:
        if 'e' in locals():
            try: capture(e,'file-failure-'+label+'.png')
            except Exception: pass
        raise
    finally:
        proc.terminate();proc.wait(timeout=10)
