"""用隔离监控目录验证诊断包全周期与有确认的批量清理；只操作临时夹具。"""
import os, sys, site, subprocess, time, json, io, tarfile, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
deps=root/'validation/python_deps'
site.addsitedir(str(deps));sys.path.extend([str(deps/'win32'),str(deps/'win32/lib')]);os.add_dll_directory(str(deps/'pywin32_system32'))
from pywinauto import Desktop
sys.stdout.reconfigure(encoding='utf-8')
out=root/'target/task-validation';out.mkdir(parents=True,exist_ok=True)
def wait(check, seconds=20):
    until=time.time()+seconds
    while time.time()<until:
        if check():return
        time.sleep(.2)
    raise AssertionError('等待条件超时')
def buttons(w,name):return [c for c in w.descendants(control_type='Button') if c.window_text()==name and c.is_visible()]
def click(w,name):
    matches=[c for c in buttons(w,name) if c.is_enabled()];assert matches,name;matches[-1].invoke();time.sleep(.3)
def texts(w):return [c.window_text() for c in w.descendants(control_type='Text')]
def package(path):
    with tarfile.open(path,'w:gz') as tar:
        data=b'{"model":"Task test"}';entry=tarfile.TarInfo('sysinfo.json');entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
def row_button(w,file,name,scale):
    title=[c for c in w.descendants(control_type='Text') if c.window_text()==file][-1].rectangle()
    return [c for c in buttons(w,name) if title.top-8*scale<=c.rectangle().top<title.top+40*scale][-1]
def confirm(proc,yes):
    dialog=Desktop(backend='uia').window(title='确认清理已完成诊断包',process=proc.pid);dialog.wait('visible',timeout=10)
    dialog.child_window(auto_id='6' if yes else '7',control_type='Button').invoke();dialog.wait_not('visible',timeout=15)
for scale in [1,1.5]:
    with tempfile.TemporaryDirectory(prefix='tracefox-tasks-') as folder:
        base=Path(folder);watch=base/'downloads';watch.mkdir();profile=base/'profile';(profile/'TraceFox').mkdir(parents=True)
        (profile/'TraceFox/settings.json').write_text(json.dumps(dict(directory=str(watch),watching=True)),encoding='utf-8')
        untouched=watch/'keep.txt';untouched.write_text('keep');old=watch/'old.tgz';package(old)
        env=dict(os.environ,LOCALAPPDATA=str(profile),SLINT_SCALE_FACTOR=str(scale))
        proc=subprocess.Popen([str(root/'target/debug/TraceFox.exe')],env=env)
        try:
            time.sleep(2);app=Desktop(backend='uia').window(title='TraceFox',process=proc.pid);app.wait('visible',timeout=10)
            assert 'old.tgz' not in texts(app)
            buttons(app,'暂停监控')[-1].iface_toggle.Toggle();wait(lambda:not json.loads((profile/'TraceFox/settings.json').read_text(encoding='utf-8'))['watching'])
            button=buttons(app,'开启监控')[-1];button.set_focus();app.type_keys('{SPACE}');wait(lambda:json.loads((profile/'TraceFox/settings.json').read_text(encoding='utf-8'))['watching'])
            print('monitor after keyboard',json.loads((profile/'TraceFox/settings.json').read_text())['watching'],flush=True)
            new=watch/'new.tgz';package(new)
            wait(lambda:'new.tgz' in texts(app));assert not buttons(app,'清理已完成')[-1].is_enabled()
            row_button(app,'new.tgz','取消',scale).invoke();wait(lambda:'已取消' in texts(app))
            time.sleep(11);assert '已取消' in texts(app)
            row_button(app,'new.tgz','重试',scale).invoke();wait(lambda:bool(buttons(app,'打开 HTML')))
            assert texts(app).count('new.tgz')==1
            # 定时刷新不得关闭菜单；重新分析保持原来的唯一一行。
            row_button(app,'new.tgz','更多操作',scale).invoke();time.sleep(.8)
            click(app,'重新分析');wait(lambda:bool(buttons(app,'打开 HTML')))
            assert texts(app).count('new.tgz')==1
            print('monitor after menu',json.loads((profile/'TraceFox/settings.json').read_text())['watching'],flush=True)
            bad=watch/'bad.tgz';bad.write_bytes(b'bad archive')
            wait(lambda:bool(buttons(app,'删除')));assert not buttons(app,'重试');assert any('损坏' in t for t in texts(app))
            app.capture_as_image().save(str(out/('tasks-'+str(int(scale*100))+'.png')))
            for c in app.descendants(control_type='Button'):
                if c.rectangle().bottom>app.rectangle().top:assert c.rectangle().height()<=40*scale,(c.window_text(),c.rectangle())
            # 批量清理必须确认；拒绝不删除任何内容。
            click(app,'清理已完成');confirm(proc,False);assert new.exists() and new.with_suffix('').exists()
            click(app,'清理已完成');confirm(proc,True)
            wait(lambda:not new.exists());wait(lambda:'new.tgz' not in texts(app))
            assert bad.exists() and old.exists() and untouched.exists()
            assert not new.with_suffix('').exists();assert any('成功 1' in t for t in texts(app))
            # 损坏包只有删除；取消确认保留，确认后保留旁边的旧报告目录。
            prior=bad.with_suffix('');prior.mkdir(exist_ok=True);(prior/'report.html').write_text('old report')
            click(app,'删除');dialog=Desktop(backend='uia').window(title='删除损坏的压缩包',process=proc.pid);dialog.wait('visible',timeout=10)
            dialog.child_window(auto_id='7',control_type='Button').invoke();assert bad.exists()
            click(app,'删除');dialog.wait('visible',timeout=10);dialog.child_window(auto_id='6',control_type='Button').invoke()
            wait(lambda:not bad.exists());wait(lambda:'bad.tgz' not in texts(app));assert (prior/'report.html').exists()
            # 重新下载完整包后正常进入监控。
            package(bad);wait(lambda:bool(buttons(app,'打开 HTML')),25);assert texts(app).count('bad.tgz')==1
            app.capture_as_image().save(str(out/('complete-'+str(int(scale*100))+'.png')))
            print('PASS: monitoring, cancel/retry, failure/recovery, compact rows, cleanup confirmation/scope; scale='+str(scale),flush=True)
        except Exception:
            try:
                print(texts(app),flush=True);app.capture_as_image().save(str(out/'failure.png'))
            except Exception:pass
            raise
        finally:proc.terminate();proc.wait(timeout=10)
