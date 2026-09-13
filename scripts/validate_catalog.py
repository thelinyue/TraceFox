"""隔离可执行文件和规则，验证日志目录 CRUD、来源引用、分栏拖动与缩放。"""
import ctypes, json, os, shutil, site, subprocess, sys, tempfile, time
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")
root=Path(__file__).resolve().parents[1]
deps=root/'validation/python_deps';site.addsitedir(str(deps));sys.path.extend([str(deps/'win32'),str(deps/'win32/lib')]);os.add_dll_directory(str(deps/'pywin32_system32'))
from pywinauto import Desktop, mouse
out=root/'target/catalog-validation';out.mkdir(parents=True,exist_ok=True)
def controls(e,kind):
 return [c for c in e.descendants(control_type=kind) if c.is_visible() and c.is_enabled() and c.rectangle().width()>0]
def button(e,name):
 return next(c for c in controls(e,'Button') if c.window_text()==name)
def click(e,name):
 button(e,name).invoke();time.sleep(.3)
def field(e,label,value):
 found=[c for c in controls(e,'Edit') if c.window_text()==label]
 assert found, (label,[(c.window_text(),c.get_value()) for c in controls(e,'Edit')]);found[0].set_edit_text(value)
def texts(e):return ' '.join(c.window_text() for c in e.descendants(control_type='Text') if c.is_visible())
def select_file(e,needle):
 next(c for c in controls(e,'Button') if needle in c.window_text() and '条规则' in c.window_text()).invoke();time.sleep(.2)
for scale in [1,1.5]:
 with tempfile.TemporaryDirectory(prefix='tracefox-catalog-') as tmp:
  profile=Path(tmp);exe=profile/'bin/TraceFox.exe';exe.parent.mkdir();shutil.copy2(root/'target/debug/TraceFox.exe',exe)
  config=exe.parent/'assets/default-rules.json';config.parent.mkdir();base=json.loads((root/'assets/default-rules.json').read_text(encoding='utf-8'))
  base['system']=[];base['rules']=[];base['log_files']=[];base['layout']['file_order']=[]
  config.write_text(json.dumps(base,ensure_ascii=False),encoding='utf-8');initial=config.read_bytes()
  env=os.environ.copy();env['LOCALAPPDATA']=str(profile);env['SLINT_SCALE_FACTOR']=str(scale)
  proc=subprocess.Popen([str(exe)],env=env)
  try:
   app=Desktop(backend='uia').window(title='TraceFox',process=proc.pid);app.wait('visible',timeout=20);click(app,'规则管理')
   e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid);e.wait('visible',timeout=10)
   Desktop(backend='win32').window(handle=e.handle).move_window(x=0,y=0,width=round(1160*scale),height=min(round(760*scale),ctypes.windll.user32.GetSystemMetrics(1)-40));time.sleep(.5)
   print('opened',scale,flush=True)
   click(e,'新增日志文件');field(e,'日志名称','临时日志');field(e,'归档内路径','log/cancel.log');e.type_keys('{ESC}');time.sleep(.2)
   assert config.read_bytes()==initial
   click(e,'新增日志文件');field(e,'日志名称','关闭撤回');Desktop(backend='win32').window(handle=e.handle).send_message(0x10);time.sleep(.3)
   assert e.is_visible() and not any(c.window_text()=='日志名称' for c in controls(e,'Edit'))
   click(e,'新增日志文件');field(e,'日志名称','自定义中文日志');field(e,'归档内路径','log/custom.log');click(e,'完成')
   assert not any(c.window_text()=='日志名称' for c in controls(e,'Edit')), texts(e)
   assert config.read_bytes()==initial
   select_file(e,'自定义中文日志');click(e,'添加规则到此日志文件')
   check=controls(e,'CheckBox');assert len(check)==1 and check[0].get_toggle_state()==1
   controls(e,'Edit')[0].set_edit_text('目录引用规则');click(e,'下一步')
   controls(e,'Edit')[0].set_edit_text('error');click(e,'下一步');click(e,'完成添加')
   click(e,'删除日志文件');assert '引用' in texts(e)
   click(e,'编辑日志文件');field(e,'日志名称','已改名日志');field(e,'归档内路径','log/renamed.log');click(e,'完成');click(e,'保存全部')
   saved=json.loads(config.read_text(encoding='utf-8'));assert saved['log_files'][0]['name']=='已改名日志';assert saved['rules'][0]['source_file_ids']==[saved['log_files'][0]['id']];assert 'sources' not in saved['rules'][0]
   assert 'log/renamed.log' not in ' '.join(c.window_text() for c in e.descendants() if c.is_visible())
   click(e,'新增日志文件');field(e,'日志名称','已改名日志');field(e,'归档内路径','log/other.log');click(e,'完成');assert '名称重复' in texts(e);click(e,'取消')
   click(e,'新增日志文件');field(e,'日志名称','第二日志');field(e,'归档内路径','log/two.log');click(e,'完成');click(e,'删除日志文件');assert '第二日志' not in texts(e)
   click(e,'新增日志文件');field(e,'日志名称','ZIP日志');field(e,'归档内路径','log/z.log')
   combo=controls(e,'ComboBox')[-1];rect=combo.rectangle();combo.click_input();time.sleep(.2);mouse.click(coords=(rect.left+round(70*scale),rect.top+round(60*scale)));time.sleep(.2);click(e,'完成');assert '暂不支持 ZIP' in texts(e);click(e,'取消')
   click(e,'新增日志文件');field(e,'日志名称','共享来源');field(e,'归档内路径','other/shared.log');click(e,'完成')
   select_file(e,'已改名日志');click(e,'编辑')
   checks=controls(e,'CheckBox');source=next(c for c in checks if '共享来源' in c.window_text());source.toggle();time.sleep(.2)
   assert 'other/shared.log' not in ' '.join(c.window_text() for c in controls(e,'CheckBox'))
   click(e,'完成');click(e,'保存全部');assert len(json.loads(config.read_text(encoding='utf-8'))['rules'][0]['source_file_ids'])==2
   slider=controls(e,'Slider')[0];r=slider.rectangle();start=(r.left+r.width()//2,r.top+r.height()//2);end=(start[0]+round(70*scale),start[1])
   mouse.press(coords=start)
   for n in range(1,8):mouse.move(coords=(start[0]+round((end[0]-start[0])*n/7),start[1]));time.sleep(.04)
   mouse.release(coords=end);time.sleep(.3);click(e,'保存全部');width=json.loads(config.read_text(encoding='utf-8'))['layout']['file_panel_width'];assert 300<=width<=315,width
   e.capture_as_image().save(str(out/f'catalog-{scale}.png'))
   click(e,'取消');click(app,'规则管理');e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid)
   Desktop(backend='win32').window(handle=e.handle).move_window(x=0,y=0,width=round(1160*scale),height=min(round(760*scale),ctypes.windll.user32.GetSystemMetrics(1)-40));time.sleep(.3)
   click(e,'保存全部');assert json.loads(config.read_text(encoding='utf-8'))['layout']['file_panel_width']==width
   Desktop(backend='win32').window(handle=e.handle).move_window(x=0,y=0,width=round(800*scale),height=round(580*scale));time.sleep(.3)
   assert not controls(e,'Slider');assert controls(e,'ComboBox')
   click(e,'编辑日志文件');e.capture_as_image().save(str(out/f'catalog-modal-{scale}.png'));finish=button(e,'完成').rectangle();bounds=e.rectangle();assert bounds.top<=finish.top<finish.bottom<=bounds.bottom
   click(e,'取消');click(e,'取消');print('PASS catalog CRUD, draft cancel, references, width/reopen, compact, scale',scale,flush=True)
  except Exception:
   if 'e' in locals():
    try:e.capture_as_image().save(str(out/f'failure-{scale}.png'));print(texts(e),flush=True)
    except Exception:pass
   raise
  finally:proc.terminate();proc.wait(timeout=10)
