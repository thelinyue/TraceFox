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
def source_query(e):
 found=[c for c in controls(e,'Edit') if c.window_text()=='日志来源筛选']
 assert found, [(c.window_text(),c.get_value()) for c in controls(e,'Edit')]
 return found[0]
def source_option(e,needle,source_rect):
 found=[]
 for window in Desktop(backend='uia').windows(process=e.process_id(),visible_only=True):
  for kind in ['Button','Text']:
   for c in window.descendants(control_type=kind):
    label=c.element_info.name or c.window_text()
    rect=c.rectangle()
    if c.is_visible() and needle in label and rect.top>=source_rect.bottom and abs(rect.right-source_rect.right)<=12:
     found.append(c)
 return found[-1] if found else None
def wait_source_option(e,needle,source_rect,present=True):
 for _ in range(15):
  found=source_option(e,needle,source_rect)
  if (found is not None)==present: return found
  time.sleep(.1)
 return found
def open_rule(e,name):
 row=next(c for c in controls(e,'Button') if name in c.window_text() or name in (c.element_info.name or ''))
 rect=row.rectangle()
 next(c for c in controls(e,'Button') if c.window_text()=='规则更多操作' and abs(c.rectangle().top-rect.top)<12).invoke();time.sleep(.2)
 next(c for c in controls(e,'Button') if c.window_text()=='编辑规则').invoke();time.sleep(.3)
def select_file(e,needle):
 row=next(c for c in controls(e,'Text') if needle in c.window_text() and '日志文件' not in c.window_text())
 rect=row.rectangle();mouse.click(coords=(rect.left+rect.width()//2,rect.top+rect.height()//2));time.sleep(.2)
def drag_file(e,source,target,scale):
 source_rect=next(c for c in controls(e,'Text') if source in c.window_text() and '日志文件' not in c.window_text()).rectangle()
 target_rect=next(c for c in controls(e,'Text') if target in c.window_text() and '日志文件' not in c.window_text()).rectangle()
 start=(source_rect.left+round(8*scale),source_rect.top+source_rect.height()//2)
 end=(target_rect.left+round(8*scale),target_rect.top+target_rect.height()//2)
 mouse.press(coords=start)
 for n in range(1,11):
  mouse.move(coords=(start[0]+(end[0]-start[0])*n//10,start[1]+(end[1]-start[1])*n//10));time.sleep(.04)
 mouse.release(coords=end);time.sleep(.4)
def file_top(e,needle):
 return next(c for c in controls(e,'Text') if needle in c.window_text() and '日志文件' not in c.window_text()).rectangle().top
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
   click(e,'添加日志文件');field(e,'日志名称','临时日志');field(e,'归档内路径','log/cancel.log');e.type_keys('{ESC}');time.sleep(.2)
   assert config.read_bytes()==initial
   click(e,'添加日志文件');field(e,'日志名称','关闭撤回');Desktop(backend='win32').window(handle=e.handle).send_message(0x10);time.sleep(.3)
   assert e.is_visible() and not any(c.window_text()=='日志名称' for c in controls(e,'Edit'))
   click(e,'添加日志文件');field(e,'日志名称','自定义中文日志');field(e,'归档内路径','log/custom.log');click(e,'完成')
   assert not any(c.window_text()=='日志名称' for c in controls(e,'Edit')), texts(e)
   assert config.read_bytes()==initial
   select_file(e,'自定义中文日志');click(e,'添加规则到当前日志文件')
   query=source_query(e);query.click_input();time.sleep(.3);source_rect=query.rectangle()
   assert wait_source_option(e,'自定义中文日志',source_rect) is not None
   query.set_edit_text('custom');assert wait_source_option(e,'自定义中文日志',source_rect) is not None
   query.set_edit_text('不存在的日志');assert wait_source_option(e,'自定义中文日志',source_rect,False) is None
   query.set_edit_text('');time.sleep(.3)
   rule_name=max((c for c in controls(e,'Edit') if c.rectangle().bottom<=source_rect.top),key=lambda c:c.rectangle().top)
   rule_name.click_input();rule_name.set_focus();assert wait_source_option(e,'自定义中文日志',source_rect,False) is None
   query.set_focus();assert wait_source_option(e,'自定义中文日志',source_rect) is not None
   controls(e,'Edit')[0].set_edit_text('目录引用规则');click(e,'下一步')
   controls(e,'Edit')[0].set_edit_text('error');click(e,'下一步');click(e,'完成添加')
   click(e,'日志文件更多操作');click(e,'删除日志文件');assert '引用' in texts(e)
   click(e,'日志文件更多操作');click(e,'编辑日志文件');field(e,'日志名称','已改名日志');field(e,'归档内路径','log/renamed.log');click(e,'完成');click(e,'保存全部')
   saved=json.loads(config.read_text(encoding='utf-8'));assert saved['log_files'][0]['name']=='已改名日志';assert saved['rules'][0]['source_file_ids']==[saved['log_files'][0]['id']];assert 'sources' not in saved['rules'][0]
   assert 'log/renamed.log' not in ' '.join(c.window_text() for c in e.descendants() if c.is_visible())
   click(e,'添加日志文件');field(e,'日志名称','已改名日志');field(e,'归档内路径','log/other.log');click(e,'完成');assert '名称重复' in texts(e);click(e,'取消')
   click(e,'添加日志文件');field(e,'日志名称','第二日志');field(e,'归档内路径','log/two.log');click(e,'完成');click(e,'日志文件更多操作');click(e,'删除日志文件');assert '第二日志' not in texts(e)
   click(e,'添加日志文件');field(e,'日志名称','ZIP日志');field(e,'归档内路径','log/z.log')
   combo=controls(e,'ComboBox')[-1];rect=combo.rectangle();combo.click_input();time.sleep(.2);mouse.click(coords=(rect.left+round(70*scale),rect.top+round(60*scale)));time.sleep(.2);click(e,'完成');assert '暂不支持 ZIP' in texts(e);click(e,'取消')
   click(e,'添加日志文件');field(e,'日志名称','共享来源');field(e,'归档内路径','other/shared.log');click(e,'完成')
   drag_file(e,'已改名日志','共享来源',scale);assert file_top(e,'共享来源')<file_top(e,'已改名日志')
   click(e,'保存全部');saved=json.loads(config.read_text(encoding='utf-8'));by_name={f['name']:f['id'] for f in saved['log_files']};assert saved['layout']['file_order'][:2]==[by_name['共享来源'],by_name['已改名日志']]
   drag_file(e,'已改名日志','共享来源',scale);assert file_top(e,'已改名日志')<file_top(e,'共享来源')
   click(e,'保存全部');saved=json.loads(config.read_text(encoding='utf-8'));assert saved['layout']['file_order'][:2]==[by_name['已改名日志'],by_name['共享来源']]
   select_file(e,'已改名日志');open_rule(e,'目录引用规则')
   query=source_query(e);query.click_input();time.sleep(.3);source_rect=query.rectangle()
   source=wait_source_option(e,'共享来源',source_rect);assert source is not None
   source_rect=source.rectangle();mouse.click(coords=(source_rect.left+source_rect.width()//2,source_rect.top+source_rect.height()//2));time.sleep(.3)
   click(e,'完成');click(e,'保存全部');assert len(json.loads(config.read_text(encoding='utf-8'))['rules'][0]['source_file_ids'])==2
   initial_width=json.loads(config.read_text(encoding='utf-8'))['layout']['file_panel_width']
   e.set_focus();time.sleep(.2);slider=controls(e,'Slider')[0];r=slider.rectangle();start=(r.left+r.width()//2,r.top+r.height()//2);end=(start[0]+round(70*scale),start[1])
   mouse.press(coords=start)
   for n in range(1,8):mouse.move(coords=(start[0]+round((end[0]-start[0])*n/7),start[1]));time.sleep(.04)
   mouse.release(coords=end);time.sleep(.3);click(e,'保存全部');width=json.loads(config.read_text(encoding='utf-8'))['layout']['file_panel_width'];assert 180<=width<=360 and width!=initial_width,(initial_width,width)
   e.capture_as_image().save(str(out/f'catalog-{scale}.png'))
   click(e,'取消');click(app,'规则管理');e=Desktop(backend='uia').window(title='TraceFox · 规则编辑',process=proc.pid)
   Desktop(backend='win32').window(handle=e.handle).move_window(x=0,y=0,width=round(1160*scale),height=min(round(760*scale),ctypes.windll.user32.GetSystemMetrics(1)-40));time.sleep(.3)
   click(e,'保存全部');assert json.loads(config.read_text(encoding='utf-8'))['layout']['file_panel_width']==width
   Desktop(backend='win32').window(handle=e.handle).move_window(x=0,y=0,width=round(800*scale),height=round(580*scale));time.sleep(.3)
   assert not controls(e,'Slider');assert controls(e,'ComboBox')
   click(e,'日志文件更多操作');click(e,'编辑日志文件');e.capture_as_image().save(str(out/f'catalog-modal-{scale}.png'));finish=button(e,'完成').rectangle();bounds=e.rectangle();assert bounds.top<=finish.top<finish.bottom<=bounds.bottom
   click(e,'取消');click(e,'取消');print('PASS catalog CRUD, draft cancel, references, width/reopen, compact, scale',scale,flush=True)
  except Exception:
   if 'e' in locals():
    try:e.capture_as_image().save(str(out/f'failure-{scale}.png'));print(texts(e),flush=True)
    except Exception:pass
   raise
  finally:proc.terminate();proc.wait(timeout=10)
