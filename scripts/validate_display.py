"""离线报告分组、聚合与存储视图回归；仅使用虚构设备数据。"""
import json
import io
import subprocess
import sys
import tarfile
from pathlib import Path
root = Path(__file__).resolve().parents[1]
deps = root / 'validation' / 'python_deps'
if deps.exists():
    sys.path.insert(0, str(deps))
from playwright.sync_api import sync_playwright

out = root / 'target' / 'display-validation'
out.mkdir(parents=True, exist_ok=True)
layout = dict(title='TraceFox',system_title='系统信息',keyword_title='关键词线索',timeline_title='时间线',accent='#2468d8',font_size=14,density='comfortable',sections=['keywords','timeline'],first_open=True,log_lines_per_batch=10)
def line(n, text, hit=False, ranges=None):
    return dict(number=n, text=text, hit=hit, ranges=ranges or [])
def fragment(file, lines):
    return dict(file=file, lines=lines, time='2026-09-09 12:00:00', annotation='测试说明')
def finding(name, group, fragments):
    return dict(rule=dict(name=name, group=group, note='参考说明', target='keywords', open=False),
                count=len(fragments), fragments=fragments, status='已提取' if fragments else '未找到符合规则的日志')
fragments=[fragment('a.log',[line(1,'abcdef',True,[[0,3]]),line(2,'context')]),
           fragment('a.log',[line(1,'abcdef',True,[[2,6]]),line(2,'context'),line(4,'needle',True,[[0,6]])]),
           fragment('b.log',[line(1,'second file',True,[[0,6]])])]
findings=[finding('A1','A',fragments),finding('B1','B',fragments[:1]),finding('A2','A',fragments[:1]),finding('empty','空组',[])]
report=dict(layout=layout,package='虚构回归样例',generated='2026-09-09',warnings=[],system=[],findings=findings,events=[])
template=(root/'assets/report.html').read_text(encoding='utf-8')
path=out/'report.html'
path.write_text(template.replace('/*REPORT_DATA*/null',json.dumps(report,ensure_ascii=False)),encoding='utf-8')
# 通过正式提取入口生成虚构设备报告，验证提取与浏览器展示的连接。
sample={'deviceName':'测试设备','sn':'TEST','systemVersion':'1.0','platform':'test',
        'disk':{'devices':[
          {'disk_info':{'label':'Hard Drive 1','model':'same','used_for':'Storage Pool 1','size':1024},'smart_info':{'report':[{'id':5,'name':'Reallocated_Sector_Ct','raw_string':'7','value':100,'status':9}]}},
          {'disk_info':{'label':'M.2 Hard Drive 1','model':'same','used_for':'Unused','size':2048},'smart_info':{'report':[{'id':5,'name':'data_units_read','value':99}]}},
          {'disk_info':{},'smart_info':{'report':[]}}]},
        'network':{'interface':[{'name':'eth0','is_running':True,'ipv4':'192.0.2.1','ipv6':['2001:db8::1','2001:db8::2'],'NetInterface':{'MTU':1500}}]}}
archive=out/'storage.tgz'
with tarfile.open(archive,'w:gz') as tar:
    for name,content in [('sysinfo.json',json.dumps(sample)),('dmidecode.log','Memory Device\n\tLocator: DIMM 0\n\tSize: 8 GB\n\tManufacturer: Test\n\tPart Number: TestModel\n')]:
        payload=content.encode();info=tarfile.TarInfo(name);info.size=len(payload);tar.addfile(info,io.BytesIO(payload))
result=subprocess.run([str(root/'target/debug/TraceFox.exe'),'--analyze',str(archive)],capture_output=True,text=True,encoding='utf-8',check=True)
storage_path=Path(result.stdout.strip().splitlines()[-1])
with sync_playwright() as p:
    browser=p.chromium.launch(channel='msedge',headless=True)
    page=browser.new_page(viewport=dict(width=1280,height=900))
    errors=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    page.goto(path.as_uri())
    assert page.locator('#keyword-tabs button').all_text_contents()==['全部','A','B']
    assert page.locator('#findings summary').all_text_contents()==['A1　3 处匹配 / 3 个片段','A2　1 处匹配 / 1 个片段','B1　1 处匹配 / 1 个片段']
    page.locator('#show-empty').check()
    page.locator('#keyword-tabs').get_by_role('button',name='空组',exact=True).click()
    page.locator('#show-empty').uncheck()
    assert page.locator('#keyword-tabs button.active').inner_text()=='全部'
    assert '空组' not in page.locator('#keyword-tabs').inner_text()
    d=page.locator('#findings details[data-index="0"]')
    d.evaluate('(d)=>d.showFragment(0)')
    page.wait_for_function("document.querySelector('#findings details[data-index=\"0\"]').textContent.includes('4 行（重叠上下文已合并）')")
    assert d.locator('.log').count()==1
    assert d.locator('.line').count()==4
    assert d.locator('.log-source').count()==0
    assert d.get_by_role('button',name='上一处',exact=True).count()==0
    assert d.get_by_role('button',name='下一处',exact=True).count()==0
    assert d.get_by_role('button',name='展开全部匹配',exact=True).count()==0
    assert d.locator('select').count()==0
    assert d.get_by_role('button',name='收起',exact=True).count()==1
    assert d.locator('mark').first.inner_text()=='abcdef'
    d.get_by_role('button',name='切换换行',exact=True).click()
    assert d.locator('.log.wrap').count()==1
    page.evaluate("window.copied='';Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.copied=text}}})")
    d.get_by_role('button',name='复制全部匹配',exact=True).click()
    copied=page.evaluate('window.copied')
    assert copied=='abcdef\ncontext\nneedle\nsecond file'
    page.locator('#search').fill('needle')
    page.locator('#search-button').click()
    page.locator('#search-results button').first.click()
    assert page.locator('#findings details[data-index="0"] select').count()==0
    page.wait_for_selector('#findings details[data-index="0"] .line[data-line="4"]')
    assert page.locator('#findings details[data-index="0"] .line[data-line="4"]').count()==1
    # 在同一事件循环内重复定位，旧批次不得写入新视图。
    page.evaluate("""() => {const d=document.querySelector('#findings details');d.showFragment(0);d.showFragment(0)}""")
    page.wait_for_timeout(100)
    assert page.locator('#findings details').first.locator('.line').count()==4
    page.evaluate("""() => {report.findings[0].fragments=Array.from({length:3000},(_,i)=>({file:'large.log',time:'',annotation:'',lines:[{number:i+1,text:'row '+i,hit:true,ranges:[]}]}));showFindings('全部');const d=document.querySelector('#findings details');d.showFragment(0)}""")
    page.wait_for_function("document.querySelector('#findings details').textContent.includes('3000 行（重叠上下文已合并）')")
    large=page.locator('#findings details').first
    assert large.locator('.line').count()==10
    action_style=large.locator('.finding-actions').evaluate("e=>({position:getComputedStyle(e).position,buttonHeight:e.querySelector('button').getBoundingClientRect().height})")
    assert action_style['position']=='sticky' and action_style['buttonHeight']>=44
    large.get_by_role('button',name='继续显示 10 行',exact=True).click()
    assert large.locator('.line').count()==20
    for _ in range(18):
        large.get_by_role('button',name='继续显示 10 行',exact=True).click()
    page.evaluate("window.scrollTo(0, document.querySelector('#findings details .log').getBoundingClientRect().top + window.scrollY + 500)")
    sticky_top=large.locator('.finding-actions').evaluate("e=>e.getBoundingClientRect().top")
    assert 0<=sticky_top<=12,sticky_top
    large.get_by_role('button',name='收起',exact=True).click()
    page.wait_for_function("document.querySelector('#findings details').open===false")
    assert page.evaluate("document.activeElement===document.querySelector('#findings details summary')")
    page.screenshot(path=str(out/'keywords.png'),full_page=False)
    assert not errors,errors
    mobile_errors=[]
    mobile=browser.new_page(viewport=dict(width=390,height=844))
    mobile.emulate_media(reduced_motion='reduce')
    mobile.add_init_script("""const original=Element.prototype.scrollIntoView;Element.prototype.scrollIntoView=function(options){window.__scrollOptions=options;return original.call(this,options)}""")
    mobile.on('pageerror',lambda error:mobile_errors.append(str(error)))
    mobile.goto(path.as_uri())
    mobile.wait_for_selector('#findings details .finding-actions')
    assert mobile.locator('#findings details .finding-actions button').first.evaluate("e=>e.getBoundingClientRect().height")>=44
    mobile.locator('#findings details .finding-actions').get_by_role('button',name='收起',exact=True).click()
    mobile.wait_for_function('window.__scrollOptions')
    assert mobile.evaluate('window.__scrollOptions.behavior')=='auto'
    assert not mobile_errors,mobile_errors
    mobile.close()
    page.goto(storage_path.as_uri())
    assert page.locator('#system-tabs button').all_text_contents()==['设备概览','硬盘与存储池','网络接口','内存信息','补充信息']
    page.locator('#system-tabs').get_by_role('button',name='硬盘与存储池',exact=True).click()
    disks=page.locator('#system-content .disk')
    assert disks.count()==3
    assert 'Raw：7' in disks.nth(0).inner_text()
    assert 'Raw：7' not in disks.nth(1).inner_text()
    assert '重点 SMART' not in disks.nth(1).inner_text() # NVMe ID 5 不能当作 SATA 坏扇区。
    assert '未提供 SMART 属性' in disks.nth(2).inner_text()
    assert '未提供存储池信息' in page.locator('#system-content').inner_text()
    assert disks.nth(0).locator('details').get_attribute('open') is None
    disks.nth(0).locator('summary').click()
    assert '9' in disks.nth(0).locator('table').inner_text()
    page.screenshot(path=str(out/'storage.png'),full_page=True)
    page.locator('#system-tabs').get_by_role('button',name='网络接口',exact=True).click()
    assert '1500' in page.locator('#system-content').inner_text()
    assert '2001:db8::1\n2001:db8::2' in page.locator('#system-content').inner_text()
    page.locator('#system-tabs').get_by_role('button',name='内存信息',exact=True).click()
    assert 'TestModel' in page.locator('#system-content').inner_text()
    assert not errors,errors
    browser.close()
print('PASS: grouped order, empty groups, aggregate dedup/highlights/copy/wrap, navigation/search, cancellation, 3000 matches, storage identity/SMART, network, memory')
