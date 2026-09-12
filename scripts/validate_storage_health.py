"""在真实生成报告中点击硬盘、筛选及详情，验证 SMART 状态与原始数值。"""
import argparse
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'validation/python_deps'))
from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument('report', type=Path, help='test.tgz 生成的 report.html')
args = parser.parse_args()
output = root / 'validation/storage-health'
output.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(channel='msedge', headless=True)
    page = browser.new_page(viewport={'width': 1600, 'height': 1000})
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.goto(args.report.resolve().as_uri())
    page.wait_for_function("document.body.dataset.ready==='true'")
    page.locator('[data-page=storage]').click()
    cards = page.locator('.disk-row')
    assert cards.count() == 4
    expected = {'Hard Drive 1': '正常', 'Hard Drive 2': '正常',
                'Hard Drive 3': '异常', 'Hard Drive 4': '正常'}
    results = []
    for label, status in expected.items():
        card = cards.filter(has=page.locator('.disk-row-title', has_text=label))
        assert card.locator('.health').inner_text().endswith(status)
        card.locator('.disk-row-head').click()
        assert card.locator('.disk-details').is_visible()
        assert card.locator('.disk-row-title').inner_text() == label
        # 详情必须仍绑定原盘；将完整 SMART 表中的读数与原始磁盘位置关联核对。
        disk_index = int(label[-1]) - 1
        counts = page.evaluate('''i => {
            const t=report.system.find(t=>t.view==='storage');
            const c=t.storage[i];
            const smart=report.system.find(s=>s.view==='storage-smart'&&s.source===t.source&&s.group===t.group);
            return {info:c.details.length, smart:smart.rows.filter((r,j)=>smart.storage[j].device===c.device).length};
        }''', disk_index)
        card.locator('.disk-details details').last.click()
        tables = card.locator('.disk-details table')
        assert card.locator('.detail-field').count() >= 6
        assert tables.nth(0).locator('tr').count() == counts['smart'] + 1
        reason = card.locator('.disk-details .detail-intro').inner_text()
        if status == '异常':
            assert '待处理扇区：816' in reason and '离线不可校正扇区：816' in reason
        else:
            assert ('未触发风险条件' in reason or '缺少可判定' in reason)
        results.append({'label': label, 'status': status, 'reason': reason, **counts})
        card.locator('.disk-row-head').click()
        assert not card.locator('.disk-details').is_visible()
    for name, count in [('正常', 3), ('异常', 1), ('注意', 0), ('未检测', 0), ('全部', 4)]:
        page.locator('#storage .tabs').get_by_role('button', name=name, exact=True).click()
        assert cards.count() == count, name
    assert cards.first.locator('.disk-row-title').inner_text() == 'Hard Drive 3'
    assert '1 个需要关注' in page.locator('.pool-summary').inner_text()
    page.screenshot(path=str(output / 'report.png'), full_page=True)
    assert not errors, errors
    (output / 'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'statuses': expected, 'page_errors': errors, 'filters_and_dialogs': 'passed'}, ensure_ascii=True))
    browser.close()
