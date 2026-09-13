"""用浏览器验证当前离线模板；真实报告只读取数据，另生成验证副本。"""
import argparse
import base64
import gzip
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
deps = root / "validation" / "python_deps"
if deps.exists():
    sys.path.insert(0, str(deps))
from playwright.sync_api import sync_playwright
from report_data import load_report


def fixture():
    """覆盖跨规则重复行、重叠上下文、分页外命中和独立 SMART 视图。"""
    def line(n, hit=False):
        text = f"2026-09-11 10:00:00 日志 {n}" + (" TARGET" if n == 250 else "")
        return dict(number=n, text=text, hit=hit, ranges=[[20, 26]] if hit else [])

    def fragment(file, start, end, hits):
        return dict(file=file, time="2026-09-11 10:00:00", annotation="上下文说明",
                    lines=[line(n, n in hits) for n in range(start, end + 1)])

    def finding(id, count, fragments, target="keywords"):
        return dict(rule=dict(id=id, name=id, group="存储服务", note="匹配说明 <script>安全文本</script>",
                              target=target, open=False, source_file_ids=sorted({"event" if target=="timeline" else "storage" if f["file"].endswith("storage.log") else "kern" for f in fragments}) or ["kern"]), count=count, fragments=fragments,
                    status="已提取" if count else "来源文件缺失")

    a = fragment("logs/kern.log", 1, 300, {20, 250})
    overlap = fragment("logs/kern.log", 19, 25, {20})
    b = fragment("logs/storage.log", 1, 30, {20})
    fields = [dict(name="型号", path="model", missing="未提供", view="cards"),
              dict(name="容量", path="size", missing="未提供", view="cards")]
    storage = [dict(device="0", label="Hard Drive 1", pool="Storage Pool 1", raid="RAID1"),
               dict(device="1", label="M.2 Hard Drive 1", pool="Storage Pool 1", raid="RAID1")]
    base = dict(id="disks", name="磁盘信息", source="disk.json", group="存储", view="storage",
                warning="", fields=fields, rows=[{"型号": "HDD 示例", "容量": "8 TB"},
                                              {"型号": "NVMe 示例", "容量": "1 TB"}], storage=storage)
    smart = dict(id="smart", name="SMART", source="disk.json", group="存储", view="storage-smart",
                 warning="", fields=[dict(name="属性", path="name", missing=""),
                                      dict(name="Raw", path="raw_string", missing=""),
                                      dict(name="Current", path="value", missing="")],
                 rows=[{"属性": "Reallocated_Sector_Ct", "Raw": "0", "Current": "100"},
                       {"属性": "media_errors", "Raw": "2", "Current": "99"}], storage=storage)
    event = dict(name="设备复位原因", group="系统事件", time="2026-09-11T10:00:00+08:00",
                 key="2026-09-11T02:00:00Z", note="原始技术说明 UNKNOWN",
                 event_type="reset_reason", evidence_strength="strong", time_precision="exact",
                 sources=[a])

    def session(id, time, classification, confidence="高", end=None, precision="exact"):
        return dict(session_id=id, boot_time=time, boot_time_precision="exact",
                    incident_time_start=time, incident_time_end=end,
                    incident_time_precision=precision, boot_id="fixture-boot-id",
                    facts=[event], end_classification=classification, confidence=confidence,
                    supporting_evidence=["硬盘在启动过程中被重新识别"],
                    limitations=["设备自身没有记录明确原因"])

    sessions = [
        session("s7", "2026-09-11T10:00:00+08:00", "疑似断电", "中",
                "2026-09-11T10:03:00+08:00", "range"),
        session("s6", "2026-09-11T09:00:00+08:00", "硬件复位"),
        session("s5", "2026-09-11T08:00:00+08:00", "Watchdog 重启"),
        session("s4", "2026-09-11T07:00:00+08:00", "Kernel Panic 重启"),
        session("s3", "2026-09-11T06:00:00+08:00", "正常重启"),
        session("s2", "2026-09-11T05:00:00+08:00", "正常关机"),
        session("s1", "2026-09-11T04:00:00+08:00", "未知复位", "低", precision="unknown"),
    ]
    return dict(log_files=[dict(id=id,name=name,path=path,mode="exact",container="diagnostic_archive") for id,name,path in [("kern","内核日志","logs/kern.log"),("storage","存储日志","logs/storage.log"),("event","事件日志","logs/event.log"),("disk","设备信息","disk.json")]],
                source_labels={"logs/kern.log":"内核日志 · kern.log","logs/storage.log":"存储日志 · storage.log"},
                source_catalog={"logs/kern.log":["kern"],"logs/storage.log":["storage"],"logs/event.log":["event"]},
                system_file_ids={"disks":"disk","smart":"disk"},package="测试诊断包.tgz", generated="2026-09-11 12:00:00",
                layout=dict(title="诊断信息汇总", system_title="系统信息", keyword_title="关键词线索",
                            timeline_title="事件时间线", sections=["keywords", "timeline"], accent="#2468d8",
                            font_size=14, density="comfortable", timeline_sort="desc",
                            first_open=True, log_lines_per_batch=50),
                findings=[finding("SATA 链路记录", 3, [a, overlap, b]),
                          finding("未命中规则", 0, []),
                          finding("时间线规则", 1, [fragment("logs/event.log", 1, 2, {1})], "timeline")],
                events=[event], timeline_facts=[event], timeline_sessions=sessions,
                timeline_warnings=[], system=[base, smart],
                warnings=["日志读取失败 logs/storage.log：测试提示"])


def write_payload(path, payload, template):
    encoded = json.dumps(payload, ensure_ascii=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(template.replace("/*REPORT_DATA*/null", encoded), encoding="utf-8")
    return path


def write_report(path, data, template, compressed=True):
    """默认生成正式压缩格式；对象格式用于覆盖测试夹具兼容分支。"""
    if compressed:
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
        payload = "gzip-base64-v1:" + base64.b64encode(
            gzip.compress(raw, compresslevel=9, mtime=0)
        ).decode()
    else:
        payload = data
    return write_payload(path, payload, template)


parser = argparse.ArgumentParser()
parser.add_argument("samples", type=pathlib.Path, nargs="?")
parser.add_argument("--output", type=pathlib.Path, default=root / "validation/report-redesign/browser.json")
args = parser.parse_args()
folder = args.output.resolve().parent
template = (root / "assets/report.html").read_text(encoding="utf-8")
data = fixture()
report = write_report(folder / "fixture/report.html", data, template)
results = []
with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors, remote = [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("request", lambda req: remote.append(req.url) if req.url.startswith(("http:", "https:")) else None)

    def load(path):
        page.goto(path.as_uri(), wait_until="load", timeout=60000)
        page.wait_for_function("document.body.dataset.ready==='true'", timeout=60000)

    def search(text):
        page.locator("#search").fill(text)
        page.locator("#search-button").click()
        page.wait_for_function("document.querySelector('#search-results p')?.textContent.includes('个匹配位置')")

    load(report)
    assert page.locator("#keywords").is_visible()
    assert page.locator("#system").is_hidden()
    assert page.locator("[data-rule]").count() == 2
    assert page.locator(".file-group").count() == 2
    assert page.locator(".tree-group > summary").all_text_contents() == ["内核日志", "存储日志"]
    assert "内核日志 · kern.log" in page.locator(".file-link").first.inner_text()
    search("内核日志")
    assert page.locator("#search-results button").count() > 0

    page.wait_for_function("document.querySelectorAll('#findings .line').length===50")
    search("TARGET")
    page.locator("#search-results button").first.click()
    page.wait_for_function("document.querySelector('#findings .line.target')?.dataset.line==='250'")
    assert page.locator("#findings .line").count() == 50
    assert page.locator("#findings .line.target").inner_text().endswith("TARGET")
    page.wait_for_function("document.querySelector('#findings .line.target')?.dataset.line==='250'")
    search("storage.log")
    page.locator("#search-results button").first.click()
    assert page.locator('.file-group[data-file="logs/storage.log"]').get_attribute("open") is not None
    search("TARGET")
    page.locator("#search-results button").filter(has_text="时间线").click()
    assert page.locator("#timeline .line.target").get_attribute("data-line") == "250"
    # 时间线默认按倒序显示通俗结论，技术术语只在第二层详情中出现。
    page.locator("#navigation").get_by_role("button", name="事件时间线 · 7", exact=True).click()
    cards = page.locator("#events .session-card")
    assert cards.count() == 7
    first = cards.first
    assert first.locator(".session-time").inner_text() == "约 09-11 10:00–10:03"
    assert first.locator(".session-time").get_attribute("title") == (
        "2026-09-11T10:00:00+08:00 至 2026-09-11T10:03:00+08:00"
    )
    assert first.locator(".session-result").inner_text() == "疑似断电"
    assert "判断把握" not in first.locator(".session-head").inner_text()
    assert page.locator("#events .session-result").all_text_contents() == [
        "疑似断电", "设备发生硬件复位", "系统无响应后自动重启", "系统崩溃后重启",
        "正常重启", "正常关机", "无法判断上次关机原因",
    ]
    for technical_term in ["UNKNOWN", "reset_reason", "strong", "boot_id"]:
        assert technical_term not in first.locator(".session-head").inner_text()
    first.locator(":scope > details > summary").click()
    assert "为什么这样判断" in first.inner_text()
    assert "硬盘在启动过程中被重新识别" in first.inner_text()
    assert "判断把握：中" in first.inner_text()
    assert "为什么不能完全确定" in first.inner_text()
    assert "设备自身没有记录明确原因" in first.inner_text()
    first.locator(".technical-evidence > summary").click()
    page.wait_for_function("document.querySelector('#events .technical-evidence')?.textContent.includes('fixture-boot-id')")
    assert "boot_id：fixture-boot-id" in first.inner_text()
    assert "原始事件类型：reset_reason" in first.inner_text()
    assert "证据等级：strong" in first.inner_text()
    for label, expected in [("正常", 2), ("可能异常", 4), ("无法判断", 1), ("全部", 7)]:
        page.locator("#event-tabs").get_by_role("button", name=label, exact=True).click()
        assert page.locator("#events .session-card").count() == expected
    page.evaluate("preparePrint()")
    printed = page.locator("#print-content").inner_text()
    assert "为什么这样判断" in printed
    assert "boot_id：fixture-boot-id" in printed
    assert "原始事件类型：reset_reason" in printed
    assert "250 2026-09-11 10:00:00 日志 250 TARGET" in printed
    page.set_viewport_size({"width": 390, "height": 844})
    page.evaluate("document.documentElement.style.setProperty('--size','20px')")
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
    assert page.evaluate("document.querySelector('main').getBoundingClientRect().width>=360")
    page.evaluate("document.documentElement.style.setProperty('--size','14px')")
    page.set_viewport_size({"width": 1440, "height": 1000})
    # 点击当前行内详情，检查 HDD 与 M.2 的 SMART 证据没有串盘。
    page.locator("#navigation").get_by_role("button", name="硬盘与存储池", exact=True).click()
    assert page.locator(".disk-row").count() == 2
    for i, expected in enumerate(["HDD 示例", "NVMe 示例"]):
        row = page.locator(".disk-row").nth(i)
        row.locator(".disk-row-head").click()
        assert row.locator(".disk-details").is_visible()
        assert expected in row.inner_text()
        row.locator(".disk-details details").last.click()
        assert ("Reallocated_Sector_Ct" if i == 0 else "media_errors") in row.locator(".disk-details").inner_text()
        row.locator(".disk-row-head").click()
        assert row.locator(".disk-details").is_hidden()
    page.locator('[data-rule="0"]').first.click()
    page.evaluate("document.querySelector('#print-content').replaceChildren()")
    # 亮暗主题和移动目录、字体放大不能造成整页横向溢出。
    for theme in ["light", "dark"]:
        page.locator("#clear-search").click()
        page.emulate_media(color_scheme=theme, reduced_motion="reduce")
        page.screenshot(path=str(folder / f"desktop-{theme}.png"))
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
    page.set_viewport_size({"width": 390, "height": 844})
    page.locator("#menu-toggle").click()
    assert page.locator("#sidebar").is_visible()
    page.evaluate("document.documentElement.style.setProperty('--size','20px')")
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
    page.screenshot(path=str(folder / "mobile-dark.png"))
    results.append({"report": "fixture", "passed": True})

    # 无系统数据、无命中和独立 SMART 是合法的规则配置。
    empty = fixture()
    empty.update(findings=[], events=[], system=[], warnings=[])
    load(write_report(folder / "empty/report.html", empty, template, compressed=False))
    assert "未找到关键词匹配" in page.locator("#findings").inner_text()
    preview = fixture()
    preview["findings"] = []
    preview["events"] = []
    load(write_report(folder / "system-preview/report.html", preview, template))
    assert page.locator("#system").is_visible()
    standalone = fixture()
    standalone["system"] = standalone["system"][:2]
    standalone["system"].append(dict(id="lsblk", name="设备树（lsblk）", source="cmd/lsblk.log", group="存储", view="table", warning="", raw_text="NAME        SIZE TYPE  RO MOUNTPOINTS\\nmd0         7.3T raid1 0  /volume1\\nsda         8T   disk  0\\nsdb         8T   disk  0\\n", fields=[dict(name="设备", path="name"), dict(name="类型", path="type"), dict(name="容量", path="size"), dict(name="挂载点", path="mountpoint"), dict(name="父设备", path="pkname")], rows=[{"设备":"md0", "类型":"raid1", "容量":"7.3T", "挂载点":"/volume1", "父设备":""}, {"设备":"sda", "类型":"disk", "容量":"8T", "挂载点":"", "父设备":"md0"}, {"设备":"sdb", "类型":"disk", "容量":"8T", "挂载点":"", "父设备":"md0"}]))
    load(write_report(folder / "standalone/report.html", standalone, template))
    page.locator("#menu-toggle").click()
    page.locator("#navigation").get_by_role("button", name="硬盘与存储池", exact=True).click()
    raw_source = page.locator("#storage-content .raw-source")
    assert raw_source.count() == 1
    assert page.locator("#storage-content").locator(":scope > .raw-source").last.evaluate("node => node === node.parentElement.lastElementChild")
    assert raw_source.get_attribute("open") is None
    raw_source.locator("summary").click()
    assert raw_source.locator(".raw-log").is_visible()
    assert "NAME        SIZE TYPE" in raw_source.locator(".raw-log").inner_text()
    row = page.locator(".disk-row").first
    row.locator(".disk-row-head").click()
    assert "RAID1" in page.locator("#storage-content").inner_text()
    row.locator(".disk-details details").last.click()
    assert "重映射扇区计数" in row.locator(".disk-details").inner_text()
    row.locator(".disk-row-head").click()
    results.append({"report": "empty-and-standalone", "passed": True})

    large = fixture()
    large["findings"][0]["fragments"] = [dict(
        file="large.log", time="无法识别", annotation="", lines=[
            dict(number=n, text=f"日志 {n}" + (" needle-end" if n == 20000 else ""),
                 hit=True, ranges=[]) for n in range(20000, 0, -1)])]
    large["findings"][0]["count"] = 20000
    page.set_viewport_size({"width": 1440, "height": 1000})
    load(write_report(folder / "large/report.html", large, template))
    assert page.locator("#findings .line").count() == 50
    assert page.locator("#findings .line").first.get_attribute("data-line") == "20000"
    search("needle-end")
    page.locator("#search-results button").first.click()
    page.wait_for_function("document.querySelector('#findings .line.target')?.dataset.line==='20000'")
    assert page.locator("#findings .line").count() == 50
    results.append({"report": "20000-lines-reverse-order", "passed": True})

    if args.samples:
        page.set_viewport_size({"width": 1440, "height": 1000})
        for original in sorted(args.samples.glob("*/report.html")):
            sample = load_report(original)
            load(write_report(folder / "samples" / original.parent.name / "report.html", sample, template))
            page.locator("#navigation").get_by_role("button", name=sample["layout"]["system_title"], exact=True).click()
            results.append({"report": original.parent.name, "passed": True})

    broken = write_payload(folder / "broken/report.html", "gzip-base64-v1:not-base64", template)
    failure = browser.new_page()
    failure.goto(broken.as_uri())
    failure.wait_for_function("document.body.dataset.ready==='error'")
    assert "报告数据解压或解析失败" in failure.locator("#findings").inner_text()
    failure.close()

    unsupported = browser.new_page()
    unsupported.add_init_script(
        "Object.defineProperty(globalThis,'DecompressionStream',{value:undefined,configurable:true})"
    )
    unsupported.goto(report.as_uri())
    unsupported.wait_for_function("document.body.dataset.ready==='error'")
    assert "请使用最新版 Edge 或 Chrome" in unsupported.locator("#findings").inner_text()
    unsupported.close()
    results.append({"report": "compressed-errors", "passed": True})
    assert not errors, errors
    assert not remote, remote
    browser.close()
args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(results, ensure_ascii=True, indent=2))
