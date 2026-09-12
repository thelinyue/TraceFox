// 验证报告实际使用的 SMART 判定函数，避免 Rust 测试遗漏浏览器脚本回归。
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../assets/report.html'), 'utf8');
new vm.Script(html.match(/<script>([\s\S]*)<\/script>/)[1]);
const start = html.indexOf('function smartNumber(');
assert.notEqual(start, -1, '报告应按 SMART 数值判定状态');
const context = vm.createContext({});
vm.runInContext(html.slice(start, html.indexOf('function storageView(', start)), context);
const t = {fields: ['id', 'name', 'raw_string', 'value', 'worst', 'thresh', 'status'].map(path => ({name:path, path}))};
const row = (name, raw_string, extra = {}) => ({name, raw_string, ...extra});
const health = rows => context.storageHealth(t, rows);
const status = rows => health(rows).status;
// 名称带 Error/Pending 不代表错误；厂商编码的大 Raw 值也不能当作坏扇区数。
assert.equal(status([row('Current_Pending_Sector', '0'), row('Offline_Uncorrectable', '0')]), '正常');
assert.equal(status([row('Raw_Read_Error_Rate', '160058752', {id:'1', value:'117', thresh:'6'}), row('Seek_Error_Rate', '26507335', {id:'7', value:'74', thresh:'30'})]), '正常');
assert.equal(status([row('UDMA_CRC_Error_Count', '5'), row('Reallocated_Sector_Ct', '0')]), '正常');
assert.equal(status([row('Reallocated_Sector_Ct', '40')]), '注意');
assert.equal(status([row('Current_Pending_Sector', '816')]), '异常');
assert.match(health([row('Offline_Uncorrectable', '816')]).reasons.join(' '), /816/);
assert.equal(status([row('Raw_Read_Error_Rate', '0', {id:'1', value:'6', thresh:'6'})]), '异常');
assert.equal(status([row('Airflow_Temperature_Cel', '39', {id:'190', value:'61', worst:'43', thresh:'45'})]), '注意');
assert.equal(status([row('Start_Stop_Count', '100', {id:'4', value:'0', thresh:'0'})]), '未检测');
assert.equal(status([row('critical_warning', '0x00'), row('media_errors', '0')]), '正常');
assert.equal(status([row('critical_warning', '0x01')]), '异常');
assert.equal(status([row('media_errors', '', {value:'2'})]), '异常');
assert.equal(status([row('percentage_used', '', {value:'100'})]), '注意');
assert.equal(status([row('Current_Pending_Sector', '', {value:'100'})]), '未检测');
for (const missing of ['', '未获取', 'garbage', '-1', '2 3 3']) {
    assert.equal(status([row('Current_Pending_Sector', missing)]), '未检测');
}
assert.equal(status([]), '未检测');
assert.equal(context.storageHealth(null, []).status, '未检测');
// 规则编辑器允许重命名列，判定必须按字段路径读取而非硬编码列标题。
assert.equal(context.storageHealth({fields:[{name:'自定义名称',path:'name'},{name:'自定义原始值',path:'raw_string'}]}, [{'自定义名称':'Offline_Uncorrectable','自定义原始值':'0'}]).status, '正常');
console.log('SMART 状态回归测试通过');
