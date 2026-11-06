import { run_steps } from 'zray_recovery';
let passed = 0;
function check(value, message) { assert(value, message); passed++; }
for (let fail in [-1, 0, 1, 2]) {
    const visited = [];
    const tasks = map(['remove_rules', 'stop_dns', 'restore_dns'], (name, i) => ({
        label: name, run: () => { push(visited, name); return i != fail; }
    }));
    const errors = run_steps(tasks);
    check(join(',', visited) == 'remove_rules,stop_dns,restore_dns', '单步失败不得跳过其他恢复步骤');
    check(length(errors) == (fail < 0 ? 0 : 1), '恢复步骤错误报告');
}
const visited = [];
const errors = run_steps([
    {label: 'stop_proxy', run: () => { push(visited, 'stop'); die('injected failure'); }},
    {label: 'cleanup', run: () => { push(visited, 'cleanup'); return false; }},
    {label: 'restore_dns', run: () => { push(visited, 'dns'); return true; }}
]);
check(join(',', visited) == 'stop,cleanup,dns', '异常和失败不能提前终止 DNS 恢复');
check(length(errors) == 2, '保留所有错误');
check(index(errors[0], 'injected failure') >= 0, '保留异常根因');
check(length(run_steps([])) == 0, '重复恢复无额外任务');
print({recovery_passed: passed});
