// Execute the actual apply.uc with mock UCI/app modules and system()/exit().
// All commands are captured; no router, DNS, firewall, or service is touched.
const recovery_test_context = { config: {}, states: [] };
let passed = 0;
for (let policy in ['direct', 'block']) {
    recovery_test_context.config = { enabled: '1', mode: 'global', failure_policy: policy, revision: 'isolated' };
    recovery_test_context.states = [];
    const commands = [];
    let exited = false;
    try {
        include('../luci-app-zray/root/usr/share/zray-ui/apply.uc', {
            recovery_test_context,
            system: command => {
                push(commands, join(' ', command));
                if (command[1] == 'start') return 1;
                if (command[1] == 'stop') return 1; // Force an additional cleanup failure.
                return 0;
            },
            warn: message => {},
            exit: code => { exited = code == 1; die('test-exit'); }
        });
    } catch (e) { if (e.message != 'test-exit') die(e.message); }
    assert(exited, '启动失败必须返回失败状态'); passed++;
    assert(index(commands, '/usr/bin/ucode /usr/share/zray-ui/cleanup.uc') >= 0, '停止服务失败后仍须清理和恢复 DNS'); passed++;
    const state = recovery_test_context.states[-1];
    assert(state.phase == 'error' && state.revision == 'isolated', '清理失败仍必须记录最终错误状态'); passed++;
    assert((index(commands, '/usr/libexec/zray-ui-rules failed') >= 0) == (policy == 'block'), '仅显式断网保护才能安装阻断规则'); passed++;
}
recovery_test_context.allowWrites = true;
recovery_test_context.config.failure_policy = 'direct';
recovery_test_context.states = [];
const commands = [];
include('../luci-app-zray/root/usr/share/zray-ui/apply.uc', {
    recovery_test_context,
    system: command => { push(commands, join(' ', command)); return 0; },
    warn: message => {},
    exit: code => { die('Unexpected exit: ' + code); }
});
assert(recovery_test_context.states[-1].phase == 'idle', '正常启动完成'); passed++;
assert(index(commands, '/etc/init.d/zray-ui start') < index(commands, '/etc/init.d/zray-dns start'), 'DNS 服务在主进程启动退出后调用'); passed++;
assert(index(commands, '/etc/init.d/https-dns-proxy start') < 0, '不再启动有额外联动的全局 DNS 服务'); passed++;
assert(index(commands, '/usr/bin/ucode /usr/share/zray-ui/activate-dns.uc') >= 0, '节点验证成功后启用 DNS 转发'); passed++;
print({apply_integration_passed: passed});
