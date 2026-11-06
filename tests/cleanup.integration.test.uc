// Exercise the production cleanup entry point with no real system calls.
const recovery_test_context = { backupPresent: true, live: true };
let passed = 0;
for (let failure in [0, 1, 2, -1]) {
    const commands = [];
    let code = 0;
    try {
        include('../luci-app-zray/root/usr/share/zray-ui/cleanup.uc', {
            recovery_test_context,
            system: command => {
                push(commands, join(' ', command));
                return length(commands) - 1 == failure ? 1 : 0;
            },
            warn: message => {},
            exit: status => { code = status; die('test-exit'); }
        });
    } catch (e) { if (e.message != 'test-exit') die(e.message); }
    assert(length(commands) == 3, '任一步失败时仍执行全部清理步骤'); passed++;
    assert(commands[2] == '/usr/bin/ucode /usr/share/zray-ui/restore-dns.uc', '始终尝试恢复 DNS'); passed++;
    assert(code == (failure >= 0 ? 1 : 0), '清理失败必须准确返回错误'); passed++;
}
print({cleanup_integration_passed: passed});
