import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const root = new URL('../luci-app-zray/', import.meta.url);
const read = path => fs.readFileSync(new URL(path, root), 'utf8');

test('所有常驻服务都禁止 stdout/stderr 写入系统日志', () => {
    for (const service of ['zray-ui', 'zray-dns', 'zray-health']) {
        const source = read('root/etc/init.d/' + service);
        assert.match(source, /procd_set_param stdout 0/);
        assert.match(source, /procd_set_param stderr 0/);
        assert.doesNotMatch(source, /procd_set_param (stdout|stderr) 1/);
    }
});
test('设置任务和健康监控没有追加日志或 logger 调用', () => {
    for (const path of ['root/usr/libexec/zray-ui-apply', 'root/usr/libexec/zray-ui-monitor', 'root/usr/share/ucode/zray_ui.uc']) {
        const source = read(path);
        assert.doesNotMatch(source, />>|\blogger\b/);
        assert.match(source, /\/dev\/null 2>&1/);
    }
});
test('节点测试和探测错误仅即时返回，不创建日志文件', () => {
    assert.doesNotMatch(read('root/usr/share/zray-ui/test-node.uc'), /\.log|zray-ui-test-error/);
    const monitor = read('root/usr/share/ucode/zray_monitor.uc');
    const probe = monitor.slice(monitor.indexOf('export function probe'));
    assert.doesNotMatch(probe, /zray-ui-probe-error|fs\.readfile\(path\)/);
    assert.match(probe, /2>&1/);
    assert.match(monitor, /substr\(value.error, 0, 512\)/);
});
test('订阅临时内容总会清理，启动时删除旧版本私有日志', () => {
    const manage = read('root/usr/share/ucode/zray_manage.uc');
    assert.doesNotMatch(manage, /subscription-error/);
    assert.match(manage, /catch \(error\)[\s\S]*fs\.unlink\(output\)/);
    assert.match(read('postinst'), /cleanup-logs\.uc/);
    assert.doesNotMatch(read('postinst'), /touch.*\.log/);
});
test('移除日志 RPC 与 ACL，关闭时不启动健康守护进程', () => {
    const rpc = read('root/usr/libexec/rpcd/zray');
    assert.doesNotMatch(rpc, /method == 'logs'|logs: \{\}/);
    const acl = JSON.parse(read('root/usr/share/rpcd/acl.d/luci-app-zray.json'));
    assert.ok(!acl['luci-app-zray'].read.ubus.zray.includes('logs'));
    assert.match(read('root/etc/init.d/zray-health'), /enabled\)" = 1 \] \|\| return 0/);
});
