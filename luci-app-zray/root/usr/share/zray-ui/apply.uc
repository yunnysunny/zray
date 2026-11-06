import { cursor } from 'uci';
import * as fs from 'fs';
import * as app from 'zray_ui';
import * as policy from 'zray_policy';
import { run_steps } from 'zray_recovery';

const config = app.settings();
const before = app.state();
const policy_key = sprintf('%J', policy.options(config));
if (fs.access(app.state_path) && before.revision == config.revision && before.phase != 'applying') exit(0);
app.write_state({ revision: config.revision, phase: 'applying', error: '' });
try {
    const monitor_needed = config.enabled == '1' && config.mode != 'direct';
    if (monitor_needed && !app.live('zray-health')) system(['/etc/init.d/zray-health', 'start']);
    else if (!monitor_needed && app.live('zray-health')) system(['/etc/init.d/zray-health', 'stop']);
    let unchanged = false;
    if (fs.readfile('/tmp/zray-ui-applied-options') == policy_key && config.enabled == '1' && app.live('zray-ui') && app.live('zray-dns') && app.rules_active() && fs.access('/mnt/zray/config.json')) {
        const desired = app.runtime_config();
        const actual = json(fs.readfile('/mnt/zray/config.json'));
        unchanged = true;
        for (let key, value in desired)
            if (actual[key] !== value) unchanged = false;
    }
    if (!unchanged) {
        if (app.live('zray-ui') || config.enabled != '1' || app.rules_active())
            app.checked(system(['/etc/init.d/zray-ui', 'stop']) == 0, '停止代理服务失败。');
        if (config.enabled == '1' && config.mode != 'direct') {
            app.checked(system(['/etc/init.d/zray-ui', 'start']) == 0, '启用失败，请检查节点参数和运行日志。');
            app.checked(system(['/usr/libexec/zray-ui-rules', 'start']) == 0, '设置转发规则失败。');
            app.checked(system(['/usr/bin/ucode', '/usr/share/zray-ui/dns.uc']) == 0, '配置加密 DNS 失败。');
            if (app.live('https-dns-proxy'))
                app.checked(system(['/etc/init.d/https-dns-proxy', 'stop']) == 0, '停止原有加密 DNS 失败。');
            app.checked(system(['/etc/init.d/zray-dns', 'start']) == 0, '启动加密 DNS 失败。');
            app.checked(system(['/usr/bin/ucode', '/usr/share/zray-ui/activate-dns.uc']) == 0, '启用 DNS 转发失败。');
        }
    }
    app.checked(fs.writefile('/tmp/zray-ui-applied-options', policy_key), '保存生效设置失败。');
    app.write_state({ revision: config.revision, phase: 'idle', error: '' });
}
catch (error) {
    let message = error.message;
    const steps = [
        { label: '停止异常服务失败', run: () => system(['/etc/init.d/zray-ui', 'stop']) == 0 },
        { label: '清理转发或恢复 DNS 失败', run: () => system(['/usr/bin/ucode', '/usr/share/zray-ui/cleanup.uc']) == 0 }
    ];
    if (config.enabled == '1' && config.mode != 'direct' && config.failure_policy == 'block')
        push(steps, { label: '安装故障阻断规则失败', run: () => system(['/usr/libexec/zray-ui-rules', 'failed']) == 0 });
    const errors = run_steps(steps);
    if (length(errors)) message += '；' + join('；', errors);
    else message += config.enabled == '1' && config.mode != 'direct' && config.failure_policy == 'block'
        ? '；已按明确配置阻断所选设备的外网，路由器自身仍可连接以恢复服务。'
        : '；已清理代理规则并恢复原有 DNS，可继续普通直连上网。';
    app.write_state({ revision: config.revision, phase: 'error', error: message });
    warn(message + '\n');
    exit(1);
}
