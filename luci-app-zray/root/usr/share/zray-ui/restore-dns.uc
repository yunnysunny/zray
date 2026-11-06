import * as fs from 'fs';
import { cursor } from 'uci';
import * as app from 'zray_ui';
import { run_steps } from 'zray_recovery';

const backup = '/mnt/zray/.scratch/ui-doh-original';
if (!fs.access(backup)) exit(0);
const restart = fs.readfile(backup + '.running') == '1';
const errors = run_steps([
    { label: '恢复原有加密 DNS 设置失败', run: () => !!fs.writefile('/etc/config/https-dns-proxy', fs.readfile(backup)) },
    { label: '恢复原有 DNS 转发配置失败', run: () => {
        if (!fs.access(backup + '.dhcp')) return true;
        const saved = json(fs.readfile(backup + '.dhcp'));
        const uci = cursor();
        app.checked(uci.load('dhcp'), '读取 DHCP 配置失败');
        for (let name, values in saved) {
            if (uci.get('dhcp', name) != 'dnsmasq') continue;
            for (let key, value in values) {
                if (value == null) {
                    if (uci.get('dhcp', name, key) != null) app.checked(uci.delete('dhcp', name, key), '清理 DNS 选项失败');
                } else app.checked(uci.set('dhcp', name, key, value), '还原 DNS 选项失败');
            }
        }
        return uci.save('dhcp') && uci.commit('dhcp');
    } },
    { label: '恢复 DNS 转发服务失败', run: () => !fs.access(backup + '.dhcp') || system(['/etc/init.d/dnsmasq', 'reload']) == 0 },
    { label: '恢复原有加密 DNS 服务失败', run: () => !restart || system(['/etc/init.d/https-dns-proxy', 'start']) == 0 }
]);
if (length(errors)) { warn(join('；', errors) + '\n'); exit(1); }
// Retain recovery material until all services have been restored successfully.
for (let suffix in ['.dhcp', '.running', ''])
    if (fs.access(backup + suffix)) app.checked(fs.unlink(backup + suffix), '清理 DNS 备份失败。');
