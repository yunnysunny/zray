import * as fs from 'fs';
import * as app from 'zray_ui';

const backup = '/mnt/zray/.scratch/ui-doh-original';
if (!fs.access(backup)) exit(0);
const restart = fs.readfile(backup + '.running') == '1';
app.checked(fs.writefile('/etc/config/https-dns-proxy', fs.readfile(backup)), '恢复原有 DNS 设置失败。');
app.checked(fs.unlink(backup), '清理 DNS 设置备份失败。');
app.checked(fs.unlink(backup + '.running'), '清理 DNS 状态备份失败。');
if (restart)
    app.checked(system(['/etc/init.d/https-dns-proxy', 'start']) == 0, '恢复原有 DNS 服务失败。');
