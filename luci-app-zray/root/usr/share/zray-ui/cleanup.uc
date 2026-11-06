import * as fs from 'fs';
import * as app from 'zray_ui';
import { run_steps } from 'zray_recovery';

const errors = run_steps([
    { label: '清理代理转发规则失败', run: () => system(['/usr/libexec/zray-ui-rules', 'stop']) == 0 },
    { label: '停止代理 DNS 失败', run: () => !fs.access('/mnt/zray/.scratch/ui-doh-original') || !app.live('zray-dns') || system(['/etc/init.d/zray-dns', 'stop']) == 0 },
    { label: '恢复原有 DNS 失败', run: () => system(['/usr/bin/ucode', '/usr/share/zray-ui/restore-dns.uc']) == 0 }
]);
if (length(errors)) { warn(join('；', errors) + '\n'); exit(1); }
