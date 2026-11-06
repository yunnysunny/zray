import { cursor } from 'uci';
import * as fs from 'fs';
import * as app from 'zray_ui';

const config = app.settings();
const before = app.state();
if (before.revision == config.revision && before.phase != 'applying') exit(0);
app.write_state({ revision: config.revision, phase: 'applying', error: '' });
try {
    let unchanged = false;
    if (config.enabled == '1' && app.live('zray-ui') && app.live('https-dns-proxy') && app.rules_active() && fs.access('/mnt/zray/config.json')) {
        const desired = app.runtime_config();
        const actual = json(fs.readfile('/mnt/zray/config.json'));
        unchanged = true;
        for (let key, value in desired)
            if (actual[key] !== value) unchanged = false;
    }
    if (!unchanged) {
        if (app.live('zray-ui'))
            app.checked(system(['/etc/init.d/zray-ui', 'stop']) == 0, '停止代理服务失败。');
        if (config.enabled == '1')
            app.checked(system(['/etc/init.d/zray-ui', 'start']) == 0, '启用失败，请检查节点参数和运行日志。');
    }
    app.write_state({ revision: config.revision, phase: 'idle', error: '' });
}
catch (error) {
    let message = error.message;
    if (app.live('zray-ui') && system(['/etc/init.d/zray-ui', 'stop']) != 0)
        message += '；停止异常服务失败，请查看系统日志。';
    const uci = cursor();
    if (uci.get('zray', 'main', 'revision') == config.revision) {
        app.checked(uci.set('zray', 'main', 'enabled', '0'), '恢复主开关状态失败。');
        app.checked(uci.save('zray'), '保存主开关状态失败。');
        app.checked(uci.commit('zray'), '提交主开关状态失败。');
    }
    app.write_state({ revision: config.revision, phase: 'error', error: message });
    warn(message + '\n');
    exit(1);
}
