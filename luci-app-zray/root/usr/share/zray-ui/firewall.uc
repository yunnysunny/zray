import { cursor } from 'uci';
import * as app from 'zray_ui';

const uci = cursor();
app.checked(uci.load('firewall'), '读取防火墙设置失败。');
if (uci.get('firewall', 'zray_transparent'))
    app.checked(uci.delete('firewall', 'zray_transparent'), '更新旧版代理规则失败。');
app.checked(uci.set('firewall', 'zray_ui', 'include'), '创建防火墙联动失败。');
for (let key, value in { type: 'script', path: '/usr/libexec/zray-ui-rules', fw4_compatible: '1', enabled: '1' })
    app.checked(uci.set('firewall', 'zray_ui', key, value), '保存防火墙联动失败。');
app.checked(uci.save('firewall'), '保存防火墙配置失败。');
app.checked(uci.commit('firewall'), '提交防火墙配置失败。');
