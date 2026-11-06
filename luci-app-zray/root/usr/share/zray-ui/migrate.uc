import * as fs from 'fs';
import { cursor } from 'uci';
import * as app from 'zray_ui';

const uci = cursor();
function finish_migration() {
    app.checked(uci.set('zray', 'main', 'migration_done', '1'), '保存迁移状态失败。');
    app.checked(uci.save('zray'), '保存迁移配置失败。');
    app.checked(uci.commit('zray'), '提交迁移配置失败。');
}
const config = app.settings();
if (config.migration_done == '1') exit(0);
if (length(app.nodes(false)) || config.revision != 'initial') {
    finish_migration();
    exit(0);
}
let path = '/mnt/zray/config.json';
if (!fs.access(path)) path = '/mnt/zray/.scratch/ui-migration.json';
if (!fs.access(path)) {
    finish_migration();
    exit(0);
}
const old = json(fs.readfile(path));
const node = {
    name: '现有节点', server: old.server, port: old.port || 443,
    uuid: old.uuid, sni: old.sni || old.server,
    public_key: old.public_key, short_id: old.short_id || ''
};
assert(!app.validate(node), '现有节点无法迁移：' + app.validate(node));
app.checked(uci.set('zray', 'existing', 'node'), '创建现有节点失败。');
for (let key, value in node) app.checked(uci.set('zray', 'existing', key, '' + value), '保存现有节点失败。');
app.checked(uci.set('zray', 'main', 'node', 'existing'), '选择现有节点失败。');
if (old.bootstrap_dns) app.checked(uci.set('zray', 'main', 'bootstrap_dns', old.bootstrap_dns), '保存启动 DNS 失败。');
const enabled = app.live('zray-transparent') || app.live('zray');
app.checked(uci.set('zray', 'main', 'enabled', enabled ? '1' : '0'), '保存主开关失败。');
finish_migration();
print('已导入现有节点。\n');
