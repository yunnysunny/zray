import * as fs from 'fs';
import { cursor } from 'uci';
import * as app from 'zray_ui';
import * as monitor from 'zray_monitor';
const config = app.settings();
if (config.enabled != '1' || config.mode == 'direct' || app.state().phase == 'applying') exit(0);
const state = monitor.probe();
if (state.phase == 'healthy') exit(0);
if (state.failures < int(config.failure_limit) || time() - state.last_recovery < int(config.recovery_cooldown)) exit(0);
const uci = cursor();
const available = map(app.nodes(false), n => n.id);
const backups = filter(config.backup_nodes, id => id != config.node && index(available, id) >= 0);
const next = state.proxy_ok && !state.dns_ok ? config.node : length(backups) ? backups[0] : config.node;
if (state.proxy_ok && !state.dns_ok) {
    if (fs.access('/tmp/zray-ui-dns-fallback')) app.checked(fs.unlink('/tmp/zray-ui-dns-fallback'), '切换 DNS 失败。');
    else app.checked(fs.writefile('/tmp/zray-ui-dns-fallback', '1'), '切换 DNS 失败。');
}
if (fs.access('/tmp/zray-ui-applied-options')) app.checked(fs.unlink('/tmp/zray-ui-applied-options'), '清除应用标记失败。');
state.last_recovery = time();
state.action = next == config.node ? '重新解析并连接当前节点' : '切换备用节点';
monitor.save_health(state);
if (next != config.node) app.checked(uci.set('zray', 'main', 'node', next), '切换备用节点失败。');
app.commit(uci, true);
