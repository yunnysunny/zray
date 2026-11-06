import * as fs from 'fs';
import * as app from 'zray_ui';
const id = ARGV[0];
const selected = filter(app.nodes(true), n => n.id == id);
assert(length(selected) == 1, '节点不存在。');
const node = selected[0];
const config = { ...app.runtime_config(), listen: '127.0.0.1:10801', redirect: '', max_connections: 8,
    server: node.server, port: node.port, uuid: node.uuid, sni: node.sni, public_key: node.public_key, short_id: node.short_id };
const path = '/tmp/zray-ui-test-config.json';
assert(fs.writefile(path, config), '写入检测配置失败。');
assert(system(['/bin/chmod', '600', path]) == 0, '保护检测配置失败。');
assert(system(['/bin/chown', 'zray:zray', path]) == 0, '设置检测权限失败。');
const command = "trap '/sbin/start-stop-daemon -K -p /tmp/zray-ui-test.pid >/dev/null 2>&1; rm -f /tmp/zray-ui-test.pid /tmp/zray-ui-test-config.json' EXIT HUP INT TERM; " +
    "/sbin/start-stop-daemon -S -b -m -p /tmp/zray-ui-test.pid -c zray -x /mnt/zray/zray -- /tmp/zray-ui-test-config.json >/dev/null 2>&1 || exit 1; " +
    "sleep 0.3; /usr/bin/curl --silent --show-error --fail --connect-timeout 4 --max-time 8 --retry 1 --retry-connrefused --retry-delay 0 --socks5-hostname 127.0.0.1:10801 --output /dev/null --write-out '%{time_total}' '" + app.settings().probe_url + "' 2>&1";
const child = assert(fs.popen(command, 'r'), '启动检测失败。');
const duration = trim(child.read('all'));
const code = child.close();
print({id, ok: code == 0, checked_at: time(), duration_ms: code == 0 ? int(+duration * 1000) : null,
    error: code == 0 ? '' : substr(duration || '启动检测失败。', 0, 512)});
