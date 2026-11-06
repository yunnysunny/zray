import * as fs from 'fs';
import { connect } from 'ubus';
import * as app from 'zray_ui';

export const legacy_logs = [
    '/tmp/zray-ui-apply.log', '/tmp/zray-ui-apply.log.1', '/tmp/zray-ui-health.log', '/tmp/zray-ui-health.log.1',
    '/tmp/zray-ui-startup.log', '/tmp/zray-ui-probe-error', '/tmp/zray-ui-test.log', '/tmp/zray-ui-test-error',
    '/tmp/zray-ui-subscription-error.txt', '/tmp/zray-ui-subscription.txt',
    '/mnt/zray/.scratch/ui-apply.log', '/mnt/zray/.scratch/ui-apply.log.1'
];
export function log_storage() {
    return { enabled: false, retained_files: length(filter(legacy_logs, path => fs.access(path))) };
};
export const health_path = '/tmp/zray-ui-health.json';
function read(path) { return app.checked(fs.readfile(path), '读取失败：' + path + '：' + fs.error()); }
export function health() {
    return fs.access(health_path) ? json(read(health_path)) : { checked_at: 0, phase: 'unknown', failures: 0 };
};
export function save_health(value) {
    if (value.error) value.error = substr(value.error, 0, 512);
    app.checked(fs.writefile(health_path + '.new', value), '写入健康状态失败。');
    app.checked(fs.rename(health_path + '.new', health_path), '保存健康状态失败。');
};
export function resources() {
    const bus = app.checked(connect(), '连接系统状态服务失败。');
    const info = app.checked(bus.call('system', 'info'), '读取系统状态失败。');
    const service = app.checked(bus.call('service', 'list', { name: 'zray-ui' }), '读取进程状态失败。');
    const cpu = split(trim(split(read('/proc/stat'), '\n')[0]), /[[:space:]]+/);
    const values = map(slice(cpu, 1), n => int(n));
    let total = 0;
    for (let value in slice(values, 0, 8)) total += value;
    const idle = values[3] + values[4];
    const lan = trim(read('/mnt/zray/.scratch/ui-lan.txt'));
    let received = 0, sent = 0;
    for (let line in split(read('/proc/net/dev'), '\n')) {
        const parts = split(line, ':');
        if (length(parts) == 2 && trim(parts[0]) == lan) {
            const fields = split(trim(parts[1]), /[[:space:]]+/);
            received = int(fields[0]); sent = int(fields[8]);
        }
    }
    const current = { time: time(), total, idle, received, sent };
    const path = '/tmp/zray-ui-resources.json';
    const before = fs.access(path) ? json(read(path)) : null;
    app.checked(fs.writefile(path, current), '写入资源采样失败。');
    let cpu_percent = null, upload_bps = null, download_bps = null;
    if (before && current.time > before.time && total > before.total) {
        cpu_percent = 100.0 * (1.0 - (idle - before.idle) / (1.0 * (total - before.total)));
        upload_bps = (received >= before.received ? (received - before.received) / (1.0 * (current.time - before.time)) : 0);
        download_bps = (sent >= before.sent ? (sent - before.sent) / (1.0 * (current.time - before.time)) : 0);
    }
    let process = null;
    for (let key, instance in service['zray-ui']?.instances || {}) {
        if (!instance.running || !instance.pid) continue;
        const status = read('/proc/' + instance.pid + '/status');
        const rss = match(status, /VmRSS:[[:space:]]+([0-9]+)/);
        const virtual = match(status, /VmSize:[[:space:]]+([0-9]+)/);
        process = { pid: instance.pid, rss_kib: rss ? int(rss[1]) : null, virtual_kib: virtual ? int(virtual[1]) : null };
    }
    const disk = app.checked(info.root, '读取闪存容量失败。');
    const count = fs.readfile('/proc/sys/net/netfilter/nf_conntrack_count');
    const capacity = fs.readfile('/proc/sys/net/netfilter/nf_conntrack_max');
    return { sampled_at: current.time, cpu_percent, memory: info.memory, load: map(info.load, n => n / 65536.0),
        logging: log_storage(), flash: { total: disk.total * 1024, available: disk.avail * 1024 },
        traffic: { interface: lan, upload_bps, download_bps }, process,
        connections: { count: count ? int(count) : null, capacity: capacity ? int(capacity) : null }, health: health() };
};
export function probe() {
    const c = app.settings();
    const start = time();
    const child = app.checked(fs.popen('/usr/bin/curl --silent --show-error --fail --connect-timeout 4 --max-time 8 --socks5-hostname 127.0.0.1:10800 --output /dev/null ' + sprintf('%s', "'" + c.probe_url + "'") + ' 2>&1', 'r'), '启动连通检测失败。');
    const error = child.read('all');
    const code = child.close();
    const dns = connect().call('service', 'list', {name: 'zray-dns'});
    let dns_running = false;
    for (let key, instance in dns?.['zray-dns']?.instances || {}) if (instance.running) dns_running = true;
    const dns_port = c.mode == 'direct' ? '53' : '5053';
    const dns_test = app.checked(fs.popen('/usr/bin/nslookup -port=' + dns_port + ' -timeout=3 -retry=1 openwrt.org 127.0.0.1 2>&1', 'r'), '启动 DNS 检测失败。');
    const dns_output = dns_test.read('all');
    const dns_ok = dns_test.close() == 0 && (dns_running || c.mode == 'direct');
    const before = health();
    const value = { checked_at: time(), node: c.node, phase: code == 0 && dns_ok ? 'healthy' : 'failed',
        proxy_ok: code == 0, dns_running, dns_ok, duration_ms: (time() - start) * 1000,
        failures: code == 0 && dns_ok ? 0 : (before.failures || 0) + 1,
        error: code != 0 ? trim(error) : !dns_ok ? 'DNS 查询失败：' + trim(dns_output) : '', last_recovery: before.last_recovery || 0 };
    save_health(value);
    return value;
};
