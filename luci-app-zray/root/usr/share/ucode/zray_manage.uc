import * as fs from 'fs';
import { cursor } from 'uci';
import * as app from 'zray_ui';
import * as policy from 'zray_policy';

export function save_options(input) {
    const error = policy.validate_options(input);
    if (error) return { error };
    const c = policy.options(input);
    const nodes = app.nodes(false);
    for (let id in c.backup_nodes) if (!length(filter(nodes, n => n.id == id))) return {error: '备用节点不存在：' + id};
    if (length(c.direct_domains) || length(c.proxy_domains)) {
        const p = app.checked(fs.popen('/usr/sbin/dnsmasq --version', 'r'), '读取 DNS 能力失败。');
        const version = p.read('all');
        app.checked(p.close() == 0, '读取 DNS 能力失败。');
        if (index(version, 'no-nftset') >= 0 || index(version, 'nftset') < 0) return {error: '域名分流需要 dnsmasq-full 的 nftset 支持，当前可使用 IP 分流。'};
    }
    const uci = cursor();
    for (let key, value in c) {
        if (type(value) == 'array' && !length(value)) {
            if (uci.get('zray', 'main', key) != null) app.checked(uci.delete('zray', 'main', key), '清除设置失败：' + key);
        } else app.checked(uci.set('zray', 'main', key, value), '保存设置失败：' + key);
    }
    if (fs.access('/tmp/zray-ui-dns-fallback')) app.checked(fs.unlink('/tmp/zray-ui-dns-fallback'), '恢复主要 DNS 失败。');
    return app.commit(uci, true);
};

export function devices() {
    const result = [];
    if (!fs.access('/tmp/dhcp.leases')) return result;
    const text = app.checked(fs.readfile('/tmp/dhcp.leases'), '读取设备列表失败。');
    for (let line in split(trim(text), '\n')) {
        const parts = split(line, /[[:space:]]+/);
        if (length(parts) >= 4) push(result, {mac: parts[1], ip: parts[2], name: parts[3] == '*' ? parts[2] : parts[3]});
    }
    return result;
};

export function subscription(url) {
    if (type(url) != 'string' || length(url) > 2048 || !match(url, /^https:\/\/[a-zA-Z0-9.-]+(:443)?\/[^[:space:]]*$/) || match(url, /["'\\]/)) return {error: '订阅地址必须是有效的 HTTPS 地址，端口为 443。'};
    const hostname = match(url, /^https:\/\/([^\/:]+)/)[1];
    const p = app.checked(fs.popen('/usr/bin/resolveip -4 -t 5 ' + hostname, 'r'), '解析订阅地址失败。');
    const addresses = filter(split(trim(p.read('all')), '\n'), v => length(v));
    if (p.close() != 0 || !length(addresses)) return {error: '无法解析订阅服务器地址。'};
    for (let address in addresses) {
        const ip = iptoarr(address);
        if (!ip || length(ip) != 4 || ip[0] == 0 || ip[0] == 10 || ip[0] == 127 || ip[0] >= 224 || (ip[0] == 169 && ip[1] == 254) || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168)) return {error: '订阅服务器必须使用公网地址。'};
    }
    const output = '/tmp/zray-ui-subscription.txt';
    const command = '/usr/bin/curl --silent --show-error --fail --proto =https --connect-timeout 5 --max-time 15 --max-filesize 262144 --resolve ' + hostname + ':443:' + addresses[0] + ' --output ' + output + " '" + url + "' 2>&1";
    let result;
    try {
        const child = app.checked(fs.popen(command, 'r'), '下载订阅失败。');
        const detail = child.read('all');
        if (child.close() != 0) result = {error: '下载订阅失败：' + substr(trim(detail), 0, 512)};
        else {
            const text = app.checked(fs.readfile(output), '读取订阅失败。');
            result = length(text) > 262144 ? {error: '订阅内容超过 256 KiB。'} : {text};
        }
    }
    catch (error) { result = {error: error.message}; }
    if (fs.access(output)) fs.unlink(output);
    return result;
};

export function test_node(id) {
    if (type(id) != 'string' || !match(id, /^[a-zA-Z0-9_]+$/) || !length(filter(app.nodes(false), n => n.id == id))) return {error: '节点不存在。'};
    const p = app.checked(fs.popen('/usr/bin/flock -n /var/lock/zray-ui-test.lock /usr/bin/ucode /usr/share/zray-ui/test-node.uc ' + id, 'r'), '启动节点检测失败。');
    const text = p.read('all');
    if (p.close() != 0) return {error: text || '已有节点检测任务，请稍后再试。'};
    return json(text);
};
