export const defaults = {
    mode: 'global', device_mode: 'all', devices: [], direct_ip: [], proxy_ip: [],
    direct_domains: [], proxy_domains: [], ipv6_policy: 'passthrough',
    failure_policy: 'direct', health_interval: '60', failure_limit: '3',
    recovery_cooldown: '120', backup_nodes: [],
    dns_url: 'https://cloudflare-dns.com/dns-query',
    dns_fallback_url: 'https://dns.google/dns-query',
    probe_url: 'https://www.gstatic.com/generate_204'
};

export function options(config) {
    const result = {};
    for (let key, value in defaults) result[key] = config[key] ?? value;
    return result;
};

export function validate_options(input) {
    if (type(input) != 'object') return '设置必须是对象。';
    for (let key, value in input) if (!(key in defaults)) return '不支持的设置：' + key;
    const c = options(input);
    for (let key, values in {
        mode: ['global', 'rules', 'direct'], device_mode: ['all', 'selected'],
        ipv6_policy: ['passthrough', 'block'], failure_policy: ['block', 'direct']
    }) if (index(values, c[key]) < 0) return '选项不正确：' + key;
    for (let key, limits in {health_interval: [30, 3600], failure_limit: [2, 10], recovery_cooldown: [60, 3600]}) {
        if (!match('' + c[key], /^[0-9]+$/) || int(c[key]) < limits[0] || int(c[key]) > limits[1]) return '数值超出范围：' + key;
    }
    for (let key in ['devices', 'direct_ip', 'proxy_ip', 'direct_domains', 'proxy_domains', 'backup_nodes']) {
        if (type(c[key]) != 'array' || length(c[key]) > 256) return '列表格式错误或超过 256 项：' + key;
        for (let value in c[key]) {
            if (type(value) != 'string') return '列表项目必须是文本：' + key;
            if (key == 'devices' && !match(value, /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/)) return '设备 MAC 地址格式不正确。';
            if (key == 'backup_nodes' && !match(value, /^[a-zA-Z0-9_]+$/)) return '备用节点标识不正确。';
            if (key == 'direct_ip' || key == 'proxy_ip') {
                const parts = split(value, '/');
                if (length(parts) > 2 || length(iptoarr(parts[0]) || []) != 4 || (length(parts) == 2 && (!match(parts[1], /^[0-9]+$/) || int(parts[1]) > 32))) return '请输入 IPv4 地址或 CIDR：' + value;
            }
            if ((key == 'direct_domains' || key == 'proxy_domains') && (!match(value, /^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$/) || index(value, '..') >= 0)) return '域名格式不正确：' + value;
        }
    }
    if (c.device_mode == 'selected' && !length(c.devices)) return '请至少选择一个使用代理的设备。';
    for (let key in ['dns_url', 'dns_fallback_url', 'probe_url']) {
        if (type(c[key]) != 'string' || length(c[key]) > 512 || (!match(c[key], /^https:\/\/[a-zA-Z0-9.-]+(:[0-9]+)?(\/[^[:space:]]*)?$/) || match(c[key], /["'\\]/))) return '请输入有效的 HTTPS 地址：' + key;
    }
    for (let value in c.direct_domains) if (index(c.proxy_domains, value) >= 0) return '域名同时出现在直连和代理列表：' + value;
    for (let value in c.direct_ip) if (index(c.proxy_ip, value) >= 0) return '地址同时出现在直连和代理列表：' + value;
    return null;
};

export function rules(config, upstream, lan, failed) {
    const c = options(config);
    const error = validate_options(c);
    assert(!error, error);
    assert(match(lan, /^[a-zA-Z0-9_.:-]+$/), 'LAN 接口名称不正确。');
    assert(length(upstream) > 0, '缺少节点地址。');
    for (let ip in upstream) assert(length(iptoarr(ip) || []) == 4, '节点地址不正确。');
    const lines = ['add table inet zray', 'delete table inet zray', 'table inet zray {'];
    function set4(name, values, dynamic) {
        push(lines, 'set ' + name + ' { type ipv4_addr; flags interval' + (dynamic ? ', timeout; timeout 1h' : '') + ';' + (length(values) ? ' elements = { ' + join(', ', values) + ' };' : '') + ' }');
    }
    set4('upstream4', upstream, false);
    set4('direct4', ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'], false);
    set4('user_direct4', c.direct_ip, false);
    set4('user_proxy4', c.proxy_ip, false);
    set4('direct_domains4', [], true);
    set4('proxy_domains4', [], true);
    const device = c.device_mode == 'selected' ? 'ether saddr { ' + join(', ', c.devices) + ' } ' : '';
    const source = 'iifname "' + lan + '" ' + device;
    push(lines, 'chain route { ip daddr @upstream4 return; ip daddr @direct4 return; fib daddr type local return;');
    if (failed) push(lines, 'return;');
    else if (c.mode != 'direct') {
        push(lines, 'ip daddr @user_proxy4 meta l4proto tcp counter redirect to :1080; ip daddr @proxy_domains4 meta l4proto tcp counter redirect to :1080;');
        push(lines, 'ip daddr @user_direct4 return; ip daddr @direct_domains4 return;');
        if (c.mode == 'global') push(lines, 'meta l4proto tcp counter redirect to :1080;');
    }
    push(lines, '}');
    push(lines, 'chain prerouting { type nat hook prerouting priority -101; policy accept;');
    if (!failed && c.mode != 'direct') push(lines, source + 'meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 counter redirect to :53;');
    push(lines, source + 'meta nfproto ipv4 jump route; }');
    push(lines, 'chain output { type nat hook output priority -101; policy accept; meta skuid "zray" return; meta nfproto ipv4 jump route; }');
    push(lines, 'chain forward { type filter hook forward priority -1; policy accept;');
    push(lines, source + 'ip daddr @upstream4 return; ' + source + 'ip daddr @direct4 return;');
    push(lines, source + 'ip6 daddr { ::1, fc00::/7, fe80::/10, ff00::/8 } return;');
    if (c.ipv6_policy == 'block' && (!failed || c.failure_policy == 'block')) push(lines, source + 'meta nfproto ipv6 counter reject with icmpv6 type admin-prohibited;');
    if (failed && c.failure_policy == 'block') push(lines, source + 'meta nfproto ipv4 counter reject with icmp type admin-prohibited;');
    else if (!failed && c.mode != 'direct') {
        push(lines, source + 'ip daddr @user_direct4 return; ' + source + 'ip daddr @direct_domains4 return;');
        if (c.mode == 'global') push(lines, source + 'udp dport 443 counter reject with icmp type port-unreachable;');
        else push(lines, source + 'ip daddr @user_proxy4 udp dport 443 reject; ' + source + 'ip daddr @proxy_domains4 udp dport 443 reject;');
    }
    push(lines, '}');
    // A LAN kill switch must not block router-originated recovery probes,
    // bootstrap DNS, package downloads, or upstream addresses after a DNS change.
    push(lines, '}');
    return join('\n', lines) + '\n';
};

export function dns_rules(config) {
    const c = options(config);
    const lines = [];
    if (c.mode == 'direct') return '';
    for (let domain in c.direct_domains) {
        push(lines, 'nftset=/' + domain + '/4#inet#zray#direct_domains4');
        push(lines, 'server=/' + domain + '/' + config.bootstrap_dns);
    }
    for (let domain in c.proxy_domains) push(lines, 'nftset=/' + domain + '/4#inet#zray#proxy_domains4');
    return join('\n', lines) + '\n';
};
