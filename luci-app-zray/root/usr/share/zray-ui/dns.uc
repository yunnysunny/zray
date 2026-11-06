import { cursor } from 'uci';
import * as fs from 'fs';
import * as app from 'zray_ui';

const uci = cursor();
const backup = '/mnt/zray/.scratch/ui-doh-original';
if (!fs.access(backup)) {
    app.checked(fs.writefile(backup, fs.readfile('/etc/config/https-dns-proxy')), '保存原有 DNS 设置失败。');
    app.checked(fs.writefile(backup + '.running', app.live('https-dns-proxy') ? '1' : '0'), '保存原有 DNS 状态失败。');
}
app.checked(uci.load('https-dns-proxy'), '读取加密 DNS 设置失败。');
const entries = [];
uci.foreach('https-dns-proxy', 'https-dns-proxy', section => push(entries, section['.name']));
for (let name in entries) app.checked(uci.delete('https-dns-proxy', name), '更新加密 DNS 实例失败。');
app.checked(uci.set('https-dns-proxy', 'config', 'dnsmasq_config_update', '*'), '设置 DNS 联动失败。');
app.checked(uci.set('https-dns-proxy', 'config', 'force_dns', '1'), '设置 DNS 规则失败。');
app.checked(uci.set('https-dns-proxy', 'config', 'force_dns_port', ['53']), '设置 DNS 端口失败。');
app.checked(uci.set('https-dns-proxy', 'config', 'canary_domains_icloud', '0'), '设置 DNS 选项失败。');
app.checked(uci.set('https-dns-proxy', 'config', 'canary_domains_mozilla', '0'), '设置 DNS 选项失败。');
app.checked(uci.set('https-dns-proxy', 'zray', 'https-dns-proxy'), '创建 DNS 实例失败。');
for (let key, value in {
    resolver_url: 'https://cloudflare-dns.com/dns-query', bootstrap_dns: app.settings().bootstrap_dns,
    listen_addr: '127.0.0.1', listen_port: '5053', proxy_server: 'socks5h://127.0.0.1:10800',
    user: 'nobody', group: 'nogroup'
}) app.checked(uci.set('https-dns-proxy', 'zray', key, value), '保存 DNS 实例失败。');
app.checked(uci.save('https-dns-proxy'), '保存加密 DNS 设置失败。');
app.checked(uci.commit('https-dns-proxy'), '提交加密 DNS 设置失败。');
