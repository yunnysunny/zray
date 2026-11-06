import * as fs from 'fs';
import * as app from 'zray_ui';
import * as policy from 'zray_policy';
const config = app.settings();
const lan = trim(app.checked(fs.readfile('/mnt/zray/.scratch/ui-lan.txt'), '读取 LAN 接口失败。'));
const upstream = filter(split(trim(app.checked(fs.readfile('/mnt/zray/.scratch/ui-upstream4'), '读取节点地址失败。')), '\n'), s => length(s));
const failed = ARGV[0] == 'failed';
const target = '/tmp/zray-ui-rules.nft';
app.checked(fs.writefile(target, policy.rules(config, upstream, lan, failed)), '生成规则失败。');
app.checked(system(['/usr/sbin/nft', '--check', '--file', target]) == 0, '防火墙规则检查失败。');
app.checked(system(['/usr/sbin/nft', '--file', target]) == 0, '加载防火墙规则失败。');
const dns = policy.dns_rules(config);
const old_dns = fs.readfile('/tmp/dnsmasq.d/zray.conf') || '';
const dns_changed = old_dns != dns;
app.checked(fs.mkdir('/tmp/dnsmasq.d') || fs.stat('/tmp/dnsmasq.d')?.type == 'directory', '创建 DNS 规则目录失败。');
if (!failed && length(trim(dns))) {
    const proc = app.checked(fs.popen('/usr/sbin/dnsmasq --version', 'r'), '读取 DNS 能力失败。');
    const version = proc.read('all');
    app.checked(proc.close() == 0, '读取 DNS 能力失败。');
    app.checked(index(version, 'no-nftset') < 0 && index(version, 'nftset') >= 0, '域名分流需要启用 nftset 的 dnsmasq-full，请安装后重试；IP 分流无需该组件。');
    app.checked(fs.writefile('/tmp/dnsmasq.d/zray.conf', dns), '保存 DNS 分流规则失败。');
} else if (fs.access('/tmp/dnsmasq.d/zray.conf')) app.checked(fs.unlink('/tmp/dnsmasq.d/zray.conf'), '删除 DNS 分流规则失败。');
// Startup batches this file update with the DoH service's single DNS restart.
// Firewall reloads with unchanged rules must never restart dnsmasq.
if (ARGV[0] != 'start' && dns_changed)
    app.checked(system(['/etc/init.d/dnsmasq', 'reload']) == 0, '重新加载 DNS 分流规则失败。');
