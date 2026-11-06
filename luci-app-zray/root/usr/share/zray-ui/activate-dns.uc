import { cursor } from 'uci';
import * as app from 'zray_ui';

// Own one explicit DNS configuration update. The dedicated zray-dns
// service only runs the DoH process; it does not rewrite DNS or firewall rules.
const uci = cursor();
app.checked(uci.load('dhcp'), '读取 DNS 转发配置失败。');
uci.foreach('dhcp', 'dnsmasq', section => {
    const servers = section.server;
    if (type(servers) != 'array' || length(servers) != 1 || servers[0] != '127.0.0.1#5053') {
        app.checked(uci.set('dhcp', section['.name'], 'server', ['127.0.0.1#5053']), '设置加密 DNS 转发失败。');
    }
    if (section.noresolv != '1') {
        app.checked(uci.set('dhcp', section['.name'], 'noresolv', '1'), '设置 DNS 转发模式失败。');
    }
});
app.checked(uci.save('dhcp') && uci.commit('dhcp'), '保存 DNS 转发配置失败。');
// Even if forwarding was already correct, domain nftsets may have changed.
app.checked(system(['/etc/init.d/dnsmasq', 'reload']) == 0, '启用加密 DNS 转发失败。');
