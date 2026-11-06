import test from 'node:test';
import assert from 'node:assert/strict';
import { parseVlessLink, parseLinks, validateNode } from '../luci-app-zray/htdocs/luci-static/resources/zray/links.js';

const uuid = '12345678-1234-1234-1234-123456789abc';
const key = Buffer.alloc(32, 7).toString('base64url');
const query = 'security=reality&type=tcp&flow=xtls-rprx-vision&sni=www.example.com&pbk=' + key + '&sid=ab12';
const link = 'vless://' + uuid + '@node.example.com:443?' + query + '#%E6%B5%8B%E8%AF%95%E8%8A%82%E7%82%B9';

test('标准分享链接使用 URL 解析器读取节点及中文名称', () => {
    assert.deepEqual(parseVlessLink(link), { name: '测试节点', server: 'node.example.com', port: 443, uuid, public_key: key, short_id: 'ab12', sni: 'www.example.com' });
});
test('Quantumult X 编码的完整地址及参数别名', () => {
    const authority = Buffer.from(':' + uuid + '@node.example.com:50123').toString('base64url');
    const node = parseVlessLink('vless://' + authority + '?remarks=QX&tls=1&peer=www.example.com&xtls=2&pbk=' + key + '&sid=ab12&fingerprint=chrome');
    assert.equal(node.uuid, uuid);
    assert.equal(node.port, 50123);
    assert.equal(node.name, 'QX');
});
test('IPv6 地址和缺省端口', () => {
    assert.equal(parseVlessLink('vless://' + uuid + '@[2001:db8::1]?' + query).server, '2001:db8::1');
    assert.equal(parseVlessLink('vless://' + uuid + '@node.example.com?' + query).port, 443);
});
test('批量导入保留顺序并对空行进行处理', () => {
    assert.equal(parseLinks('\n' + link + '\r\n\n' + link).length, 2);
    assert.throws(() => parseLinks(''), /请粘贴/);
    assert.throws(() => parseLinks(Array(21).fill(link).join('\n')), /20/);
});
test('不支持的传输和安全模式在导入处立即报错', () => {
    assert.throws(() => parseVlessLink(link.replace('type=tcp', 'type=ws')), /传输/);
    assert.throws(() => parseVlessLink(link.replace('security=reality', 'security=tls')), /REALITY/);
    assert.throws(() => parseVlessLink(link.replace('xtls-rprx-vision', 'none')), /flow/);
    assert.throws(() => parseVlessLink(link.replace('#', '&fp=firefox#')), /指纹/);
});
test('公钥、UUID、端口和 Short ID 输入错误不被默认值掩盖', () => {
    const valid = parseVlessLink(link);
    for (const [field, value] of [['public_key', 'invalid'], ['uuid', 'invalid'], ['port', 0], ['port', 65536], ['short_id', 'a'], ['sni', 'invalid/name']])
        assert.throws(() => validateNode({ ...valid, [field]: value }));
});
test('批量错误标明位置并终止整批解析', () => {
    assert.throws(() => parseLinks(link + '\nnot-a-link'), /第 2 个节点/);
});
