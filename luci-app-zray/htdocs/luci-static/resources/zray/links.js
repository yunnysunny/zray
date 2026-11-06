const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function decodeBase64(value) {
    const encoded = value.replace(/-/g, '+').replace(/_/g, '/');
    return atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, '='));
}

export function validateNode(input) {
    const node = Object.fromEntries(['name', 'server', 'uuid', 'sni', 'public_key', 'short_id'].map(key => [key, String(input[key] ?? '').trim()]));
    node.port = Number(input.port == null || input.port === '' ? 443 : input.port);
    if (!node.server || /[\s/?#@]/.test(node.server)) throw new Error('请填写有效的服务器地址。');
    if (!Number.isInteger(node.port) || node.port < 1 || node.port > 65535) throw new Error('服务器端口应为 1 至 65535。');
    if (!uuidPattern.test(node.uuid)) throw new Error('用户 ID（UUID）格式不正确。');
    if (!/^[A-Za-z0-9_-]{43}=?$/.test(node.public_key) || decodeBase64(node.public_key).length !== 32) throw new Error('REALITY 公钥格式不正确。');
    if (!/^(?:[0-9a-f]{2}){0,8}$/i.test(node.short_id)) throw new Error('Short ID 应为不超过 16 位的偶数长度十六进制字符。');
    if (!node.sni || /[^a-z0-9.-]/i.test(node.sni)) throw new Error('请填写有效的服务器名称（SNI）。');
    node.name = node.name || node.server;
    if (node.name.length > 100) throw new Error('节点名称不能超过 100 个字符。');
    node.uuid = node.uuid.toLowerCase();
    node.short_id = node.short_id.toLowerCase();
    node.public_key = node.public_key.replace(/=+$/, '');
    return node;
}

export function parseVlessLink(text) {
    let outer;
    try { outer = new URL(text.trim()); }
    catch { throw new Error('分享链接格式不正确，请粘贴完整的 vless:// 链接。'); }
    if (outer.protocol !== 'vless:') throw new Error('请导入 VLESS + REALITY 节点。');
    const query = outer.searchParams;
    const transport = query.get('type') || query.get('network') || 'tcp';
    if (!['tcp', 'raw'].includes(transport)) throw new Error('该节点使用了 Zray 尚未支持的传输方式：' + transport + '。');
    const security = query.get('security') || (query.get('pbk') ? 'reality' : '');
    if (security !== 'reality') throw new Error('该节点需要使用 REALITY 安全模式。');
    const flow = query.get('flow');
    if (flow && flow !== 'xtls-rprx-vision') throw new Error('该节点的 flow 需要设置为 xtls-rprx-vision。');
    if (query.has('xtls') && query.get('xtls') !== '2') throw new Error('该节点需要使用 XTLS Vision。');
    const fingerprint = query.get('fp') || query.get('fingerprint');
    if (fingerprint && fingerprint !== 'chrome') throw new Error('Zray 当前使用 Chrome 指纹，请使用对应的节点配置。');
    let address = outer;
    if (!outer.username && !outer.password) {
        try { address = new URL('vless://' + decodeBase64(outer.host)); }
        catch { throw new Error('链接中的服务器信息无法解码。'); }
    }
    let uuid = decodeURIComponent(address.password || address.username);
    if (!uuidPattern.test(uuid)) {
        try { uuid = decodeBase64(uuid); }
        catch { throw new Error('链接中的用户 ID 无法解码。'); }
    }
    return validateNode({
        name: query.get('remarks') || decodeURIComponent(outer.hash.slice(1)),
        server: address.hostname.replace(/^\[|\]$/g, ''),
        port: address.port || 443,
        uuid,
        sni: query.get('sni') || query.get('peer') || '',
        public_key: query.get('pbk') || '',
        short_id: query.get('sid') || ''
    });
}

export function parseLinks(text) {
    const lines = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    if (!lines.length) throw new Error('请粘贴节点分享链接。');
    if (lines.length > 20) throw new Error('一次最多导入 20 个节点。');
    return lines.map((line, index) => {
        try { return parseVlessLink(line); }
        catch (error) { throw new Error('第 ' + (index + 1) + ' 个节点：' + error.message); }
    });
}
