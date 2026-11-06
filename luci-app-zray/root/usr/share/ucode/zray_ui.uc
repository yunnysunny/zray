import * as fs from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';

export const state_path = '/mnt/zray/.scratch/ui-state.json';

export function checked(result, message) {
    assert(result !== false && result !== null, message);
    return result;
};

export function settings() {
    const uci = cursor();
    return uci.get_all('zray', 'main');
};

export function nodes(secret) {
    const result = [];
    const uci = cursor();
    checked(uci.foreach('zray', 'node', section => {
        const node = { id: section['.name'], name: section.name, server: section.server, port: int(section.port), sni: section.sni };
        if (secret) {
            node.uuid = section.uuid;
            node.public_key = section.public_key;
            node.short_id = section.short_id || '';
        }
        push(result, node);
    }) !== null, '读取节点列表失败。');
    return result;
};

export function validate(node) {
    if (type(node) != 'object') return '节点数据格式不正确。';
    for (let key in ['name', 'server', 'uuid', 'sni', 'public_key', 'short_id'])
        if (type(node[key]) != 'string') return '节点字段不完整：' + key;
    if (!length(node.name) || length(node.name) > 300) return '节点名称长度不正确。';
    if (!iptoarr(node.server) && !match(node.server, /^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$/)) return '服务器地址格式不正确。';
    if (type(node.port) != 'int' || node.port < 1 || node.port > 65535) return '服务器端口格式不正确。';
    if (!match(node.uuid, /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/)) return '用户 ID（UUID）格式不正确。';
    const public_key = replace(replace(node.public_key, '-', '+'), '_', '/');
    if (!match(node.public_key, /^[A-Za-z0-9_-]{43}$/) || length(b64dec(public_key + '=')) != 32) return 'REALITY 公钥格式不正确。';
    if (!match(node.short_id, /^([a-fA-F0-9]{2}){0,8}$/)) return 'Short ID 格式不正确。';
    if (!match(node.sni, /^[a-zA-Z0-9.-]{1,253}$/)) return '服务器名称（SNI）格式不正确。';
    return null;
};

export function state() {
    if (!fs.access(state_path)) return { revision: '', phase: 'idle', error: '' };
    return json(checked(fs.readfile(state_path), '读取服务状态失败：' + fs.error()));
};

export function write_state(value) {
    checked(fs.writefile(state_path + '.new', value), '写入服务状态失败：' + fs.error());
    checked(fs.rename(state_path + '.new', state_path), '保存服务状态失败：' + fs.error());
};

export function live(name) {
    const bus = checked(connect(), '连接服务管理器失败。');
    const result = checked(bus.call('service', 'list', { name }), '读取服务状态失败。');
    for (let key, instance in result[name]?.instances || {})
        if (instance.running) return true;
    return false;
};

export function rules_active() {
    const process = checked(fs.popen('/usr/sbin/nft --json list tables', 'r'), '读取转发规则失败。');
    const text = process.read('all');
    checked(process.close() == 0, '读取转发规则失败。');
    const result = json(text);
    return length(filter(result.nftables, item => item.table?.family == 'inet' && item.table?.name == 'zray')) > 0;
};

export function runtime_config() {
    const config = settings();
    const selected = filter(nodes(true), node => node.id == config.node);
    assert(length(selected) == 1, '请先添加并选择节点。');
    const node = selected[0];
    assert(!validate(node), validate(node));
    return {
        listen: '0.0.0.0:10800', redirect: '0.0.0.0:1080', sniff: true,
        server: node.server, port: node.port, bootstrap_dns: config.bootstrap_dns,
        sni: node.sni, uuid: node.uuid, public_key: node.public_key, short_id: node.short_id,
        max_connections: int(config.max_connections), handshake_timeout_s: 15,
        idle_timeout_s: 300, sock_buf: 0
    };
};

export function status() {
    const config = checked(settings(), '读取 Zray 设置失败。');
    const current = state();
    const pending = current.revision != config.revision || current.phase == 'applying';
    return {
        enabled: config.enabled == '1', node: config.node || '', revision: config.revision,
        running: live('zray-ui') && rules_active(), dns_running: live('https-dns-proxy'),
        pending, phase: current.phase, error: current.error || '', nodes: nodes(false)
    };
};

export function commit(uci, apply) {
    const revision = b64enc(fs.readfile('/dev/urandom', 12));
    checked(uci.set('zray', 'main', 'revision', revision), '更新设置版本失败。');
    checked(uci.save('zray'), '保存设置失败：' + uci.error());
    checked(uci.commit('zray'), '提交设置失败：' + uci.error());
    const child = checked(fs.popen('/usr/libexec/zray-ui-apply >>/mnt/zray/.scratch/ui-apply.log 2>&1 &', 'r'), '启动设置任务失败。');
    checked(child.close() == 0, '提交设置任务失败。');
    return { ok: true, revision };
};
