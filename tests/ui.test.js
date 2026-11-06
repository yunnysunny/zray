import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { create, connectionSummary } from '../luci-app-zray/htdocs/luci-static/resources/zray/controls.js';

class Element {
    constructor(tag, attrs = {}, children = []) { this.tag = tag; this.attrs = attrs; this.children = [children].flat(Infinity).filter(x => x !== null && x !== undefined); this.value = attrs.value || ''; this.isConnected = true; this.listeners = {}; }
    addEventListener(name, callback) { this.listeners[name] = callback; }
    replaceChildren(...children) { this.children = children.flat(Infinity); }
    contains() { return false; }
    set textContent(value) { this.children = [String(value)]; }
    get textContent() { return this.children.map(x => x instanceof Element ? x.textContent : String(x)).join(''); }
    querySelector(selector) { return walk(this).find(n => selector.startsWith('#') && n.attrs.id === selector.slice(1)); }
    click() { return (this.attrs.click || this.listeners.click)?.({preventDefault() {}, target: this}); }
}
function walk(root) { return root instanceof Element ? [root, ...root.children.flatMap(walk)] : []; }
globalThis.E = (tag, attrs, children) => new Element(tag, attrs, children);
const options = {mode: 'global', device_mode: 'all', devices: [], direct_ip: [], proxy_ip: [], direct_domains: [], proxy_domains: [], ipv6_policy: 'passthrough', failure_policy: 'direct', dns_url: 'https://dns.google/dns-query', dns_fallback_url: 'https://cloudflare-dns.com/dns-query', health_interval: '60', failure_limit: '3', recovery_cooldown: '120', backup_nodes: [], probe_url: 'https://www.gstatic.com/generate_204'};
function state(overrides = {}) { return {enabled: false, running: false, dns_running: false, pending: false, error: '', node: 'n1', options: {...options}, nodes: [{id: 'n1', name: '我的节点', server: 'node.example', port: 443}], ...overrides}; }
function setup(initial = state()) {
    const calls = [], modals = [];
    const ui = {showModal: (title, body) => modals.push(new Element('modal', {title}, body)), hideModal() {}, addNotification() {}};
    const rpc = {declare: ({method}) => async (...args) => {
        calls.push([method, ...args]);
        if (method === 'status') return initial;
        if (method === 'resources') return {memory: {}, flash: {}, connections: {}};
        if (method === 'logs') return {log: 'test log'};
        if (method === 'devices') return {devices: []};
        return {ok: true};
    }};
    const context = {view: {extend: v => v}, rpc, ui, E: globalThis.E, L: {resource: p => p, env: {}}, window: {setTimeout() {}, clearTimeout() {}, addEventListener() {}}, document: {activeElement: null}, CSS: {escape: x => x}, console};
    const source = fs.readFileSync(new URL('../luci-app-zray/htdocs/luci-static/resources/view/zray/client.js', import.meta.url), 'utf8');
    const view = new vm.Script('(function(){' + source + '})()').runInNewContext(context);
    view.render([initial, {}, {create: () => create(ui)}]);
    return {view, calls, modals};
}

test('首页仅显示代理操作，资源和日志不自动请求', async () => {
    const {view, calls} = setup();
    assert.match(view.root.textContent, /已关闭 · 普通直连/);
    assert.doesNotMatch(view.root.textContent, /CPU|可用内存|导出备份|检测全部|TCP 透明代理/);
    assert.deepEqual(walk(view.root).filter(n => n.attrs.role === 'tab').map(n => n.textContent), ['代理', '节点', '设置']);
    await view.refresh(); await view.refresh();
    assert.ok(calls.every(([name]) => name === 'status'));
});
test('资源只在打开诊断时读取，始终不请求历史日志', async () => {
    const {view, calls} = setup();
    view.tab = 'settings'; view.renderPage();
    assert.equal(calls.length, 0);
    await walk(view.root).find(n => n.textContent === '诊断' && n.tag === 'button').click();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(calls.filter(([m]) => m === 'resources').length, 1);
    assert.equal(calls.filter(([m]) => m === 'logs').length, 0);
    await view.refresh();
    assert.equal(calls.filter(([m]) => m === 'resources').length, 1);
});
test('小节点列表没有搜索框或重复的服务器和协议列', () => {
    const {view} = setup(); view.tab = 'nodes'; view.renderPage();
    assert.equal(view.root.querySelector('#zray-node-search'), undefined);
    assert.doesNotMatch(view.root.textContent, /node.example|VLESS/);
    assert.match(view.root.textContent, /我的节点.*当前节点/);
    view.state.nodes = Array.from({length: 6}, (_, i) => ({id: String(i), name: '节点' + i, server: 'host', port: 443})); view.renderPage();
    assert.ok(view.root.querySelector('#zray-node-search'));
});
test('连接状态区分进程运行和真实连通，过期结果不会显示正常', () => {
    const s = state({enabled: true, running: true, dns_running: true});
    assert.equal(connectionSummary(s, '').text, '已开启 · 等待检测');
    s.health = {node: 'n1', phase: 'healthy', checked_at: 100};
    assert.equal(connectionSummary(s, '', false, 110000).ok, true);
    assert.equal(connectionSummary(s, '', false, 300000).ok, false);
    s.dns_running = false;
    assert.match(connectionSummary(s, '').error, /DNS/);
    s.running = false;
    assert.match(connectionSummary(s, '').text, /等待恢复/);
    s.error = '启用失败；已清理代理规则并恢复原有 DNS，可继续普通直连上网。';
    assert.match(connectionSummary(s, '').text, /当前直连/);
    s.options.failure_policy = 'block';
    assert.match(connectionSummary(s, '').text, /断网保护/);
});
test('指定设备和断网确认按需显示，打开设置不会保存配置', async () => {
    const {view, calls, modals} = setup();
    await view.controls.settings(view, 'routing');
    let modal = modals.at(-1);
    const device = modal.querySelector('#zray-option-devices');
    const box = walk(modal).find(n => n.children.some(c => c instanceof Element && c.querySelector('#zray-option-devices')) && n.tag === 'div');
    assert.ok(device); assert.ok(box.hidden);
    const mode = modal.querySelector('#zray-option-device_mode'); mode.value = 'selected'; mode.listeners.change();
    assert.equal(box.hidden, false);
    await view.controls.settings(view, 'dns'); modal = modals.at(-1);
    const consent = modal.querySelector('#zray-block-consent');
    const warning = walk(modal).find(n => n.children.includes(consent));
    assert.equal(warning.hidden, true);
    const policy = modal.querySelector('#zray-option-failure_policy'); policy.value = 'block'; policy.listeners.change();
    assert.equal(warning.hidden, false);
    await walk(modal).find(n => n.tag === 'button' && n.textContent === '保存并应用').click();
    assert.ok(calls.every(([m]) => m !== 'save_options'));
});
test('分组保存保留未显示的设置和所有节点规则', async () => {
    const original = state(); original.options.proxy_domains = ['example.com'];
    const {view, calls, modals} = setup(original);
    await view.controls.settings(view, 'advanced');
    const modal = modals.at(-1); modal.querySelector('#zray-option-health_interval').value = '120';
    await walk(modal).find(n => n.tag === 'button' && n.textContent === '保存并应用').click();
    const payload = JSON.parse(calls.find(([m]) => m === 'save_options')[1]);
    assert.equal(payload.health_interval, '120');
    assert.deepEqual(payload.proxy_domains, ['example.com']);
    assert.equal(payload.failure_policy, 'direct');
    assert.equal(payload.mode, 'global');
});
