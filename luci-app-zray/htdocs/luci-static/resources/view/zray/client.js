'use strict';
'require view';
'require rpc';
'require ui';

const api = {};
for (const [method, params] of Object.entries({ status: [], get_node: ['id'], logs: [], save_nodes: ['data'], delete_node: ['id'], select_node: ['id'], set_enabled: ['enabled'] }))
    api[method] = rpc.declare({ object: 'zray', method, params, reject: true });

async function request(method, ...args) {
    const result = await api[method](...args);
    if (result.error && method !== 'status') throw new Error(result.error);
    return result;
}

return view.extend({
    load: function() {
        this.assetVersion = L.env.nodespec.action.path;
        return Promise.all([request('status'), import(L.resource('zray/links.js') + '?v=' + encodeURIComponent(this.assetVersion))]);
    },
    render: function(data) {
        this.state = data[0];
        this.links = data[1];
        this.tab = 'basic';
        this.busy = false;
        this.root = E('div', { class: 'zray-page' });
        this.renderPage();
        this.timer = window.setTimeout(() => this.refresh(), 1000);
        window.addEventListener('beforeunload', () => window.clearTimeout(this.timer), { once: true });
        return this.root;
    },
    refresh: async function() {
        if (!this.root.isConnected) return;
        const before = JSON.stringify(this.state);
        const previousError = this.networkError;
        try {
            this.state = await request('status');
            this.networkError = '';
        }
        catch (error) { this.networkError = error.message; }
        if (before !== JSON.stringify(this.state) || previousError !== this.networkError) this.renderPage();
        this.timer = window.setTimeout(() => this.refresh(), this.state.pending || this.busy ? 500 : 2000);
    },
    change: async function(method, ...args) {
        this.busy = true;
        this.renderPage();
        try {
            await request(method, ...args);
            this.state = await request('status');
        }
        catch (error) { ui.addNotification(null, E('p', {}, [error.message]), 'error'); }
        finally { this.busy = false; this.renderPage(); }
    },
    renderPage: function() {
        const state = this.state;
        const waiting = this.busy || state.pending;
        const active = state.nodes.find(node => node.id === state.node);
        const status = this.networkError ? '状态读取失败' : waiting ? (state.enabled ? '正在启用…' : '正在关闭…') : state.running && state.dns_running ? '运行中' : '已关闭';
        const tabs = [['basic', '基本设置'], ['nodes', '节点列表'], ['logs', '运行日志']];
        const toggle = E('input', { id: 'zray-main-switch', type: 'checkbox', role: 'switch', 'aria-label': '主开关', change: event => {
            const enabled = event.target.checked;
            this.state.enabled = enabled;
            this.change('set_enabled', enabled);
        }});
        toggle.checked = state.enabled;
        toggle.disabled = this.busy || !active;
        const children = [
            E('link', { rel: 'stylesheet', href: L.resource('zray/style.css') + '?v=' + encodeURIComponent(this.assetVersion) }),
            E('h2', {}, 'Zray'),
            E('div', { class: 'cbi-map-descr' }, '添加节点后，打开主开关即可自动代理当前网络的公网 IPv4 TCP 流量。'),
            E('fieldset', { class: 'cbi-section' }, [E('legend', {}, '运行状态'), E('div', { class: 'zray-status-grid', 'aria-live': 'polite' }, [
                this.statusBlock('TCP 透明代理', status, !waiting && !this.networkError && state.running),
                this.statusBlock('加密 DNS', this.networkError ? '状态读取失败' : waiting ? '正在应用设置…' : state.dns_running ? '运行中' : '已关闭', !waiting && !this.networkError && state.dns_running),
                this.statusBlock('当前节点', active ? active.name : '尚未添加节点', !!active)
            ])]),
            E('ul', { class: 'cbi-tabmenu', role: 'tablist' }, tabs.map(([key, title]) => E('li', { class: this.tab === key ? 'cbi-tab' : 'cbi-tab-disabled' }, E('a', { href: '#', role: 'tab', 'aria-selected': this.tab === key ? 'true' : 'false', click: event => {
                event.preventDefault(); this.tab = key; this.renderPage(); if (key === 'logs') this.loadLogs();
            }}, title))))
        ];
        if (state.error || this.networkError)
            children.push(E('div', { class: 'alert-message error', role: 'alert' }, [state.error || this.networkError]));
        if (this.tab === 'basic') {
            const select = E('select', { id: 'zray-current-node', 'aria-label': '代理节点', change: event => this.change('select_node', event.target.value) },
                state.nodes.length ? state.nodes.map(node => E('option', { value: node.id }, [node.name])) : [E('option', { value: '' }, '请先添加节点')]);
            select.disabled = waiting || !state.nodes.length;
            select.value = state.node || '';
            children.push(E('fieldset', { class: 'cbi-section' }, [
                E('legend', {}, '基本设置'),
                this.formRow('主开关', E('label', { class: 'zray-switch-label', for: 'zray-main-switch' }, [toggle, E('span', {}, waiting ? '正在应用设置…' : state.enabled ? '已开启' : '已关闭')]), '开启后自动配置透明代理及加密 DNS；关闭后恢复普通上网。'),
                this.formRow('代理节点', E('div', { class: 'zray-node-choice' }, [select, this.button('添加节点', () => this.nodeDialog(), 'add')]), '选择需要使用的节点，节点切换会自动生效。'),
                E('div', { class: 'cbi-section-descr' }, state.nodes.length ? '设备正常连接当前路由器即可使用，无需填写代理地址。' : '还没有节点。点击“添加节点”，粘贴分享链接即可完成添加。')
            ]));
        }
        else if (this.tab === 'nodes') {
            children.push(E('div', { class: 'zray-toolbar' }, [this.button('添加节点', () => this.nodeDialog(), 'add'), E('span', {}, '支持 VLESS + REALITY 分享链接，也可以手动填写。')]));
            const table = E('table', { class: 'table cbi-section-table zray-nodes' }, [E('tr', { class: 'tr table-titles' }, ['节点名称', '服务器', '协议', '操作'].map(title => E('th', { class: 'th' }, title)))]);
            for (const node of state.nodes) table.appendChild(E('tr', { class: 'tr' }, [
                E('td', { class: 'td', 'data-title': '节点名称' }, [E('strong', {}, [node.name]), node.id === state.node ? E('span', { class: 'zray-current' }, '当前节点') : '']),
                E('td', { class: 'td', 'data-title': '服务器' }, [node.server + ':' + node.port]),
                E('td', { class: 'td', 'data-title': '协议' }, 'VLESS · REALITY'),
                E('td', { class: 'td cbi-section-actions', 'data-title': '操作' }, E('div', { class: 'zray-actions' }, [
                    this.button(node.id === state.node ? '正在使用' : '使用', () => this.change('select_node', node.id), 'apply', waiting || node.id === state.node),
                    this.button('编辑', async () => { try { this.nodeDialog((await request('get_node', node.id)).node); } catch (error) { ui.addNotification(null, E('p', {}, [error.message]), 'error'); } }, 'edit', waiting),
                    this.button('删除', () => ui.showModal('删除节点', [E('p', {}, ['确定删除“' + node.name + '”？']), E('div', { class: 'right' }, [this.button('取消', () => ui.hideModal()), this.button('删除', () => { ui.hideModal(); this.change('delete_node', node.id); }, 'remove')])]), 'remove', waiting)
                ]))
            ]));
            if (!state.nodes.length) table.appendChild(E('tr', { class: 'tr' }, E('td', { class: 'td center', colspan: 4 }, '还没有节点，请点击“添加节点”。')));
            children.push(table);
        }
        else children.push(E('fieldset', { class: 'cbi-section' }, [E('legend', {}, '运行日志'), this.button('刷新日志', () => this.loadLogs()), E('pre', { id: 'zray-log', class: 'zray-log' }, [this.log || '暂无设置日志。'])]));
        const focused = this.root.contains(document.activeElement) ? document.activeElement.id : '';
        this.root.replaceChildren(...children);
        if (focused) this.root.querySelector('#' + CSS.escape(focused))?.focus({ preventScroll: true });
    },
    loadLogs: async function() {
        try { this.log = (await request('logs')).log || '暂无设置日志。'; }
        catch (error) { this.log = error.message; }
        const box = this.root.querySelector('#zray-log');
        if (box) box.textContent = this.log;
    },
    statusBlock: function(title, text, ready) {
        return E('div', { class: 'zray-status-block' }, [E('div', { class: 'zray-status-title' }, [title]), E('strong', { class: ready ? 'zray-green' : 'zray-muted' }, [text])]);
    },
    formRow: function(title, control, description) {
        return E('div', { class: 'cbi-value' }, [E('label', { class: 'cbi-value-title' }, title), E('div', { class: 'cbi-value-field' }, [control, description ? E('div', { class: 'cbi-value-description' }, description) : ''])]);
    },
    button: function(title, action, kind, disabled) {
        const button = E('button', { type: 'button', class: 'btn cbi-button cbi-button-' + (kind || 'neutral'), click: action }, [title]);
        button.disabled = !!disabled;
        return button;
    },
    nodeDialog: function(existing, manual) {
        const error = E('div', { class: 'alert-message error zray-form-error', role: 'alert', hidden: true });
        const fields = {};
        const body = [E('div', { class: 'zray-dialog-tabs' }, [
            this.button('链接导入', () => this.nodeDialog(null, false), manual || existing ? 'neutral' : 'apply'),
            this.button('手动填写', () => this.nodeDialog(existing, true), manual || existing ? 'apply' : 'neutral')
        ]), error];
        let links;
        if (!manual && !existing) {
            links = E('textarea', { id: 'zray-import-links', rows: 6, placeholder: 'vless://…', 'aria-label': '节点分享链接', autocomplete: 'off', spellcheck: 'false' });
            body.push(E('label', { for: 'zray-import-links' }, '节点分享链接'), links, E('p', { class: 'cbi-value-description' }, '粘贴服务商提供的完整分享链接，每行一个，一次最多导入 20 个节点。'));
        }
        else for (const [key, title, type, placeholder] of [
            ['name', '节点名称', 'text', '可选，方便自己辨认'], ['server', '服务器地址', 'text', '服务器域名或 IP'],
            ['port', '端口', 'number', '443'], ['uuid', '用户 ID（UUID）', 'password', '服务商提供的 UUID'],
            ['public_key', 'REALITY 公钥', 'text', '服务商提供的公钥'], ['sni', '服务器名称（SNI）', 'text', '服务商提供的 SNI'],
            ['short_id', 'Short ID', 'text', '可选']
        ]) {
            fields[key] = E('input', { id: 'zray-node-' + key, 'aria-label': title, type, value: existing?.[key] ?? (key === 'port' ? '443' : ''), placeholder, autocomplete: 'off', spellcheck: 'false', min: key === 'port' ? '1' : null, max: key === 'port' ? '65535' : null });
            body.push(this.formRow(title, E('label', { for: 'zray-node-' + key, class: 'zray-field-label' }, fields[key])));
        }
        const save = this.button(!manual && !existing ? '一键导入' : '保存节点', async () => {
            error.hidden = true;
            save.disabled = true;
            try {
                const nodes = links ? this.links.parseLinks(links.value) : [this.links.validateNode(Object.fromEntries(Object.entries(fields).map(([key, input]) => [key, input.value])))];
                if (existing) nodes[0].id = existing.id;
                await request('save_nodes', JSON.stringify(nodes));
                ui.hideModal();
                this.state = await request('status');
                this.renderPage();
                ui.addNotification(null, E('p', {}, '已保存 ' + nodes.length + ' 个节点。'), 'info');
            }
            catch (failure) { error.textContent = failure.message; error.hidden = false; }
            finally { save.disabled = false; }
        }, 'apply');
        body.push(E('div', { class: 'right zray-dialog-actions' }, [this.button('取消', () => ui.hideModal()), save]));
        ui.showModal(existing ? '编辑节点' : '添加节点', body, 'zray-node-dialog');
    },
    handleSave: null,
    handleSaveApply: null,
    handleReset: null
});
