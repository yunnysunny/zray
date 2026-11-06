'use strict';
'require view';
'require rpc';
'require ui';

const api = {};
for (const [method, params] of Object.entries({ status: [], resources: [], devices: [], save_options: ['data'], test_node: ['id'], subscription: ['url'], export_nodes: [], get_node: ['id'], save_nodes: ['data'], delete_node: ['id'], select_node: ['id'], set_enabled: ['enabled'] }))
    api[method] = rpc.declare({ object: 'zray', method, params, reject: true });

async function request(method, ...args) {
    const result = await api[method](...args);
    if (result.error && method !== 'status') throw new Error(result.error);
    return result;
}

return view.extend({
    load: function() {
        this.assetVersion = L.env.nodespec.action.path;
        return Promise.all([request('status'), import(L.resource('zray/links.js') + '?v=' + encodeURIComponent(this.assetVersion)), import(L.resource('zray/controls.js') + '?v=' + encodeURIComponent(this.assetVersion))]);
    },
    render: function(data) {
        this.state = data[0];
        this.links = data[1];
        this.controls = data[2].create(ui);
        this.call = request;
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
        this.timer = window.setTimeout(() => this.refresh(), this.state.pending || this.busy ? 250 : 2000);
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
        const summary = this.controls.summary(state, this.networkError, waiting);
        const children = [
            E('link', { rel: 'stylesheet', href: L.resource('zray/style.css') + '?v=' + encodeURIComponent(this.assetVersion) }),
            E('h2', {}, 'Zray'),
            E('ul', { class: 'cbi-tabmenu', role: 'tablist' }, [['basic', '代理'], ['nodes', '节点'], ['settings', '设置']].map(([key, title]) => E('li', { class: this.tab === key ? 'cbi-tab' : 'cbi-tab-disabled' }, E('a', { href: '#', role: 'tab', 'aria-selected': this.tab === key ? 'true' : 'false', click: event => {
                event.preventDefault(); this.tab = key; this.diagnosticsOpen = false; this.detailsOpen = false; this.renderPage();
            }}, title))))
        ];
        if (summary.error) children.push(E('div', {class: 'alert-message error', role: 'alert'}, [summary.error,
            this.button('查看详情', () => { this.tab = 'settings'; this.diagnosticsOpen = true; this.renderPage(); this.loadDiagnostics(); })]));
        if (this.tab === 'basic') {
            const toggle = E('input', { id: 'zray-main-switch', type: 'checkbox', role: 'switch', 'aria-label': '主开关', change: event => {
                this.state.enabled = event.target.checked; this.change('set_enabled', event.target.checked);
            }});
            toggle.checked = state.enabled;
            toggle.disabled = this.busy || !active;
            const select = E('select', { id: 'zray-current-node', 'aria-label': '代理节点', change: event => this.change('select_node', event.target.value) },
                state.nodes.length ? state.nodes.map(node => E('option', { value: node.id }, node.name)) : [E('option', { value: '' }, '尚未添加节点')]);
            select.disabled = waiting || !state.nodes.length;
            select.value = state.node || '';
            const mode = E('select', {id: 'zray-mode', 'aria-label': '代理模式', change: event => this.change('save_options', JSON.stringify({...state.options, mode: event.target.value}))},
                [['global', '全局代理'], ['rules', '规则分流'], ['direct', '全部直连']].map(([value, label]) => E('option', {value}, label)));
            mode.value = state.options.mode;
            mode.disabled = waiting;
            children.push(E('section', {class: 'zray-basic'}, [
                this.formRow('主开关', E('label', {class: 'zray-switch-label', for: 'zray-main-switch'}, [toggle, E('span', {}, state.enabled ? '开启' : '关闭')])),
                this.formRow('状态', E('div', {class: summary.ok ? 'zray-green' : 'zray-muted', role: 'status', 'aria-live': 'polite'}, summary.text)),
                this.formRow('节点', select),
                this.formRow('模式', E('div', {class: 'zray-actions'}, [mode, state.options.mode === 'rules' ? this.button('规则设置', () => this.controls.settings(this, 'routing')) : '']))
            ]));
            if (!state.nodes.length) children.push(E('p', {}, [this.button('添加节点', () => this.nodeDialog(), 'add')]));
            if (state.enabled && state.options.mode !== 'direct' && state.ipv6_warning)
                children.push(E('p', {class: 'cbi-value-description'}, ['IPv6 当前直连，可能绕过代理。', this.button('设置', () => this.controls.settings(this, 'routing'))]));
            children.push(this.controls.connectionDetails(this));
        } else if (this.tab === 'nodes') {
            children.push(E('div', {class: 'zray-toolbar'}, [this.button('添加节点', () => this.nodeDialog(), 'add'), this.controls.nodeMenu(this)]));
            if (state.nodes.length > 5) {
                const search = E('input', {id: 'zray-node-search', type: 'search', placeholder: '搜索节点', 'aria-label': '搜索节点', input: event => { this.search = event.target.value; this.renderPage(); }});
                search.value = this.search || ''; children.push(search);
            }
            const query = state.nodes.length > 5 ? (this.search || '').toLowerCase() : '';
            const nodes = state.nodes.filter(n => (n.name + ' ' + n.server).toLowerCase().includes(query));
            children.push(E('div', {class: 'zray-node-list'}, nodes.map(node => {
                const result = this.nodeTests?.[node.id];
                return E('div', {class: 'zray-node-row'}, [
                    E('div', {class: 'zray-node-name'}, [E('strong', {}, node.name), node.id === state.node ? E('span', {class: 'zray-current'}, '当前节点') : '',
                        result ? E('div', {class: 'cbi-value-description'}, result.ok ? '检测通过 · ' + (result.duration_ms / 1000).toFixed(2) + ' 秒' : '检测失败') : '']),
                    E('div', {class: 'zray-actions'}, [node.id !== state.node ? this.button('使用', () => this.change('select_node', node.id), 'apply', waiting) : '',
                        this.button('检测', () => this.controls.test(this, node), 'neutral', this.testing || waiting), this.controls.nodeActions(this, node, waiting)])
                ]);
            })));
            if (!nodes.length) children.push(E('p', {class: 'cbi-section-descr'}, state.nodes.length ? '没有匹配的节点。' : '尚未添加节点，粘贴分享链接即可添加。'));
        } else children.push(this.controls.settingsPage(this));
        const focused = this.root.contains(document.activeElement) ? document.activeElement.id : '';
        const selection = focused && typeof document.activeElement.selectionStart === 'number' ? [document.activeElement.selectionStart, document.activeElement.selectionEnd] : null;
        this.root.replaceChildren(...children);
        if (focused) {
            const field = this.root.querySelector('#' + CSS.escape(focused));
            field?.focus({preventScroll: true});
            if (selection && field?.setSelectionRange) field.setSelectionRange(...selection);
        }
    },
    loadDiagnostics: async function() {
        if (this.diagnosticsPending) return;
        this.diagnosticsPending = true;
        try {
            this.resources = await request('resources');
            this.resourceError = '';
        } catch (error) {
            this.resourceError = error.message;
        } finally {
            this.diagnosticsPending = false;
            if (this.root.isConnected && this.tab === 'settings' && this.diagnosticsOpen) this.renderPage();
        }
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
