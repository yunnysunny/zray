export function connectionSummary(state, networkError, waiting = false, now = Date.now()) {
    if (networkError) return {text: '状态读取失败', error: '无法读取路由器状态，请检查连接。', ok: false};
    const block = state.options.failure_policy === 'block';
    if (waiting) return {text: state.enabled ? '正在连接…' : '正在关闭…', error: '', ok: false};
    if (!state.enabled) return {text: '已关闭 · 普通直连', error: state.error ? '上次设置未成功，请查看详情。' : '', ok: false};
    if (state.options.mode === 'direct') return {text: '已开启 · 全部直连', error: '', ok: false};
    if (state.error || !state.running) {
        const restored = state.error?.includes('已清理代理规则并恢复原有 DNS');
        return {text: block ? '连接失败 · 断网保护已配置' : restored ? '连接失败 · 当前直连' : '连接异常 · 等待恢复',
            error: block ? '代理不可用，已配置的断网保护可能阻断设备外网。' : restored ? '代理未能启动，已恢复普通直连。' : '代理不可用，请查看详情确认恢复状态。', ok: false};
    }
    if (!state.dns_running) return {text: '已开启 · DNS 异常', error: '加密 DNS 未运行，请查看详情。', ok: false};
    const h = state.health || {};
    const fresh = h.node === state.node && now / 1000 - h.checked_at >= 0 && now / 1000 - h.checked_at <= Math.max(90, Number(state.options.health_interval || 60) * 2);
    if (fresh && h.phase === 'failed') return {text: '已开启 · 连接异常', error: h.dns_ok === false ? 'DNS 查询失败，正在尝试恢复。' : '节点连接异常，正在尝试恢复。', ok: false};
    return fresh && h.phase === 'healthy' ? {text: '已开启 · 连通正常', error: '', ok: true}
        : {text: '已开启 · 等待检测', error: '', ok: false};
}

export function create(ui) {
    const notify = (error) => ui.addNotification(null, E('p', {}, String(error.message || error)), 'error');
    const bytes = n => n == null ? '等待采样' : n >= 1048576 ? (n / 1048576).toFixed(1) + ' MiB' : (n / 1024).toFixed(1) + ' KiB';
    function download(name, value) {
        const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
        const link = E('a', { href: url, download: name });
        document.body.appendChild(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    return {
        summary: connectionSummary,
        menu(view, title, actions, label = title) {
            return E('details', {class: 'zray-menu'}, [E('summary', {'aria-label': label}, title),
                E('div', {class: 'zray-menu-items'}, actions.map(([name, action, disabled]) => view.button(name, action, 'neutral', disabled)))]);
        },
        nodeMenu(view) {
            return this.menu(view, '更多', [
                ['检测全部节点', () => this.testAll(view), view.testing || view.state.pending],
                ['订阅更新', () => this.importDialog(view, true)],
                ['导入备份', () => this.importDialog(view, false)],
                ['导出备份', () => this.exportDialog(view), !view.state.nodes.length]
            ]);
        },
        nodeActions(view, node, waiting) {
            return this.menu(view, '⋯', [
                ['查看详情', () => ui.showModal(node.name, [E('p', {}, node.server + ':' + node.port), E('p', {}, 'VLESS · REALITY'),
                    E('div', {class: 'right'}, view.button('关闭', () => ui.hideModal()))])],
                ['编辑', async () => { try { view.nodeDialog((await view.call('get_node', node.id)).node); } catch (error) { notify(error); } }, waiting],
                ['删除', () => ui.showModal('删除节点', [E('p', {}, '确定删除“' + node.name + '”？'), E('div', {class: 'right'}, [
                    view.button('取消', () => ui.hideModal()), view.button('删除', () => { ui.hideModal(); view.change('delete_node', node.id); }, 'remove')])]), waiting]
            ], node.name + '的更多操作');
        },
        connectionDetails(view) {
            const h = view.state.health || {};
            return E('div', {class: 'zray-connection-details'}, [
                E('button', {type: 'button', class: 'btn cbi-button-neutral', 'aria-expanded': !!view.detailsOpen, click: () => { view.detailsOpen = !view.detailsOpen; view.renderPage(); }}, view.detailsOpen ? '收起连接详情' : '连接详情'),
                view.detailsOpen ? E('div', {class: 'cbi-value-description'}, [
                    E('p', {}, '代理进程：' + (view.state.running ? '运行中' : '未运行') + '；加密 DNS：' + (view.state.dns_running ? '运行中' : '未运行')),
                    E('p', {}, h.checked_at ? '最近检测：' + new Date(h.checked_at * 1000).toLocaleString() + '；耗时 ' + h.duration_ms + ' ms。' : '尚无检测记录。'),
                    h.error ? E('p', {}, h.error) : ''
                ]) : ''
            ]);
        },
        settingsPage(view) {
            const group = (title, text, action) => E('div', {class: 'zray-settings-row'}, [view.button(title, action), E('p', {class: 'cbi-value-description'}, text)]);
            return E('div', {}, [
                group('分流与设备', '设备范围、规则和 IPv6。', () => this.settings(view, 'routing')),
                group('DNS 与恢复', 'DNS、备用节点和连接失败后的行为。', () => this.settings(view, 'dns')),
                E('details', {}, [E('summary', {}, '高级设置'), group('配置检测参数', '检测地址、间隔、失败阈值和恢复冷却时间。', () => this.settings(view, 'advanced'))]),
                E('div', {class: 'zray-settings-row'}, [
                    E('button', {type: 'button', class: 'btn cbi-button-neutral', 'aria-expanded': !!view.diagnosticsOpen, click: () => {
                        view.diagnosticsOpen = !view.diagnosticsOpen; view.renderPage(); if (view.diagnosticsOpen) view.loadDiagnostics();
                    }}, view.diagnosticsOpen ? '收起诊断' : '诊断'),
                    view.diagnosticsOpen ? this.diagnostics(view) : ''
                ])
            ]);
        },
        diagnostics(view) {
            const r = view.resources;
            const fields = r ? [
                ['CPU', r.cpu_percent == null ? '暂无采样' : r.cpu_percent.toFixed(1) + '%'],
                ['可用内存', bytes(r.memory?.available)], ['可用闪存', bytes(r.flash?.available)],
                ['LAN 上传 / 下载', bytes(r.traffic?.upload_bps) + '/s / ' + bytes(r.traffic?.download_bps) + '/s'],
                ['Zray 物理内存', bytes(r.process?.rss_kib == null ? null : r.process.rss_kib * 1024)],
                ['系统连接数', r.connections?.count == null ? '暂无数据' : r.connections.count + ' / ' + r.connections.capacity]
            ] : [];
            return E('section', {class: 'zray-diagnostics'}, [
                E('div', {class: 'zray-actions'}, [view.button(view.diagnosticsPending ? '读取中…' : '刷新', () => view.loadDiagnostics(), 'neutral', view.diagnosticsPending),
                    view.button('导出诊断', () => download('zray-diagnostics.json', {time: new Date().toISOString(), resources: view.resources,
                        status: {enabled: view.state.enabled, running: view.state.running, dns_running: view.state.dns_running, phase: view.state.phase, node_count: view.state.nodes.length}}))]),
                view.resourceError ? E('p', {role: 'alert'}, view.resourceError) : '',
                E('dl', {}, fields.flatMap(([name, value]) => [E('dt', {}, name), E('dd', {}, value)])),
                E('p', {class: 'cbi-value-description'}, '流量为 LAN 接口总量，连接数为系统总量。仅在打开或刷新时采样。'),
                E('p', {class: 'cbi-value-description'}, '不保存历史日志。'),
                view.state.error ? E('p', {role: 'alert'}, '当前错误：' + view.state.error) : ''
            ]);
        },
        async settings(view, group = 'routing') {
            try {
                const options = structuredClone(view.state.options);
                const originalPolicy = options.failure_policy;
                const error = E('div', {class: 'alert-message error', hidden: true, role: 'alert'});
                const body = [error], controls = {};
                let target = body;
                const row = (key, title, type, choices, note) => {
                    const field = type === 'select' ? E('select', {id: 'zray-option-' + key}, choices.map(([value, text]) => E('option', {value}, text)))
                        : type === 'list' ? E('textarea', {id: 'zray-option-' + key, rows: 3, spellcheck: 'false'})
                        : E('input', {id: 'zray-option-' + key, type: type || 'text'});
                    field.value = type === 'list' ? (options[key] || []).join('\n') : options[key];
                    controls[key] = {field, type};
                    const wrap = view.formRow(title, field, note); target.push(wrap); return wrap;
                };
                let consent;
                if (group === 'routing') {
                    row('device_mode', '设备范围', 'select', [['all', '全部 LAN 设备'], ['selected', '指定设备']]);
                    const devices = [];
                    target = devices;
                    row('devices', '设备 MAC 地址', 'list', null, '每行一个，也可以从下方选择设备。');
                    const picks = E('div', {class: 'zray-actions'}, view.button('读取在线设备', async () => {
                        try {
                            const found = (await view.call('devices')).devices;
                            picks.replaceChildren(...found.map(d => view.button(d.name + ' (' + d.ip + ')', () => {
                                const lines = controls.devices.field.value.split(/\s+/).filter(Boolean);
                                if (!lines.includes(d.mac)) lines.push(d.mac);
                                controls.devices.field.value = lines.join('\n');
                            })));
                            if (!found.length) picks.replaceChildren(E('p', {}, '暂无 DHCP 设备。'));
                        } catch (e) { notify(e); }
                    }));
                    const deviceBox = E('div', {}, [...devices, picks]); body.push(deviceBox);
                    const updateDevices = () => { deviceBox.hidden = controls.device_mode.field.value !== 'selected'; };
                    controls.device_mode.field.addEventListener('change', updateDevices); updateDevices();
                    const rules = []; target = rules;
                    row('direct_ip', '直连 IP / CIDR', 'list'); row('proxy_ip', '代理 IP / CIDR', 'list');
                    row('direct_domains', '直连域名', 'list', null, '包含子域名，需要 dnsmasq-full。'); row('proxy_domains', '代理域名', 'list');
                    body.push(E('details', {open: options.mode === 'rules' || ['direct_ip', 'proxy_ip', 'direct_domains', 'proxy_domains'].some(k => options[k]?.length)}, [E('summary', {}, '自定义分流规则'), ...rules]));
                    target = body;
                    row('ipv6_policy', '公网 IPv6', 'select', [['passthrough', '保持直连'], ['block', '阻断所选设备']], 'IPv6 直连可能绕过代理。');
                } else if (group === 'dns') {
                    row('dns_url', '主要 DoH 地址', 'url'); row('dns_fallback_url', '备用 DoH 地址', 'url');
                    row('failure_policy', '连接失败时', 'select', [['direct', '恢复普通直连（默认）'], ['block', '断网保护：阻断所选设备外网']]);
                    consent = E('input', {type: 'checkbox', id: 'zray-block-consent'});
                    const warning = E('label', {class: 'alert-message warning'}, [consent, ' 我了解断网保护会中断所选设备上网。']);
                    const updateWarning = () => { warning.hidden = controls.failure_policy.field.value !== 'block'; };
                    controls.failure_policy.field.addEventListener('change', updateWarning); updateWarning(); body.push(warning);
                    const selected = new Set(options.backup_nodes || []);
                    const checks = view.state.nodes.map(n => {
                        const input = E('input', {type: 'checkbox', value: n.id}); input.checked = selected.has(n.id);
                        input.addEventListener('change', () => input.checked ? selected.add(n.id) : selected.delete(n.id));
                        return E('label', {}, [input, ' ' + n.name]);
                    });
                    body.push(E('h4', {}, '备用节点'), E('div', {class: 'zray-actions'}, checks.length ? checks : '暂无节点。'));
                    controls.backup_nodes = {read: () => [...selected]};
                } else {
                    row('probe_url', 'HTTPS 检测地址', 'url');
                    row('health_interval', '检测间隔（秒）', 'number', null, '30～3600');
                    row('failure_limit', '连续失败次数', 'number', null, '2～10');
                    row('recovery_cooldown', '恢复冷却（秒）', 'number', null, '60～3600');
                }
                const save = view.button('保存并应用', async () => {
                    save.disabled = true; error.hidden = true;
                    try {
                        for (const [key, c] of Object.entries(controls)) options[key] = c.read ? c.read() : c.type === 'list' ? c.field.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean) : c.field.value;
                        if (options.failure_policy === 'block' && originalPolicy !== 'block' && !consent?.checked)
                            throw new Error('请确认断网保护会中断设备上网，或选择恢复普通直连。');
                        await view.call('save_options', JSON.stringify(options));
                        ui.hideModal(); view.state = await view.call('status'); view.renderPage();
                    } catch (failure) { error.textContent = failure.message; error.hidden = false; }
                    finally { save.disabled = false; }
                }, 'apply');
                body.push(E('div', {class: 'right zray-dialog-actions'}, [view.button('取消', () => ui.hideModal()), save]));
                ui.showModal({routing: '分流与设备', dns: 'DNS 与恢复', advanced: '高级设置'}[group], body, 'zray-settings-dialog');
            } catch (e) { notify(e); }
        },
        async test(view, node) {
            if (view.testing) return;
            view.testing = true;
            try {
                const result = await view.call('test_node', node.id);
                view.nodeTests ||= {};
                view.nodeTests[node.id] = result;
                if (!result.ok) notify(result.error);
            } catch (error) { notify(error); }
            finally { view.testing = false; view.renderPage(); }
        },
        async testAll(view) {
            for (const node of view.state.nodes) await this.test(view, node);
        },
        importDialog(view, subscription) {
            const input = subscription ? E('input', {type: 'url', placeholder: 'https://…', 'aria-label': '订阅地址'}) : E('textarea', {rows: 10, 'aria-label': '节点备份 JSON'});
            const error = E('p', {class: 'alert-message error', hidden: true, role: 'alert'});
            const save = view.button(subscription ? '下载并合并节点' : '验证并导入', async () => {
                save.disabled = true; error.hidden = true;
                try {
                    let nodes;
                    if (subscription) {
                        let text = (await view.call('subscription', input.value.trim())).text.trim();
                        if (!text.startsWith('vless://')) text = atob(text.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''));
                        const lines = text.split(/\r?\n/).map(v => v.trim()).filter(Boolean);
                        if (!lines.length || lines.length > 256) throw new Error('订阅必须包含 1～256 个 VLESS + REALITY 节点。');
                        nodes = lines.map((line, i) => { try { return view.links.parseVlessLink(line); } catch(e) { throw new Error('第 ' + (i + 1) + ' 项：' + e.message); } });
                    } else {
                        const data = JSON.parse(input.value);
                        if (data.version !== 1 || !Array.isArray(data.nodes) || !data.nodes.length || data.nodes.length > 256) throw new Error('备份格式不正确。');
                        nodes = data.nodes.map(n => view.links.validateNode(n));
                    }
                    await view.call('save_nodes', JSON.stringify(nodes));
                    ui.hideModal(); view.state = await view.call('status'); view.renderPage();
                    ui.addNotification(null, E('p', {}, '已合并 ' + nodes.length + ' 个节点，已有节点不会被删除。'), 'info');
                } catch (failure) { error.textContent = failure.message; error.hidden = false; }
                finally { save.disabled = false; }
            }, 'apply');
            ui.showModal(subscription ? '手动更新订阅' : '导入节点备份', [
                E('p', {}, subscription ? '仅支持 HTTPS 公网订阅和 VLESS + REALITY 节点。下载并验证整批内容后合并，保留手动节点。不会在后台自动更新。' : '粘贴导出的 JSON。备份包含节点凭据，请妥善保管。'),
                input, error, E('div', {class: 'right'}, [view.button('取消', () => ui.hideModal()), save])
            ]);
        },
        exportDialog(view) {
            ui.showModal('导出节点备份', [E('p', {}, '文件包含 UUID 等连接凭据。请保存在安全位置，不要公开分享。'), E('div', {class: 'right'}, [
                view.button('取消', () => ui.hideModal()), view.button('确认导出', async () => {
                    try { download('zray-nodes.json', await view.call('export_nodes')); ui.hideModal(); } catch (error) { notify(error); }
                }, 'apply')
            ])]);
        }
    };
}
