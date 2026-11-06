import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const root = new URL('../luci-app-zray/', import.meta.url);
test('LuCI 视图在其函数加载环境中语法正确', () => {
    const script = fs.readFileSync(new URL('htdocs/luci-static/resources/view/zray/client.js', root), 'utf8');
    assert.doesNotThrow(() => new vm.Script('(function(){\n' + script + '\n})'));
});
test('菜单入口受到插件 ACL 保护，匿名会话没有节点读取权限', () => {
    const menu = JSON.parse(fs.readFileSync(new URL('root/usr/share/luci/menu.d/luci-app-zray.json', root)));
    const acl = JSON.parse(fs.readFileSync(new URL('root/usr/share/rpcd/acl.d/luci-app-zray.json', root)));
    assert.deepEqual(menu['admin/services/zray'].depends.acl, ['luci-app-zray']);
    assert.ok(acl['luci-app-zray'].read.ubus.zray.includes('status'));
    assert.ok(acl['luci-app-zray'].write.ubus.zray.includes('set_enabled'));
    assert.equal(acl.unauthenticated, undefined);
    assert.equal(acl['luci-app-zray'].write.file, undefined);
});
