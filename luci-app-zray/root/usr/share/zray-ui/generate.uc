import * as fs from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
import * as app from 'zray_ui';

const config = app.settings();
const bus = app.checked(connect(), '连接网络管理器失败。');
const lan = app.checked(bus.call('network.interface.lan', 'status', {}), '读取局域网接口失败。');
assert(lan.up && match(lan.l3_device || '', /^[a-zA-Z0-9_.:-]+$/), '局域网接口尚未就绪。');
const runtime = app.runtime_config();
app.checked(fs.writefile('/mnt/zray/config.json.new', runtime), '写入节点配置失败：' + fs.error());
app.checked(fs.rename('/mnt/zray/config.json.new', '/mnt/zray/config.json'), '保存节点配置失败：' + fs.error());
app.checked(fs.writefile('/mnt/zray/.scratch/ui-lan.txt', lan.l3_device), '保存局域网接口失败。');
