import * as app from 'zray_ui';

if (app.live('zray'))
    app.checked(system(['/bin/ubus', 'call', 'service', 'delete', '{"name":"zray"}']) == 0, '停止原有 Zray 服务失败。');
