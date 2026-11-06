import * as fs from 'fs';
import { legacy_logs } from 'zray_monitor';
// Remove only files owned by this plugin. Never clear the shared system log.
for (let path in legacy_logs) if (fs.access(path)) fs.unlink(path);
