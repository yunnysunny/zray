# 更新日志

## [v0.6.0] · 2026-11-22

**破坏性变更。** zray 现在固定使用单个网络事件循环。旧配置仍能加载，`workers` 字段会触发启动警告并被忽略。此前配置了多个 worker 的部署，升级后会改为单事件循环，可以移除 `workers` 字段。

连接池满时，监听器暂停接收新连接，待有空闲槽位后恢复，减少满载时的空转和连接被立即关闭的情况。

通用 `aarch64` 和 `x86_64` 发布构建改用 `ReleaseFast`，以更大的二进制体积换取更快的用户态加密。新增 `aarch64-crypto` 和 `x86_64-aes` 构建。前者要求 ARMv8 加密扩展（AES、PMULL 和 SHA2），后者要求 x86-64-v2、AES-NI、PCLMUL 和 AVX。MIPS 和 ARMv7 发布构建继续使用 `ReleaseSmall`。

中英文文档和网站补充了 HTTP/3（QUIC）绕过 TCP 透明代理的说明，介绍如何让客户端回退到 TCP，并修正了 nftables 配置示例。文档还补充了 OpenWrt 的 `luci-app-zray` 管理界面链接。

## [v0.5.0] · 2026-11-14

同一监听端口支持 SOCKS5、HTTP CONNECT 和 HTTP 正向代理。新增可配置的网络工作线程、可选的 AF_ALG 和 `/dev/crypto` AES-GCM 后端、加密数据大小阈值，以及动态链接 libc 的构建选项。默认使用单个网络 worker 和软件加密。

改进 Vision 直连的数据转发和 `splice` 背压处理，增加转发系统调用计数和性能测量工具。修复 Vision 分片识别、直连切换及半关闭处理，修正 TLS KeyUpdate 序列号、混合密钥共享和 GREASE ECH 公钥生成，并在旧内核缺少 `getrandom` 时回退到 `/dev/urandom`。

## [v0.4.0] · 2026-11-10

新增 VLESS WebSocket 传输、出站链式转发和域名故障切换。上游连接按次限制超时，仅切换到健康目标，并在链式连接失败时记录出错的链路段及清理对应连接。

## [v0.3.0] · 2026-11-08

新增普通 VLESS + TLS 上游，通过 `security` 字段选择 `tls` 或 `reality`。修复 `sockaddr_in` 的 IPv4 地址读写，绑定失败时记录原始 `errno`。CI 增加了通过 QEMU 执行的 MIPS 单元测试和启动冒烟测试。

## [v0.2.0] · 2026-10-18

新增 `bootstrap_dns`，允许通过指定的 DNS 服务器解析上游域名，绕过 `/etc/resolv.conf`。

## [v0.1.0] · 2026-10-17

首次发布面向 Linux 路由器的 REALITY / VLESS / Vision 客户端。支持 SOCKS5 入站、通过 XUDP 转发 SOCKS5 UDP、透明 REDIRECT 入站及 TLS SNI 和 HTTP Host 嗅探。TLS 客户端支持 Chrome 指纹和 X25519MLKEM768 混合密钥共享，并提供 OpenWrt 启动脚本和路由器配置示例。

[v0.6.0]: https://github.com/yunnysunny/zray/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/yunnysunny/zray/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/yunnysunny/zray/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/yunnysunny/zray/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/yunnysunny/zray/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/yunnysunny/zray/releases/tag/v0.1.0
