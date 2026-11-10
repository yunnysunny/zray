# zray 使用说明

简体中文 | [English](usage.md)

这份文档面向**要把 zray 用起来的人**：从下载哪个文件、配置怎么写，到装在路由器上开机自启、出问题去哪儿看。

[README](README.zh-CN.md) 是完整的特性与配置参考，[链式出站教程](chain-relay-exit.zh-CN.md) 单独讲 relay / exit 那一套。三者互补，不重复。

- [1. 先确认你能不能用](#1-先确认你能不能用)
- [2. 五分钟跑起来（SOCKS5 模式）](#2-五分钟跑起来socks5-模式)
- [3. 参数从哪来：分享链接怎么填](#3-参数从哪来分享链接怎么填)
- [4. 三种用法](#4-三种用法)
- [5. 装成服务，开机自启](#5-装成服务开机自启)
- [6. 调优：把有限的 CPU 和内存用对地方](#6-调优把有限的-cpu-和内存用对地方)
- [7. 排错](#7-排错)
- [8. 从 v0.3 升级](#8-从-v03-升级)
- [9. 自带的两个自测工具](#9-自带的两个自测工具)

## 1. 先确认你能不能用

zray 是一个**客户端**，服务端不需要它。要跑起来需要三样东西：

| 需要 | 说明 |
|---|---|
| 一台 Linux 机器 | 代理服务只在 Linux 上运行。路由器（OpenWrt / ImmortalWrt）、软路由、树莓派、VPS 都行。macOS / Windows 上只能编译和跑 `probe`。 |
| 一个服务端节点 | REALITY（VLESS + `xtls-rprx-vision`），或者普通 VLESS + TLS（机场常见的那种）。协议必须是 VLESS，Trojan / VMess / Shadowsocks 都不支持。 |
| 系统的出口方式 | 你的手机、电脑、整栋房子要么手动填 SOCKS5，要么靠透明代理自动接管。 |

如果你只有一台线路好、IP 也干净的服务器，直连就够了，不需要链式那一套。见[链式出站教程](chain-relay-exit.zh-CN.md)开头的判断。

**它不是什么**：不是图形客户端，没有订阅、没有自动测速、没有负载均衡、没有日志级别开关（每条连接的生命周期都打到 stderr）。这些不在设计目标里。

## 2. 五分钟跑起来（SOCKS5 模式）

### 2.1 选对二进制

每个 tag 的 Release 里都有五个静态 musl 二进制，**没有动态依赖，也不用装任何库**：

| 文件 | 适用设备 |
|---|---|
| `zray-mipsel-softfloat` | 小端 MIPS，绝大多数 MT7621 / MT7620 路由器（小米 AC2100、红米 AC2100、新路由 3 等） |
| `zray-mips-softfloat` | 大端 MIPS，少数老设备 |
| `zray-arm-v7` | ARMv7，如多数高通 / 博通 A7 路由器、树莓派 2/3 |
| `zray-aarch64` | ARM64，如树莓派 4、ARM 软路由、ARM VPS |
| `zray-x86_64` | 普通 PC / x86 软路由 / x86 VPS |

`uname -m` 在 MIPS 上只回 `mips`，分不出大小端。在 OpenWrt 上用发行版架构串最准：

```sh
. /etc/openwrt_release && echo $DISTRIB_ARCH
# mipsel_24kc / mips_24kc / aarch64_generic / arm_cortex-a7_neon-vfpv4 / x86_64
```

`mipsel` 开头 → `zray-mipsel-softfloat`，`mips_` 开头 → `zray-mips-softfloat`，其余按上表对。还拿不准就再跑一次 `opkg print-architecture`，`mipsel_` 前缀即小端。

### 2.2 下载、校验、放到固定位置

```sh
mkdir -p /mnt/zray
cd /mnt/zray
wget -O zray https://github.com/yunnysunny/zray/releases/latest/download/zray-mipsel-softfloat
wget -O zray.sha256 https://github.com/yunnysunny/zray/releases/latest/download/zray-mipsel-softfloat.sha256
chmod 755 zray
sha256sum zray      # 和 zray.sha256 里的第一列目视比对
./zray              # 没有配置文件时报 cannot read config.json，说明二进制能跑
```

> `zray` 除了一个配置文件路径之外**不接受任何参数**：没有 `-h`、没有 `--version`，`zray --help` 会被当成文件名去读。版本号看启动日志第一行。

不建议放在 `/tmp`（重启就没了）；`/mnt/zray` 这类数据分区在 OpenWrt 上重启后仍在。

### 2.3 写一份最小配置

REALITY 节点，只有一条上游：

```json
{
  "listen": "127.0.0.1:1080",
  "server": "服务器地址",
  "port": 443,
  "sni": "伪装域名",
  "security": "reality",
  "public_key": "服务端 publicKey",
  "short_id": "服务端 shortId（没有就留空）",
  "uuid": "你的 uuid",
  "max_connections": 64
}
```

其余字段都有默认值，见 [config.example.json](../config.example.json)。两条硬性规则：

- 配置里**出现不认识的键会直接报错退出**（`bad config: UnknownField`）。多写一个逗号、键名拼错，都不会被静默忽略。
- `security` 是显式声明的。`"reality"` 必须给 `public_key`；`"tls"` 不许出现 `public_key` / `short_id`。写错组合就报错，不会悄悄降级成不校验证书的 TLS。

实用一下的话，把 `max_connections` 按内存算（每个槽约 93 KiB，见第 6 节）。

### 2.4 前台跑一次，看着日志

```sh
cd /mnt/zray && ./zray config.json
```

正常启动会打两行，第一行是版本、入口、槽位；第二行是上游和当前模式：

```
zray 0.4.0 socks5 [127.0.0.1:1080] redirect [] sniff true, 1 outbounds, 0 rules, 64 slots x 93 KiB = 5937 KiB
outbound -: 服务器地址:443 sni 伪装域名 mode reality (short_id -) vision
```

`mode reality` 就是 REALITY 模式；如果是 `mode tls, verify NONE -- WARNING: ...`，说明你在连普通 VLESS+TLS 节点，证书不校验，链路上的任何人都有可能冒充它。

### 2.5 验证真的通了

在**同一台机器**上（或能访问这个 SOCKS5 端口的机器上）：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

`ip=` 应该是服务器出口的 IP，`loc=` 是它所在的国家/地区码。第二条命令验证 DNS 也走隧道：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://ipinfo.io/json
```

两条都通，这台机器上的 SOCKS5 模式就配好了。前端接上它就行：SwitchyOmega、sing-box 的 socks outbound、手机上任意支持 SOCKS5 的客户端，地址填 `路由器IP:1080`（同样是 `/mnt/zray` 那台机器的 IP）。

> SOCKS5 入口**没有认证**，也没有绑定检查之外的保护。`listen` 保持 `127.0.0.1`；确实要给局域网用时改 `0.0.0.0:1080`，但要清楚同一网段的任何人都能拿它当出口。

## 3. 参数从哪来：分享链接怎么填

机场和自建服务一般给一条 `vless://` 链接，字段和 zray 配置一一对应：

```
vless://<uuid>@<地址>:<端口>?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=<公钥>&sid=ab12&type=tcp&flow=xtls-rprx-vision#名字
```

| 链接里的 | 配置字段 | 备注 |
|---|---|---|
| `@` 前面的 uuid | `uuid` | |
| `@` 后面的主机 / 端口 | `server` / `port` | 主机可以是域名，也可直接写 IP |
| `security=reality` | `"security": "reality"` | |
| `security=tls` | `"security": "tls"` + `"tls_verify": "none"` | 后者在当前版本必填 |
| `pbk=` | `public_key` | base64url，原样抄 |
| `sid=` | `short_id` | 十六进制，最多 8 字节；没有就留空 |
| `sni=` | `sni` | REALITY 的伪装站点，必须和服务端一致 |
| `fp=chrome` | 无 | 指纹固定是 Chrome，不需要也不可能改成别的 |
| `flow=xtls-rprx-vision` | `flow` | tcp 下默认就是 vision，可以省略 |
| `encryption=none` | 无 | VLESS 固定 none |
| `type=tcp` | 无 | 默认就是 tcp |
| `type=ws` | `"network": "ws"` | 配合 `path=` → `ws_path`，`host=` → `ws_host` |

上面那条链接对应：

```json
{
  "listen": "127.0.0.1:1080",
  "server": "服务器地址",
  "port": 443,
  "sni": "example.com",
  "security": "reality",
  "public_key": "<pbk 的值>",
  "short_id": "ab12",
  "uuid": "<uuid>",
  "flow": "xtls-rprx-vision"
}
```

**不支持 / 需要注意**：

- `type=grpc`、`type=httpupgrade`、`type=quic`：都没有实现，只能用 `tcp` 和 `ws`。
- ws 的 **early data**（链接里带 `ed=2048` 这类参数）：不实现。别把它塞进 `ws_path`，服务端真发 early data 时连接会以 `WsEarlyData` 断开。大多数服务端在没有客户端请求时不会主动发。
- `fp` 不是 chrome（如 `firefox`、`safari`、`randomized`）：客户端只呈现 Chrome 指纹，写了也没用。服务端若按指纹做了限制会连不上。
- 订阅 / 订阅转换：zray 不读订阅链接，需要自己把节点展开成链接再抄进配置。
- 免费或公共节点常见的「同名多落地、自动选最快」：不属于 zray 的能力范围，它的 `rules` 只按域名后缀分流，不做测速。

## 4. 三种用法

### 4.1 本机 / 局域网 SOCKS5（最简单）

就是第 2 节那套。适合：单台机器或几台设备手动挂代理；先验证节点可用，再折腾透明代理。

UDP 走 SOCKS5 `UDP ASSOCIATE`，用 XUDP（VLESS mux）封装，比 xray 的 Vision 行为一致。注意两点：**只支持带 Vision 的 TCP 节点**（ws 节点没有 UDP），**载荷超过约 600 字节可能被服务端出口丢弃**（DNS 正常，QUIC 一般不通）。分片不支持，现实中也没有客户端用。

### 4.2 透明代理（路由器当网关）

目标：局域网里的设备什么都不用配，命中规则的流量自动进隧道。

1. **配置两个入口**。`listen` 留着当调试用，`redirect` 才是给 nft 喂流量的：

```json
{
  "listen": "127.0.0.1:10800",
  "redirect": "0.0.0.0:1080",
  "sniff": true,
  "server": "服务器地址",
  "port": 2443,
  "bootstrap_dns": "223.5.5.5",
  "...": "其余同前"
}
```

2. **nft 规则把命中的 IP 重定向到 `redirect` 端口**。典型的按域名分流：DNS 侧（dnsmasq + chinadns-ng，或 smartdns）把命中 gfwlist 的域名解析出的 IP 写进一个 nft 集合，再由这张表负责转发：

```
table inet gfw {
    set iplist { type ipv4_addr; flags interval; }
    chain prerouting { type nat hook prerouting priority 0;
        ip daddr @iplist ip protocol tcp redirect to :1080 }
    chain output     { type nat hook output priority filter;
        ip daddr @iplist ip protocol tcp redirect to :1080 }
}
```

`prerouting` 管其他设备，`output` 管路由器自己。`redirect` 用的是 `SO_ORIGINAL_DST`，所以端口写的是 zray 的 `redirect` 端口（上例 `1080`），不是 `listen`。

3. **两条必须避开的坑**：

- **服务器自己的 IP 不能进那个集合**。否则 zray 连服务器的流量又被自己拦回来，变成死循环（症状：启动正常、一有流量就满槽位、日志里全是失败）。用 `ip daddr != <服务器 IP>` 排除，或者在 DNS 侧把服务器域名加进直连名单。
- **解析 `server` 的解析器不能依赖这条隧道**。如果 dnsmasq / chinadns-ng 的 DoT 上游本身走 zray，开机时两边互相等，谁都起不来。这时把 `bootstrap_dns` 设成公共 DNS（如 `223.5.5.5`），启动时那次解析就完全不经过本地解析器。

4. **`sniff` 保持开启**。透明代理只拿得到目标 IP，`sniff` 让它从首包解出 TLS SNI 或 HTTP `Host`，把目标换成域名。目标 IP 有可能命中 `rules` 时，zray 最多等 1 秒做这次嗅探——这是那 1 秒的来源，正常。

5. **验证**：在局域网另一台机器上不配代理，直接：

```sh
curl https://www.cloudflare.com/cdn-cgi/trace      # ip= 应为服务器出口 IP
curl https://www.baidu.com                          # 应正常（不在集合里，直连）
```

### 4.3 多节点、按域名分流、链式出站

需要「线路好的机器」和「IP 干净的机器」各一台时用这个：`rules` 把少数域名分给一组 exit，其余走 `default`。

```json
{
  "outbounds": [
    { "tag": "relay", "server": "...", "security": "reality", "public_key": "...", "uuid": "..." },
    { "tag": "exit-a", "server": "...", "security": "tls", "tls_verify": "none",
      "uuid": "...", "network": "ws", "ws_path": "/vless-ws", "flow": "none", "dialer": "relay" }
  ],
  "rules": [
    { "domain_suffix": ["openai.com", "chatgpt.com", "claude.ai"], "outbound": ["exit-a"] }
  ],
  "default": ["relay"]
}
```

规则要点：`outbound` 是一个**组**，组内成员之间才做故障切换（`fail_backoff_s`，默认 30 秒）；命中的规则失败后**不会退回 `default`**，这是故意的——宁可打不开，也不让本该走干净 IP 的请求从别处出去。链式的完整原理、封装层次、代价和验证方法都在[链式出站教程](chain-relay-exit.zh-CN.md)里。

## 5. 装成服务，开机自启

### 5.1 OpenWrt：用仓库里的 procd 脚本

```sh
scp zray              root@router:/mnt/zray/zray
scp config.json       root@router:/mnt/zray/config.json
scp deploy/zray.init  root@router:/etc/init.d/zray
ssh root@router '
  chmod 755 /etc/init.d/zray /mnt/zray/zray
  chmod 600 /mnt/zray/config.json
  /etc/init.d/zray enable
  /etc/init.d/zray start
  sleep 2; logread | tail -5
'
```

`deploy/zray.init` 只做三件事：`procd_set_param command` 指向 `/mnt/zray/zray /mnt/zray/config.json`、`respawn 3600 5 0`（崩了自动拉起，5 秒内连崩就停）、把 stdout / stderr 交给 logd。想看实时日志：`logread -f`。

配置文件的权限用 `600`（里面有 `uuid` 和 `public_key`），二进制用 `755`。别把配置放在 web 目录下。

### 5.2 普通 Linux：systemd

仓库没有附带 systemd 单元，下面这份可以直接抄：

```ini
# /etc/systemd/system/zray.service
[Unit]
Description=zray REALITY/VLESS client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/zray/zray /etc/zray/config.json
Restart=always
RestartSec=3
LimitNOFILE=1024
# 透明代理入口（redirect）需要监听 1024 以下端口时用：
# AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now zray
journalctl -u zray -f
```

透明代理的 nft / iptables 规则要另外持久化（`nft -f /etc/nftables.conf` 或发行版自己的机制），zray 不负责装规则。

## 6. 调优：把有限的 CPU 和内存用对地方

### 6.1 内存：`max_connections` × 93 KiB

启动日志最后一段就是账：`64 slots x 93 KiB = 5937 KiB`。槽位在**启动时一次性分配**，不随流量增长，超出就拒绝新连接（`conn table full`）。

| 场景 | 估算 |
|---|---|
| 普通 SOCKS5 / 透明代理 | 并发连接数 × 93 KiB |
| 链式（`dialer`） | 再乘 2：每条链式连接占两个槽（客户端那条 + hop 那条） |
| 128 MB 内存的路由器（可用约 20 MB） | 32–64 个槽比较合适 |

64 槽 ≈ 5.8 MB，128 槽 ≈ 11.6 MB。先给 `64`，出现 `conn table full` 再往上加；一加就 OOM 就说明该换更大的机器了。

### 6.2 TCP 窗口：`tcp_rmem`（比任何 zray 参数都重要）

128 MB 内存的路由器上，`net.ipv4.tcp_rmem` 默认上限约 930 KB，单条流的吞吐被「窗口 / RTT」卡住：190 ms 时约 1 MB/s。在这类机器上实测，把上限提到 4 MB 之后同一条链路的 HTTPS 吞吐从约 1 MB/s 变成 9–10 MB/s：

```sh
echo 'net.ipv4.tcp_rmem = 4096 131072 4194304' > /etc/sysctl.d/99-zray.conf
sysctl -p /etc/sysctl.d/99-zray.conf
```

**不要**用 zray 的 `sock_buf` 来干这件事：它会关掉内核的窗口自动调优，还会被 `net.core.rmem_max` 截断。`sock_buf` 留 `0`。

### 6.3 超时

| 字段 | 默认 | 什么时候改 |
|---|---|---|
| `connect_timeout_s` | 5 | 跨境 + ws 握手慢的节点偶发超时，调到 8–10 |
| `handshake_timeout_s` | 15 | 入站侧：等客户端把 SOCKS5 握手 / 首个请求送出来。移动网络下可放宽 |
| `idle_timeout_s` | 600 | 手机推送这类长连接会被它掐断，可调到 1800 |

`connect_timeout_s` 必须 ≥ 1，设 0 直接报错退出。

### 6.4 别给自己找麻烦的几条

- **Vision 节点才是默认选择**。`flow: "none"` 或 ws 节点整条连接都要软件加解密，MIPS 单核上限约 1–1.5 MB/s。
- **`default` 放在 Vision 节点上**，只有需要干净 IP 的少数域名走 ws exit。
- **别把 REALITY 服务端域名加进 gfwlist**（见 4.2 第 3 条）。

## 7. 排错

日志全部打到 stderr，OpenWrt 上在 `logread`，systemd 上在 `journalctl`。按症状查：

| 症状 | 原因 | 处理 |
|---|---|---|
| `bad config: UnknownField` | 配置里有关键名拼错，或多了不该有的字段 | 对照 [config.example.json](../config.example.json) 逐字核对；`"..."` 这种占位键也是未知键 |
| `bad config: use either top-level server/uuid or outbounds, not both` | 顶层 `server` / `uuid` 和 `outbounds` 同时存在 | 二选一 |
| `bad config: connect_timeout_s must be >= 1` | 设成了 0 | 设 ≥ 1 |
| `cannot resolve <host>: ...` | 启动时解析上游失败 | 检查网络；解析器依赖隧道时设 `bootstrap_dns`；`bootstrap_dns` 只查 A 记录，只有 AAAA 的域名请改用系统解析器 |
| `CertificateRejected` | 路由器时钟没同步（REALITY 会校验封在 `session_id` 里的时间戳）；或者 `public_key` / `short_id` / `uuid` 不匹配 | 先对时：`ntpd -q -p ntp.aliyun.com`，确认 `date` 正确；再核对参数 |
| `conn table full` | 槽位用尽：并发太多，或上游不可达导致每条连接都占着坑等超时 | 增大 `max_connections`；同时查上游可达性（不可达时会连锁占坑） |
| 启动正常，一有流量就全是失败、槽位很快满 | 透明代理把服务器自己的流量也 redirect 回来了 | 把服务器 IP 排除出 nft 集合 |
| 透明代理完全没效果 | nft 规则没命中 / 端口写成了 `listen` / `sniff` 关了 / 客户端没把网关和 DNS 指到路由器 | 逐项核对 4.2 |
| 能打开 IP 站点，域名打不开 | DNS 没走对，或 `sniff` 关闭导致域名匹配不上 | 检查 DNS 分流；`sniff` 保持 `true` |
| ws 节点特别慢（< 1 MB/s） | ws 不能用 Vision，整条连接软件加解密，是 CPU 而不是线路 | 正常现象，只用它跑 AI 聊天这类小流量 |
| 链式失败日志 `... -> relay side` | 路由器到 relay 没连上（或 relay 的下一段握手没完成） | 查 relay 本身、家宽出口 |
| 链式失败日志 `... -> exit side` | relay 通了，exit 没响应或握手出错 | 查 exit 地址 / 端口 / uuid / ws_path，以及 relay 出站是否被 exit 白名单拦了 |
| 链式失败日志 `hop connection never accepted` | relay 侧没有接受本机 hop 的 SOCKS 连接 | 通常与 `dialer` 指错节点有关 |
| `WsUpgradeRejected` | WS 升级返回了非 101（多半是 404） | `ws_path` / `ws_host` 和服务端不一致 |
| `WsEarlyData` | 服务端在同一记录里发了 101 之后的早期数据 | 关掉服务端的 early data；别把 `ed=` 写进 `ws_path` |
| `tls alert handshake_failure` / `CertificateRejected` 交替出现 | `sni` 与服务端证书或 REALITY 配置不符 | 核对 `sni` |
| UDP 不通、QUIC 打不开 | 只有 Vision TCP 节点带 UDP，且载荷 > ~600 字节可能被服务端丢 | 属于已知限制，浏览器自动回落 TCP |
| 手机上开着代理却推送延迟 / 断流 | `idle_timeout_s` 掐掉了长连接 | 调大 `idle_timeout_s` |

判断「到底是谁的问题」的通用方法：先用第 9 节的 `probe` 直接对服务端做一次握手和请求。`probe` 通、`zray` 不通，问题在 zray 的配置或入口；`probe` 也不通，问题在服务端或线路上。

## 8. 从 v0.3 升级

0.4.0 新增：VLESS WebSocket 传输（`network: "ws"`）、出站链式（`dialer`）、按域名后缀分流（`rules` / `default`）、组内故障切换（`fail_backoff_s`）、单次连接硬超时（`connect_timeout_s`）。

升级只需要换二进制：

```sh
/etc/init.d/zray stop
# 覆盖 /mnt/zray/zray（保留原配置）
/etc/init.d/zray start
```

配置向后兼容：只写了顶层 `server` / `uuid` 的旧配置照常工作，`connect_timeout_s` 默认 5 秒。要留意的是：

- 开始用链式时，`max_connections` 要按连接数翻倍往上加（每条链占两个槽）。
- 0.4 之前没有 `connect_timeout_s`，入站侧的超时由 `handshake_timeout_s` 兜着；现在它只管入站，上游有独立的 5 秒硬超时。

## 9. 自带的两个自测工具

### 9.1 `probe`：直接验服务端

不启动服务，做一次真实握手 + 一次经隧道的请求，任何平台都能编译运行（包括 Windows / macOS）：

```sh
zig build probe -- <ip> <port> <sni> <public_key> [short_id|-] [uuid url]

zig build probe -- 203.0.113.5 443 example.com K5Ko4T...4G8 - \
    00000000-0000-0000-0000-000000000000 https://www.cloudflare.com/
```

输出包含服务端选的 cipher suite 和密钥交换组、证书 HMAC 是否通过、经隧道收到的字节数。把 URL 换成 `https://tls.peet.ws/api/all` 还能看到内层连接呈现的指纹。

### 9.2 `udptest.py`：验 UDP

```sh
python3 tools/udptest.py 127.0.0.1 1080
```

用 SOCKS5 `UDP ASSOCIATE` 发几次 DNS 查询，验证 XUDP 通路。需要 Python 3，没有第三方依赖。

## 反馈

配置被拒时，报错信息里带着键名和原因；调试时把启动那两行日志和报错一起贴出来，比只说「连不上」有用得多。问题与想法：<https://github.com/yunnysunny/zray/issues>。
