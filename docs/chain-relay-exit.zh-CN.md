# 链式出站教程：relay 和 exit 到底在干什么

> 本文讲的功能（VLESS WebSocket 传输、出站链式、域名故障切换）由 PR #3 引入，v0.3.0 及更早的版本没有这些配置项。

## 先说结论

**直连 Xray 服务器**和**经 relay 绕到 exit**，真正的区别只有一处：

> **你访问的网站看到的是哪台机器的 IP。**

直连时，网站看到的是你那台 Xray 服务器的 IP。链式时，网站看到的是 exit 的 IP，但你家到 exit 这一段走的是 relay 那条好线路。

如果你只有一台服务器，它线路好、IP 也干净，ChatGPT / Claude 都能正常用，**那你不需要这个功能**，直连就是最好的方案。下面的内容全都是为“一台服务器两头顾不上”的人准备的。

---

## 1. 问题从哪来：一台服务器很难同时满足两个条件

一个能“好好用”的代理节点，其实要同时满足两件互不相干的事：

| 条件 | 由什么决定 | 好的例子 | 差的例子 |
|---|---|---|---|
| **线路好**：国内连过去快、稳、不容易被封 | 机房位置、运营商互联（CN2 GIA、CMI 等） | 香港、日本、新加坡的优化线路 VPS | 美国西海岸普通线路，晚高峰丢包严重 |
| **IP 干净**：目标网站愿意服务这个 IP | IP 所在国家/地区，是否被标成机房或滥用 IP | 美国家宽、原生 IP、口碑好的落地机 | 香港 IP（OpenAI、Anthropic 不在香港提供服务）、被大量滥用的机房段 |

麻烦在于，这两个条件经常落在不同的机器上：

- **香港 VPS**：从国内连过去很快，但用它的 IP 访问 ChatGPT / Claude 会直接提示“所在地区不支持”。
- **美国落地机**：IP 很干净，但从国内直连要么慢得没法用，要么协议容易被识别（很多落地机只提供 VLESS + ws + tls，没有 REALITY）。

只能选一台直连的话，就只能二选一。

## 2. 三种连法放在一起比

### 方案 A：直连香港（只有 relay）

```
你家路由器 ──REALITY+Vision──▶ 香港 VPS ──▶ chatgpt.com
                    (快)                    看到香港 IP → 拒绝服务 ✗
```

速度没问题，但网站不认这个 IP。

### 方案 B：直连美国（只有 exit）

```
你家路由器 ──────ws+tls 跨太平洋──────▶ 美国落地机 ──▶ chatgpt.com
            (绕路、丢包、易被干扰)                 看到美国 IP → 正常 ✓
```

IP 没问题，但国内到美国这一段很难受，而且 ws+tls 的特征比 REALITY 更明显。

### 方案 C：链式（relay → exit）

```
你家路由器 ──REALITY+Vision──▶ 香港 VPS ──骨干网──▶ 美国落地机 ──▶ chatgpt.com
            (快、抗封锁)        (relay)   (机房间线路，通常稳)  (exit)   看到美国 IP ✓
```

- **最难走的一段**（出境那一段）交给 relay：线路好，协议是 REALITY，最不容易被干扰。
- **网站看到的身份**由 exit 决定：IP 干净。
- relay 到 exit 是海外机房之间的通信，一般比国内直连美国稳定得多。

一句话：**把“怎么出去”和“以谁的身份出现”拆开，交给两台不同的机器。**

## 3. 路由器上到底多跑了什么

这是最容易误会的地方，单独说清楚：

- **只有路由器上跑着 zray，而且只有一个进程。**服务器端不需要部署 zray。
- relay 和 exit 跑的都是**标准 Xray 服务端**，配置不用改。relay 只当它收到了一条普通的 VLESS 请求，目标恰好是 `exit-a.example.com:443`；exit 也只当有个客户端从某个 IP 用 VLESS over ws 连了过来，那个 IP 恰好是 relay。
- “绕一圈”是在**数据包的封装层次**上绕：zray 先建好一条到 relay 的隧道，再把“到 exit 的连接”塞进这条隧道里。

用快递打比方：

> 你要给美国的朋友寄东西，但不想让美国那边看出寄件地址是你家。
> 于是你把包裹装进一个写着“美国朋友收”的内箱，再把内箱装进一个写着“香港中转站收”的外箱。
> 快递公司（GFW）只看得到外箱，而且外箱伪装得像普通网购件（REALITY）。
> 香港中转站拆掉外箱，看到内箱上写着美国地址，就照着转寄，但内箱是锁着的，它打不开。
> 美国朋友拆开内箱，替你把东西交给最终收件人（网站）。收件人只知道东西是美国朋友送来的。

封装从外到内：

```
┌─ REALITY 外层 TLS（伪装成访问 example.com）       ← GFW 只能看到这一层
│  └─ VLESS + Vision，目标 exit-a.example.com:443   ← relay 解到这一层为止
│     └─ TLS 1.3（到 exit-a）
│        └─ WebSocket /vless-ws
│           └─ VLESS（flow none），目标 chatgpt.com:443   ← exit 解到这一层
│              └─ 浏览器自己的 HTTPS                        ← 只有网站能解开
```

各方能看到的内容：

| 谁 | 能看到 |
|---|---|
| 你家宽带运营商 / GFW | 你在连 relay，看起来像在访问 `example.com` |
| relay（香港） | 你要连 `exit-a.example.com:443`，其余都是密文 |
| exit（美国） | 你要访问 `chatgpt.com`，来源是 relay 的 IP |
| chatgpt.com | 一个来自 exit 的美国 IP |

## 4. “那我在 relay 服务器上配转发不就行了？”

可以，而且如果 relay 是你自己的 VPS，这往往是**更省事的做法**。两种做法都值得知道：

### 做法一：在 relay 服务端链式（Xray 的 routing + outbound）

在香港 VPS 的 Xray 配置里加一个到美国的 outbound，再用 routing 规则让 `openai.com` 等域名走它。路由器上的 zray 还是普通单节点配置。

- 优点：路由器上只有一层 TLS、一个连接，CPU 和内存都最省；所有设备、所有客户端自动生效。
- 缺点：relay 必须是你能改配置的机器；exit 的账号密码放在 relay 上。

### 做法二：在路由器上链式（本功能）

- 优点：**relay 和 exit 都不用改配置**，可以是机场节点、朋友的机器，或者任何你只有连接参数、没有 root 的服务器；exit 的凭据只放在你家路由器上；挑哪个 exit、坏了切哪个，都由路由器决定。
- 缺点：路由器要多做一层 TLS 加密（exit 那段走 ws，不能用 Vision），每条链式连接占两个连接槽，内存也翻倍。

**怎么选**：relay 是你自己的 VPS，就优先在服务端配。relay 或 exit 是别人提供、你改不了的，再用路由器上的链式。

## 5. 配置逐段解读

以 `config.example.routing.json` 为例：

```json
"outbounds": [
  { "tag": "relay",  "server": "relay.example.com", "security": "reality", ... },
  { "tag": "exit-a", "server": "exit-a.example.com", "security": "tls",
    "network": "ws", "ws_path": "/vless-ws", "flow": "none",
    "dialer": "relay" },
  { "tag": "exit-b", ..., "dialer": "relay" }
]
```

- `outbounds`：列出所有节点，每个用 `tag` 起个名字。
- `"dialer": "relay"`：这是链式的关键。意思是：**连 exit-a 的时候，不要从路由器直接连，而是先经过 relay 再连过去。**没写 `dialer` 的节点就是普通直连。
- `"network": "ws"` + `"flow": "none"`：exit 走 WebSocket，WebSocket 不支持 Vision，所以 flow 必须是 `none`；写成 vision 会在启动时报错。

```json
"rules": [
  { "domain_suffix": ["openai.com", "chatgpt.com", "anthropic.com", "claude.ai"],
    "outbound": ["exit-a", "exit-b"] }
],
"default": ["relay"]
```

- 命中这几个域名的流量，走 `relay → exit-a`。exit-a 连不上就换 `exit-b`。
- 其他流量都走 `default`，也就是只到 relay 为止。看视频、刷网页不用多绕一跳，也不占 exit 的流量。
- 故障切换只在规则给出的这个列表里进行。exit-a 和 exit-b 都失败时，**连接会直接断开，不会退回 relay**。这是故意的：宁可打不开，也不能让 ChatGPT 的请求从香港 IP 出去，那样可能被风控。
- `fail_backoff_s: 30`：某个节点失败后，30 秒内不再尝试它。

## 6. 自己验证：网站到底看到了谁

这几个网站都在 Cloudflare 后面，`/cdn-cgi/trace` 会返回 Cloudflare 看到的来源 IP（`ip=`）和地区（`loc=`）。在路由器或局域网机器上执行：

```sh
# 走 default（只经过 relay）→ 应该显示 relay 的 IP，loc=HK 之类
curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace

# 命中规则（relay → exit）→ 应该显示 exit 的 IP，loc=US 之类
curl --socks5-hostname 127.0.0.1:1080 https://chatgpt.com/cdn-cgi/trace
```

两条命令的 `ip=` 不同，就说明链式生效了。如果第二条显示的也是 relay 的 IP，就检查 `rules` 有没有写对、域名后缀能不能匹配上。

> 如果用的是透明代理（`redirect`），要让规则按域名生效，`sniff` 需要保持开启，否则 zray 只能看到 IP。

## 7. 代价：路由器多做了多少活

| 项目 | 普通直连 | 链式 |
|---|---|---|
| 每条连接占的连接槽 | 1 | 2（`max_connections` 实际可用数量减半） |
| 内存 | 1 个连接结构（约 93 KiB） | 2 个连接结构 + 一对本机回环 socket |
| 加密层数 | relay 用 Vision 时，稳态下基本不加密 | exit 是 ws 时，exit 那层 TLS 全程由路由器做 |
| 延迟 | 1 次握手到 relay | 到 relay，再经 relay 到 exit，首包会慢一些 |

在小米 AC2100（MT7621）上的实测，单个下载、relay 与路由器之间 RTT 约 110 ms：

| 路径 | 吞吐 | zray 每传 1 MB 的 CPU 时间 |
|---|---|---|
| 只走 relay（REALITY + Vision） | 5–7 MB/s | 0.03–0.05 s |
| 链式，exit 也是 REALITY + Vision | 1.2–6 MB/s | 0.10–0.15 s（约 3 倍，多出来的是回环口读写） |
| 链式，exit 是 ws + tls | 约 0.55 MB/s | 约 1.0 s（约 25 倍，多出来的是软件加解密） |

所以建议**只把需要干净 IP 的少数域名放进规则**，不要把 `default` 也设成链式。exit 是 ws 时，按 CPU 推算路由器单核最多 1–1.5 MB/s，只适合 AI 聊天这类小流量。

链式失败时，日志会写明是哪一段的问题：`-> relay side` 是路由器到 relay 没连上，`-> exit side` 是 relay 通了但 exit 没响应或握手出错。

## 8. 常见疑问

**Q：链式比直连香港更安全吗？**
对 GFW 来说没有区别，它看到的都是 REALITY 那一层。区别在于 relay 看不到你访问了哪个网站，exit 看不到你家的 IP。这是一种分散信任的做法，不是更强的加密。

**Q：能不能反过来，exit 在前、relay 在后？**
能配，但没有意义。链路的第一跳决定“好不好出去”，最后一跳决定“以谁的身份出现”，顺序反了两头都吃亏。

**Q：我只有一台美国服务器，从国内直连也挺快，要用这个吗？**
不用。“线路好”和“IP 干净”你已经都有了，直连最省事。

**Q：relay 那边需要做什么设置？**
基本不用。只要确认 relay 的出站没有屏蔽 exit 的地址和端口。如果 exit 设置了来源 IP 白名单，把 relay 的 IP 加进去。
