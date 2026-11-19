# 服务端验收（路线图 3.6）

在 Linux 测试机上，把 sail 和 sing-box 分别作为服务端，用同样的负载并排测量：每条连接占多少内存、建连延迟、短连接高频开关、大块传输的吞吐与每 GiB 的 CPU，以及长时间运行的内存增长。也可以拿两个 sail 版本对比（新对旧），用作性能回归。

```
p36c (负载)                                           p36s (服务端)
netgen --SOCKS--> sing-box 客户端 ==veth 10.98.0.0/24==> 被测服务端
netgen serve <------------------------------- direct 出站 --'
```

- 被测服务端绑在 `--server-cores` 上，其余进程（netgen、客户端、目标服务）绑在 `--load-cores` 上。客户端默认是 sing-box，`--client sail` 改用 sail（见下）。
- 每个客户端进程有 `--carriers` 个 SOCKS 入站，各自对应一个出站：QUIC 和 AnyTLS 因此有这么多条承载连接，TCP 协议则分散到源地址 10.98.0.2–5 上，单一服务端也能保持超过一个源地址的端口数的连接。
- 每一轮里，每个协议都按 `--servers` 依次跑一遍，且每轮、每个协议交替先后顺序，让主机的漂移平均落到双方身上。汇总把前两个服务端按轮配对，给出比值（第一个 / 第二个）的中位数和基于 t 分布的 95% 置信区间；`--servers` 只有一个时（如 `--servers sail`）只给各值的中位数，没有比值。
- 每格都记录服务端命名空间和负载命名空间里 `nstat` 的差值（`ListenOverflows`、`ListenDrops`、`TCPSynRetrans`、`TCPTimeouts`），以及 `/proc/net/softnet_stat` 的丢包差值。

所有负载都只在这两个命名空间之间，退出时删除；脚本不改全局 sysctl。

## 运行

测试机上需要 root，以及 sing-box（作客户端和 REALITY 的握手目标）、`taskset`、`nstat`。netgen 在 `scripts/netem/netgen`。

```sh
python3 run.py --work W --sail W/sail --singbox W/sing-box --netgen W/netgen
python3 run.py ... --protocols trojan --rounds 1 --conns 1000              # 冒烟
python3 run.py ... --sail-base W/sail-old --servers sail,sail-base          # 新旧对比
python3 run.py ... --soak 24 --protocols trojan --servers sail              # 长跑
# Sail/1 与 AnyTLS、Trojan：客户端和服务端都是 sail
python3 run.py ... --client sail --servers sail --protocols sail1,anytls,trojan
```

- `--servers`：取 `sail`、`sail-base`（`--sail-base` 指定的另一个 sail）、`sing-box`；默认 `sail,sing-box`。
- `--protocols`：取 `ss2022,trojan,vless-reality,hy2,tuic,anytls`（默认全部），以及 `sail1`（sail 自己的协议 Sail/1，不在默认里）。`sail1` 只有 sail 会说：要 `--client sail`，`--servers` 只能是 `sail`、`sail-base`，否则在开始前就报错退出；客户端与服务端的 sail 都要用 `--features inbound-sail,outbound-sail` 编译（默认 feature 里没有）。
- `--client`：负载里的客户端进程，`sing-box`（默认）或 `sail`。`--client sail` 用 `--sail-client` 给的 sail（默认就是 `--sail`），以 `--client-profile` 档位运行（默认 `server`），配置与 sing-box 客户端相同（每个进程 `--carriers` 个 SOCKS 入站，各对应一个绑定源地址的出站）。sail 的 AnyTLS 客户端一个会话同时只承载一条流；Sail/1 一个会话最多承载 8 条（`STREAMS_PER_SESSION`），所以 idle 时到服务端的 TCP 连接数远少于流数。
- `--shapes`：取 `idle,churn,bulk`。
  - `idle`：netgen `hold`，以 `--rate` 每秒建立 `--conns` 条连接，并保持 `--hold` 秒。期间每 5 秒在负载命名空间里用 `ss` 数一次到服务端端口的已建立 TCP 连接（绑在 `--load-cores` 上），取最大值记为 `client_tcp_conns_peak`。
  - `churn`：netgen `churn`，经一个代理以 `--churn-rate` 每秒开关，持续 `--churn-seconds` 秒。经一个代理意味着 QUIC 协议的全部流都在一条 QUIC 连接上。
  - `bulk`：经一个代理 8 条流，每条 `--bulk-mib`，下行、上行各一次；QUIC 协议因此只用一条 QUIC 连接。
- `--rounds`：每格重复的轮数。
- `--name`、`--net`：命名空间改为 `<name>c`/`<name>s`、网段改为 `10.<net>.0.0/24`，让两次运行（比如长跑和测量轮次）共用一台主机。

`<work>` 里没有 `cert.pem` 时，脚本用 openssl 生成一对自签名证书（与 netem 的 run.py 相同）。`--server-cores`、`--load-cores` 接受 taskset 的列表写法（`0-1`、`2,3,6`），hostq 租约给的 CPU 不一定连续。任何一格一条连接都没建立（服务端没起来、客户端连不上）时，脚本在写完结果后以非零退出，这样的结果不算数。

结果写到 `<work>/results/<时间>/`：
- `results.json`：每格一条，包括 netgen 的原始结果、服务端 RSS（起点、峰值、结束）、CPU 秒、每连接 KB、每 GiB CPU 秒，以及上面的计数器差值；`client` 是负载客户端的种类，idle 格另有 `client_tcp_conns_peak` 与 `server_kb_per_session`。
- `summary.json`：各格的中位数和配对比值（idle 格含 `server_kb_per_conn`、`server_kb_per_session`、`client_tcp_conns_peak`）。

长跑（`--soak HOURS`）只用 `--servers` 的第一个和 `--protocols` 的第一个，保持 `--conns` 条连接，同时以 `--churn-rate` 开关，每 10 分钟做一次 4 条流、各 64 MiB 的下行传输。每分钟把服务端 RSS 写入 `soak-rss.csv`，结束时在 `soak.json` 给出第 2 小时起的 RSS 斜率。

## 解读

- **先看计数器，再看结果。** `softnet_dropped` 不为 0，说明宿主机的每 CPU 接收队列满了（命名空间之间的每个包都要经过它，默认长度 `net.core.netdev_max_backlog` = 1000），这一格测到的是主机，不是服务端，应作废。在专用机上可以调大它；共享机上不能改全局设置，就把速率降到不丢包为止。
- 负载跟不上时（`offered_seconds` 明显长于 `conns / rate`），建连延迟会两极分化，p99 可达数十秒，双方都会如此，这时的延迟不能用来区分服务端。
- `ListenOverflows` 只在服务端命名空间里出现、且只出现在一方时，说明是那一方的监听队列太短。
- 每连接 KB 是（峰值 RSS − 起点 RSS）/ 已建立的连接数，包含服务端到目标的那一侧连接；内核里的套接字内存不在其中。这是每条流的代价。
- 每会话 KB（`server_kb_per_session`）是（峰值 RSS − 起点 RSS）/ `client_tcp_conns_peak`，即按到服务端的 TCP 连接平摊；每条流一条连接的协议与每连接 KB 相同，Sail/1 的一个会话承载多条流，它的每会话 KB 里也含这些流自己的代价。QUIC 协议没有 TCP 连接，此值为空。
