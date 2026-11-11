# 弱网与长时间运行测试（路线图 5.5）

在 Linux 测试机上，用两个网络命名空间和 `tc netem` 模拟各种网络条件，让被测客户端（sail 或 sing-box）经 SOCKS 入站转发带校验的流量，并记录它的内存、CPU、文件描述符和 TCP 状态。

```
nc5 (10.95.0.1)                                  ns5 (10.95.0.2)
netgen 客户端 --SOCKS--> 被测客户端 ==veth, netem==> sing-box 服务端 --> netgen serve
```

- `netns.sh`：建立、整形、断开这对命名空间。所有操作都只在这两个命名空间里进行，不动宿主机自己的路由和防火墙。在用目录锁登记共享资源的主机上，设 `NETEM_LOCK_DIR`：`up` 先用 `mkdir` 原子地占用 `$NETEM_LOCK_DIR/netns-nc$NS` 和 `netns-ns$NS`（owner 文件写 `NETEM_LOCK_OWNER`，默认 `netem`），任一已被占用就失败、不建任何东西；`up` 中途失败或 `down` 时归还自己占用的锁。整形：带 `rate` 又带 `limit N` 的规格是一个瓶颈，netem 只管延迟、丢包等，队列交给后面的 tbf，按字节限为 N×1500 字节（也可直接用 `bottleneck RATE BYTES SPEC`）。netem 自己的 `limit` 按内核交给它的包计数，而 TCP 交下来的是多段的 GSO 包，与网卡卸载开关无关（2026-10-25 实测平均约 17 KB 一个，`limit 330` 攒了 3.6 MB）。只带 `rate`、不带 `limit` 的规格只为让带抖动的包保持顺序；这个速率要有限，又要远高于格子本身的速率（`run.py` 用 4gbit）：100gbit 时延迟提前结束的包会和排在它后面的包一起放出，成千个包一下子涌进接收端 CPU 的 backlog，超过 `netdev_max_backlog` 的被丢掉；netem 按前一个包（连同它的延迟）排下一个包的时间，所以速率离格子太近就成了上限，1gbit 时 rtt50 的 QUIC 只到 550–600 Mbit/s。
- `netgen/`：流量工具（Go）。双方发送的每个字节都来自带种子的生成器，由对端校验，所以数据损坏、截断、错序都会被计数，不会漏掉。模式包括大块上下行、回显往返、建连延迟、大量并发、按固定速率建立并保持大量连接（`hold`，给出建连延迟到 p999，可经多个 SOCKS 代理轮流建连）、短连接高频开关（`churn`，轮流连同一接收端的 16 个端口：都连同一个地址和端口时，先关闭的一方每条连接留下一个 TIME-WAIT，每秒数百条时内核在其中找空闲源端口，每次 connect() 要几毫秒，测到的就成了内核而不是代理）、两个方向的半关闭，以及断网期间的连通性探测。`-cc NAME` 给客户端模式拨出的连接设拥塞控制，`serve -listen` 的地址后加 `/NAME` 给该端口接受的连接设（仅 Linux，共存格的参照流用）。
- `ns_exec.py`：保留 `ip netns exec` 的命名空间 DNS/hosts 覆盖和网络 sysfs，同时把调用者原有的 cgroup 挂载树带入新的私有挂载命名空间。进程仍属于调用者设置的 cgroup；脚本不创建或放宽内存限制。需要恢复 cgroup 时使用 Linux 5.2 起的 `open_tree` / `move_mount`，优先调用 libc 的同名接口；旧 libc 在 64 位 x86_64、aarch64 上使用已知的 Linux syscall ABI，其他架构需要 libc 提供接口。缺少接口、权限或内核支持时明确失败，避免静默使用宿主机内存测量。没有 cgroup 挂载时沿用原来的启动方式。
- `run.py`：编排。每组（协议 × 客户端）按场景依次整形、跑负载、采样，结果写到 `<work>/results/<时间>/summary.json`（`{"schema": 1, "congestion": {...}, "runs": [...]}`，每次运行一项）；只有出现失败的组才保留压缩后的原始记录。`congestion` 是宿主机和两个命名空间的系统拥塞控制（`net.ipv4.tcp_congestion_control` 与可用列表），即 sing-box 和未自选的一方所用的；每项负载的 `congestion` 是经过整形链路的代理连接实际用的拥塞控制（`ss -i`，客户端到服务端的连接与服务端接受的连接各一份，取各算法同时最多的连接数）。同一个 sail 二进制的两种设置互比时用 `--sail-bin NAME=PATH` 加 `--sail-arg NAME=--set --sail-arg NAME=KEY=VALUE`。每项负载还记两侧的重传段数与发出段数（`retrans`、`outsegs`，`/proc/net/snmp`）、变动的 TcpExt 计数与整形队列的丢包（`link`）；大流量负载另记发送方代理连接每秒的状态（`sender`：合计的 pacing 与 delivery 速率、BBR 的带宽估计与增益、RTT、最小 RTT、窗口），用来比较同一格里快慢不同的轮次。`--only coexist` 跑共存格（不在默认场景里）：100 Mbit/s、40 ms RTT 的链路，浅队列（0.5×BDP）与深队列（4×BDP）各一格，一条经代理的流和一条不经代理、用内核默认拥塞控制的流同时开始，记两者都还在传时各占的份额（`shares`，去掉开头 5 秒）。

## 运行

测试机上需要 root，以及 `tc`、`ss`、`ethtool`、sing-box（作服务端和对照客户端）。

```sh
# 本机交叉编译 netgen，连同 sail 的 release 版放到测试机
(cd netgen && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o netgen .)
# 测试机上（sail 在临时 target 里编译，限制并行，编完删掉 target）
python3 run.py --work WORK --sail WORK/sail --netgen WORK/netgen
python3 run.py --protocols direct --clients sail-server --only baseline --quick   # 冒烟
```

`--protocols` 取 `direct,ss,trojan,vless,reality,hy2,tuic,tuic-cubic,tuic-bbr,mux,h2mux,smux`（默认前三个；`vless` 是 TLS 上的 vless、不带 flow；`reality` 是 vless+REALITY+vision，握手目标是服务端 netns 里另起的一个 sing-box（只开 TLS 的 http 入站）：`openssl s_server` 一次只服务一条连接，短连接场景里握手会排队等它，每秒 500 条时最多排到约 1.45 秒，ClientHello 越大越容易撞上；`tuic` 两端都用 bbr，`tuic-cubic`、`tuic-bbr` 显式指定两端的拥塞控制；`mux` 是开了 sing-mux 的 trojan（max_connections 4，默认协议），`h2mux`、`smux` 指定其多路复用协议）；`--clients` 取 `sail-server,sail-mobile,sing-box`（sail 的运行档位，或 sing-box 作对照）；`--inbound tun` 让客户端改用 tun 入站（auto_route，接管客户端 netns 的全部流量），netgen 直接连目标，走的是 TUN 路径而不是 SOCKS；`--only` 只跑名字含该子串的场景，可用逗号分隔多个（如 `--only baseline,rate10m`；`disconnect`、`rtt_step`、`concurrency`、`halfclose` 选对应的一组）；`--shape NAME=SPEC` 加一个自定的受限场景（SPEC 是 netem 的参数，如 `rtt100='delay 50ms'`；限速时要自带 `limit`），配合 `--only NAME` 单独跑；`--churn-rates` 设并发场景里 churn 阶段每秒新建的连接数，逗号分隔，默认 `200,500`；`--quick` 缩短每项负载；`--client-set KEY=VALUE` 把 sail 的 `--set` 传给被测客户端（可重复）；`--only route_switch` 单独跑默认路由切换（客户端经默认路由连服务端并跟随默认网卡）。

`--servers` 里的 `sail` 以 `--server-profile` 档位运行（默认 `server`）。2026-10-03 之前 sail 服务端不带 `--profile`，跑的是默认的桌面档位，那之前“sail 作服务端”的结果都属于桌面档位。每项负载除了客户端的 `cpu_s`，还记录协议服务端进程的 `server_cpu_s`（同一时段，/proc 的 utime+stime）。

对比矩阵：`--matrix PAIRS` 依次跑客户端>服务端组合（每边取 `sb`、`sail` 或 `--sail-bin NAME=PATH` 给出的另一个 sail 二进制，如 `--matrix sb>sb,sail>sb,sb>sail,sail>sail`），轮次在最外层，每轮轮换组合与协议的顺序，邻居噪声落在各组合上大致均匀。`--sail-env NAME=KEY=VALUE` 与 `--sail-arg NAME=ARG` 给矩阵里名为 NAME 的一边（`sail` 或 `--sail-bin` 的名字）加环境变量或命令行参数（可重复），用来比较同一个二进制的不同启动方式，例如 `--sail-bin w1=WORK/sail --sail-env w1=TOKIO_WORKER_THREADS=1`、`--sail-bin st=WORK/sail --sail-arg st=--single-thread`；`--client-profile` 设矩阵里 sail 客户端的档位（默认 `server`），`--sail-profile NAME=PROFILE` 给 `--sail-bin` 名为 NAME 的客户端单独的档位，同一个二进制的几个档位就能同跑一次、共用一组 sing-box 对照（如 `--sail-bin mob=WORK/sail --sail-profile mob=mobile --sail-bin rtr=WORK/sail --sail-profile rtr=router --matrix mob>sb,rtr>sb,sb>sb`）。`--host-cc NAME` 把两个命名空间的系统拥塞控制设为 NAME（`NETEM_CC`，netns.sh `up` 时设置；默认沿用宿主机的），即 sing-box 和 server 档位等未自选拥塞控制的一方所用的，用来模拟 `net.ipv4.tcp_congestion_control = bbr` 的服务器；实际值记在 `summary.json` 的 `congestion` 里。每次运行的 `threads` 记下客户端与服务端进程在开始和结束时各名字的线程数，用来确认工作线程数确实生效。配合使用：`--bulk-only` 只跑上下行大块；`--bulk-bytes-quic N` 给 hy2 和 tuic 单独的大块字节数；`--netgen-cpus LIST` 把两端的 netgen 绑到客户端与服务端之外的 CPU（多 Gbit 的格子至少给 4 个：只给 2 个时每个组合都卡在约 3.3 Gbit/s，瓶颈是 netgen 自己的 CPU。这样的格子连同客户端、服务端各 2 个共要 8 个 CPU，向 hostq 申请时按这个数要；在 hostq 租约里运行时，若绑定的 CPU 超出租约，run.py 一开始就报错退出）；`--end-settle S` 是运行结束前客户端的静置秒数（默认 10，用于静止 RSS；只看吞吐时可缩短）。`--peer-cpus LIST` 给矩阵里各组合共用的一边（只比较客户端时是 sing-box 服务端，只比较服务端时是 sing-box 客户端）单独的 CPU，取代那一边的 `--server-cpus` 或 `--cpus`：两边各 2 个 CPU 时，multi-Gbit 的 REALITY 与 smux 格限住吞吐的是作对照的 sing-box 一端，比的不是 sail（2026-10-24），所以共用的一边要比被比较的两组多，被比较的两组保持相同的限制。大块传输的结果里还有 `client_cpu_s_per_gib` 与 `server_cpu_s_per_gib`：客户端与协议服务端进程在这次传输里每 GiB 的 CPU 秒（/proc 的 utime+stime，不含在其他上下文里处理的软中断），与 Mbit/s 并列，多轮时也给出中位数。`client_cpu_sched_s_per_gib` 是同一客户端进程按 schedstat 的纳秒计的 CPU，比 utime+stime 的 tick 细，短传输只有几个 tick 时看它。软中断时间不计入进程（IRQ 时间记账）：没有 fq 时 BBR 的 pacing 定时器发出的包就在那里处理，落在定时器所在的 CPU 上。所以另记 `host_softirq_s_per_gib`（全机）和 `client_softirq_s_per_gib`（给了 `--cpus` 时，客户端的 CPU）。比较拥塞控制的 CPU 代价时看进程加全机软中断：只看客户端 CPU 的软中断，会把挪到那里的工作当成额外开销（2026-10-28，mobile 直连上传，1 Gbit/s 与 300 Mbit/s 的瓶颈上 bbr 在客户端 CPU 上的软中断是 cubic 的 8–11 倍，全机只多 1–6%）。

停读客户端：`--stalled N` 在每次 `bulk_down` 前经客户端再开 N 条没人读的下载（netgen `stall` 模式，每条请求 1 GiB 后不再读），等 3 s 让数据填满沿途能填的缓冲，再跑下载，下载结束后关掉。这样测的是停读的局域网客户端加正常下载时客户端的内存峰值（sail#10，路由器档位在 64 MiB cgroup 下 20 条停读加 4 条下载）；实际打开的条数记在结果的 `stalled` 里。

停读目标：`--stalled-up N` 是服务端那一侧的同一件事：在每次 `bulk_up` 前经客户端和服务端再开 N 条上传，目标一个字节都不读（netgen `stallup` 模式，目标端是 `K` 命令），用来测服务端在停读流旁边的内存和其他流的吞吐（sail#18）。

长跑：`--soak HOURS` 代替上面的场景，客户端不重启，在基线、高延迟、丢包、限速、突发丢包之间轮换，每轮跑一组轻量的带校验负载后静置 60 秒、记录客户端的静止 RSS 与描述符；每小时向该次运行目录下的 `soak.jsonl` 追加一行，结束时按“第 2 小时到最后一小时静止 RSS 增长低于 10%”判定。`--cpus LIST` 把客户端一侧（被测客户端与 netgen）绑到这些 CPU 上（`taskset -c`），`--server-cpus LIST` 把服务端一侧绑到另一组 CPU；只给 `--cpus` 时两侧都绑到同一组，用于和另一个长跑共用主机。

吞吐格子要稳：共享主机上单次结果的波动可达 2 倍。`--rounds N` 让每个受限场景的负载重复 N 次，汇总给出中位数、最小与最大值；`--bulk-bytes` 加大每条流的字节数，让传输足够长（例如每条 30 秒以上）；再用 `--cpus`/`--server-cpus` 把两侧分开绑核。

每次大块传输（上行、下行各一次），以及每组断网、rtt_step、并发与半关闭，都在新启动的客户端与服务端进程上开始：没有上一格留下的连接、QUIC 连接池或多路复用的承载连接，也没有它们的拥塞状态；netns.sh 还在两个 namespace 里设 `net.ipv4.tcp_no_metrics_save=1`，新 TCP 连接不沿用内核为同一地址缓存的 ssthresh。所以一格的结果与 `--only` 里排在它前面的格无关，记录里的 `cold` 为真。此前（2026-10-24 之前）同一运行内的各格共用进程，QUIC 与多路复用的格接着上一格的连接测，`--only` 的顺序会改变结果（rtt300 跟在 rtt150 之后约 280 Mbit/s，单独测约 90）。冷启动在长 RTT 上要几秒才爬出慢启动，rtt150 与 rtt300 因此每条流传 128 MiB（见 run.py 的 `BULK_BYTES`）。

## 场景

| 场景 | 条件 |
| --- | --- |
| baseline | 不整形 |
| rtt50 / rtt150 / rtt300 | 往返延迟，±10% 正态抖动，包保持顺序（netem 加 `rate 100gbit`；只有抖动时 netem 会按各包的延迟乱序发出，测到的是乱序容忍度。2026-10-02 之前的 rtt* 结果属于这种情况） |
| loss0.5 / loss2 / loss5 | 随机丢包，10ms 单向延迟 |
| burst2 | Gilbert-Elliott 突发丢包，平均约 2% |
| reorder5 / reorder25 | 乱序，20ms 单向延迟。netem 让被乱序的包不经过延迟直接发出，RTT 样本里会有接近 0 的值：以最小 RTT 定窗口的拥塞控制（BBR）在这两格的结果混有这个假象，不是纯粹的乱序容忍度；rtt_step 有意用它触发问题 |
| rate10m / rate2m | 限速，20ms 单向延迟 |
| blackhole5 / blackhole30 | 双向全丢 5s / 30s，链路保持 up |
| linkdown10 | 客户端一侧链路 down 10s |
| server_restart | 服务端进程重启 |
| rtt_step | 同一个客户端进程（连接不断）先在 RTT 样本里有接近 0 的链路上跑，再换到 150ms、50Mbit/s、深队列的链路上跑，见下 |
| concurrency | 2000 条并发连接保持后逐条验证；200/s、500/s 的短连接 |
| halfclose | 两个方向的半关闭各 50 次，无损和 2% 丢包下 |

rtt_step 分两段，中间不重启任何进程，QUIC 类协议的那一条连接一直保持。第一段用 `delay 20ms reorder 25% 50%`：被乱序的那四分之一的包不经过延迟，RTT 样本里有接近 0 的值，速率只有几 Mbit/s；先下行后上行各一次大块传输（4 条流 × 2 MiB，各约 10–20 秒）。随后约 1 秒内换上 `delay 75ms rate 50mbit limit 3000`（RTT 150ms，队列约 0.7 秒），第二段先上行后下行各一次（4 条流 × 8 MiB，按链路速率各约 6 秒）。通过的标准：第二段两次传输的 4 条流都完整送达（netgen 的任一读写 10 秒没有进展、或上行发完后 120 秒内等不到服务端的校验结果，都算失败），并且由 sail 发送的那一向（sail 作客户端时的上行、作服务端时的下行）不低于 15 Mbit/s，即链路的 30%。最小 RTT 若一直沿用第一段测到的值，拥塞窗口只剩几个包：sail 的 quinn fork 修正 BBR 之前，sail 在第二段发送的速率是 2.3–2.8 Mbit/s（作客户端连 sing-box 或 sail 的上行，作服务端的下行，各 2 次）；修正后作客户端 20–27 Mbit/s、作服务端 39–41 Mbit/s（其中头 10 秒旧的最小值还在）。15 是这两组测量之间的判断值。第一段不整形或只是 10ms 延迟时测不出这个问题：那时的带宽样本高，窗口不会缩小（修正前后都是 45 Mbit/s）。

## 判定

| 判定 | 标准 | 来源 |
| --- | --- | --- |
| 数据 | 零损坏、零截断 | 绝对要求 |
| 进程 | 不崩溃、不退出 | 绝对要求 |
| 无损链路（baseline） | 零失败操作 | 绝对要求（弱网场景的失败只计数） |
| 断网恢复 | 链路恢复后 3 秒内新连接成功；超过的报告原因，不直接判失败 | 路线图 2.12 的验收（"3 秒内恢复新连接"） |
| 半关闭 | 两个方向都完整送达 | 绝对要求 |
| 并发 | 2000 条全部建立并存活 | bench/core-compare 的 2000 并发 |
| 资源泄漏 | 每个场景后内存、fd、TCP 连接回到空闲基线附近 | 阈值待首轮基线测量后定 |
| 吞吐与延迟 | 与 sing-box 作客户端在同一场景下比较 | 阈值待首轮测量后定 |

所有进程以 `ulimit -n 65536` 运行，与实际部署一致：Go 程序启动时会自己把文件描述符软限制提到硬限制。

## 共享测试机上的约定

- 两组运行要并行时，用环境变量各占一对命名空间：`NETEM_NS`（默认 5，即 `nc5`/`ns5`）和 `NETEM_NET`（默认 95，即 10.95–10.97 三个 /24）。`netns.sh` 和 `run.py` 读同一组变量，例如 `NETEM_NS=54 NETEM_NET=90` 用 `nc54`/`ns54` 和 10.90–10.92。共享主机上，用前按主机的约定登记占用。
- 只在自己的一对命名空间和三个网段里工作（默认 `nc5`/`ns5` 和 10.95–10.97）；名字或网段已被占用时 `netns.sh up` 拒绝启动，退出时删除命名空间。
- 编译和每次运行前检查 `df -h /`；可用空间不足 2 GiB 时 `run.py` 不启动。
- sail 在临时 target 里用 `CARGO_BUILD_JOBS=2` 编译（默认并行度在这台机器上会被 OOM 杀掉），编完删除 target。
- 24 小时长跑前先与机器上正在运行的其他长任务协调。

## 命名空间启动回归测试

在有 cgroup v2 memory 控制器、网络和挂载命名空间权限的 Linux 测试机上运行：

```sh
sudo python3 scripts/netem/test_ns_exec.py
```

测试只建立自己的命名空间、dummy 网卡和 64 MiB cgroup，不发网络流量；验证原启动方式隐藏 cgroup 的对照、修复后的限制可见性、DNS/hosts、网络 sysfs、CPU 绑定、引号、退出状态和进程组终止，并检查宿主挂载不变。另验证嵌套只读控制器式挂载的递归保留及无 cgroup、恢复失败路径。测试结束清理自己的资源。cgroup v1 的路径识别有单元测试；实际 memory 控制器测试使用 v2，嵌套挂载测试不声称运行了 v1 内存控制器。
