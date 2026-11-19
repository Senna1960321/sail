#!/usr/bin/env python3
"""Server-side acceptance (roadmap 3.6): sail and sing-box as the server,
side by side, at the 10k level, as design-notes' 3.6 design has it.

  p36c (load)                                          p36s (server)
  netgen --SOCKS--> sing-box clients ==veth 10.98.0.0/24==> server under test
  netgen serve <-------------------------- direct outbound --'

- The server runs pinned to --server-cores; everything else to the rest.
- Each client process has --carriers SOCKS inbounds, each with an outbound
  of its own: QUIC and AnyTLS get that many carrier connections, and the
  TCP protocols spread over the source addresses 10.98.0.2..5.
- Each round runs every protocol with each of --servers (sail, sail-base:
  the --sail-base binary, sing-box) in alternating order, so the host's
  drift falls on both alike; the summary pairs the first two per round.
- Shapes: idle (netgen hold), churn (netgen churn), bulk (netgen bulk up
  and down, with server CPU per GiB). --soak runs a mixed load for hours
  and samples the server's RSS every minute.

- --client sail makes the load's client processes sail (--sail-client,
  default --sail) instead of sing-box; Sail/1 (--protocols sail1) needs it,
  and sail servers, all built with the features inbound-sail and
  outbound-sail. With one server, the summary gives its values and no ratio.
- idle also counts the TCP connections the load holds to the server, for
  KB per session beside KB per stream.

Everything stays in the two namespaces, which are removed on exit; no
global sysctl is touched. Results go to <work>/results/<time>/.

  python3 run.py --work W --sail W/sail --singbox W/sing-box --netgen W/netgen
  python3 run.py ... --protocols trojan --rounds 1 --conns 1000   # smoke
  python3 run.py ... --soak 24 --protocols trojan --servers sail
  python3 run.py ... --sail-base W/sail-old --servers sail,sail-base   # regression
  python3 run.py ... --client sail --servers sail --protocols sail1,anytls,trojan
"""
import argparse, json, math, os, signal, statistics, subprocess, sys, time

# Set by configure() from --name and --net, so that two runs (the soak and
# the rounds) can share a host apart.
NS_C, NS_S = "p36c", "p36s"
SERVER_IP, TARGET_IP = "10.98.0.1", "10.98.0.2"
CLIENT_IPS = ["10.98.0.2", "10.98.0.3", "10.98.0.4", "10.98.0.5"]
NOFILE = 1048576


def configure(name, net):
    global NS_C, NS_S, SERVER_IP, TARGET_IP, CLIENT_IPS
    NS_C, NS_S = f"{name}c", f"{name}s"
    SERVER_IP, TARGET_IP = f"10.{net}.0.1", f"10.{net}.0.2"
    CLIENT_IPS = [f"10.{net}.0.{i}" for i in range(2, 6)]


def targets():
    """A netgen server on each client address: the server's connections to
    them stay within the ephemeral ports of one source and destination."""
    return [f"{ip}:{TARGET_PORT}" for ip in CLIENT_IPS]
PORT, HS_PORT, TARGET_PORT, SOCKS_BASE = 4430, 8443, 9000, 2000
UUID = "90ee4432-671e-4ec8-8512-15d5fd0f8eab"
PSK, USER_PSK = "AAECAwQFBgcICQoLDA0ODw==", "EBESExQVFhcYGRobHB0eHw=="
PROTOCOLS = ["ss2022", "trojan", "vless-reality", "hy2", "tuic", "anytls"]
# Sail/1: only sail speaks it, both ends (a binary built with the features
# inbound-sail and outbound-sail), so not in the defaults. Its user token is
# 32 bytes, unpadded base64url.
SAIL_ONLY = {"sail1"}
SAIL_TOKEN = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"
TICK = os.sysconf("SC_CLK_TCK")


def sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)


def spawn(ns, cores, cmd, log):
    """Runs `cmd` in `ns` pinned to `cores`; exec keeps the pid, whose RSS
    and CPU are read."""
    return subprocess.Popen(
        ["taskset", "-c", cores, "ip", "netns", "exec", ns, "sh", "-c", f"ulimit -n {NOFILE}; exec {cmd}"],
        stdout=open(log, "w"), stderr=subprocess.STDOUT)


def stop(*procs):
    for p in procs:
        if p and p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for p in procs:
        if p:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()


def rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def cpu_s(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / TICK  # utime, stime


COUNTERS = ("TcpExtListenOverflows", "TcpExtListenDrops", "TcpExtTCPSynRetrans", "TcpExtTCPTimeouts")


def tcp_counters(ns):
    """The namespace's TCP counters that tell a dropped SYN or a full accept
    queue: a slow server, or a host that cannot keep up."""
    out = sh(f"ip netns exec {ns} nstat -az {' '.join(COUNTERS)}", check=False).stdout
    got = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 2 and f[0] in COUNTERS:
            got[f[0]] = int(f[1])
    return got


def softnet_dropped():
    """Packets the host's per-CPU backlogs dropped, all CPUs."""
    with open("/proc/net/softnet_stat") as f:
        return sum(int(line.split()[1], 16) for line in f)


def tcp_conns_to_server(cores):
    """The established TCP connections from the load's namespace to the
    server's port."""
    out = sh(f"taskset -c {cores} ip netns exec {NS_C} ss -tnH state established "
             f"'( dport = :{PORT} )'", check=False).stdout
    return sum(1 for line in out.splitlines() if line.strip())


def sockstat(ns):
    out = sh(f"ip netns exec {ns} cat /proc/net/sockstat", check=False).stdout
    for line in out.splitlines():
        if line.startswith("TCP:"):
            f = line.split()
            return int(f[f.index("inuse") + 1])
    return 0


# ---- configurations ----

def server_tls(work, reality=None, keys=None):
    if reality:
        return {"enabled": True, "server_name": "localhost",
                "reality": {"enabled": True, "handshake": {"server": SERVER_IP, "server_port": HS_PORT},
                            "private_key": keys[0], "short_id": ["0123456789abcdef"]}}
    return {"enabled": True, "certificate_path": f"{work}/cert.pem", "key_path": f"{work}/key.pem"}


def client_tls(reality=None, keys=None):
    if reality:
        return {"enabled": True, "server_name": "localhost", "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": keys[1], "short_id": "0123456789abcdef"}}
    return {"enabled": True, "server_name": "localhost", "insecure": True}


def inbound(proto, work, keys):
    base = {"tag": "in", "listen": SERVER_IP, "listen_port": PORT}
    return {
        "ss2022": lambda: {**base, "type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": PSK,
                           "users": [{"name": "u", "password": USER_PSK}]},
        "trojan": lambda: {**base, "type": "trojan", "users": [{"name": "u", "password": "p"}],
                           "tls": server_tls(work)},
        "vless-reality": lambda: {**base, "type": "vless",
                                  "users": [{"name": "u", "uuid": UUID, "flow": "xtls-rprx-vision"}],
                                  "tls": server_tls(work, True, keys)},
        "hy2": lambda: {**base, "type": "hysteria2", "users": [{"name": "u", "password": "p"}],
                        "tls": server_tls(work)},
        "tuic": lambda: {**base, "type": "tuic", "users": [{"name": "u", "uuid": UUID, "password": "p"}],
                         "congestion_control": "bbr", "tls": {**server_tls(work), "alpn": ["h3"]}},
        "anytls": lambda: {**base, "type": "anytls", "users": [{"name": "u", "password": "p"}],
                           "tls": server_tls(work)},
        "sail1": lambda: {**base, "type": "sail", "users": [{"token": SAIL_TOKEN}],
                          "tls": server_tls(work)},
    }[proto]()


def outbound(proto, tag, bind, keys):
    base = {"tag": tag, "server": SERVER_IP, "server_port": PORT, "inet4_bind_address": bind}
    return {
        "ss2022": lambda: {**base, "type": "shadowsocks", "method": "2022-blake3-aes-128-gcm",
                           "password": f"{PSK}:{USER_PSK}"},
        "trojan": lambda: {**base, "type": "trojan", "password": "p", "tls": client_tls()},
        "vless-reality": lambda: {**base, "type": "vless", "uuid": UUID, "flow": "xtls-rprx-vision",
                                  "tls": client_tls(True, keys)},
        "hy2": lambda: {**base, "type": "hysteria2", "password": "p", "tls": client_tls()},
        "tuic": lambda: {**base, "type": "tuic", "uuid": UUID, "password": "p", "congestion_control": "bbr",
                         "tls": {**client_tls(), "alpn": ["h3"]}},
        "anytls": lambda: {**base, "type": "anytls", "password": "p", "tls": client_tls()},
        # The outbound sets its own ALPN.
        "sail1": lambda: {**base, "type": "sail", "token": SAIL_TOKEN, "tls": client_tls()},
    }[proto]()


def client_config(proto, process, carriers, keys):
    """A client process: `carriers` SOCKS inbounds, each routed to an
    outbound of its own, all bound to the process's source address."""
    bind = CLIENT_IPS[process % len(CLIENT_IPS)]
    inbounds, outbounds, rules = [], [], []
    for k in range(carriers):
        port = SOCKS_BASE + process * carriers + k
        inbounds.append({"type": "socks", "tag": f"s{k}", "listen": "127.0.0.1", "listen_port": port})
        outbounds.append(outbound(proto, f"o{k}", bind, keys))
        rules.append({"inbound": [f"s{k}"], "outbound": f"o{k}"})
    return {"log": {"level": "error"}, "inbounds": inbounds, "outbounds": outbounds, "route": {"rules": rules}}


def write(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)
    return path


# ---- the namespaces ----

def up():
    for ns in (NS_C, NS_S):
        if sh(f"ip netns list | grep -qw {ns}", check=False).returncode == 0:
            sys.exit(f"{ns} exists: another run, or a stale one (ip netns del {ns})")
    sh(f"ip netns add {NS_C}")
    sh(f"ip netns add {NS_S}")
    sh(f"ip link add c36 netns {NS_C} type veth peer name s36 netns {NS_S}")
    for ns, dev in ((NS_C, "c36"), (NS_S, "s36")):
        sh(f"ip netns exec {ns} ip link set lo up")
        sh(f"ip netns exec {ns} ip link set {dev} up")
        sh(f"ip netns exec {ns} sysctl -qw net.ipv4.ip_local_port_range='10000 65535' "
           f"net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535")
    sh(f"ip netns exec {NS_S} ip addr add {SERVER_IP}/24 dev s36")
    for ip in CLIENT_IPS:
        sh(f"ip netns exec {NS_C} ip addr add {ip}/24 dev c36")


def down():
    for ns in (NS_C, NS_S):
        sh(f"ip netns pids {ns} 2>/dev/null | xargs -r kill -9", check=False)
        sh(f"ip netns del {ns}", check=False)


# ---- one measurement ----

class Run:
    def __init__(self, args, out, keys, server_cores, load_cores):
        self.args, self.out, self.keys = args, out, keys
        self.server_cores, self.load_cores = server_cores, load_cores

    def start(self, server, proto):
        a = self.args
        cfg = write(f"{self.out}/server-{proto}.json",
                    {"log": {"level": "error"}, "inbounds": [inbound(proto, a.work, self.keys)],
                     "outbounds": [{"type": "direct", "tag": "direct"}]})
        sail = {"sail": a.sail, "sail-base": a.sail_base}.get(server)
        cmd = f"{sail} --profile server -c {cfg}" if sail else f"{a.singbox} run -c {cfg}"
        self.server = spawn(NS_S, self.server_cores, cmd, f"{self.out}/log-{server}-{proto}.txt")
        self.clients = []
        for p in range(a.processes):
            ccfg = write(f"{self.out}/client-{proto}-{p}.json", client_config(proto, p, a.carriers, self.keys))
            ccmd = (f"{a.sail_client} --profile {a.client_profile} -c {ccfg}" if a.client == "sail"
                    else f"{a.singbox} run -c {ccfg}")
            self.clients.append(spawn(NS_C, self.load_cores, ccmd,
                                      f"{self.out}/log-client-{proto}-{p}.txt"))
        time.sleep(2)
        # Warm: what is set up once per carrier or lazily is, before the base.
        self.netgen("setup", f"-proxy {self.proxies()[0]} -n 50", check=False)
        time.sleep(2)

    def proxies(self):
        a = self.args
        return [f"127.0.0.1:{SOCKS_BASE + i}" for i in range(a.processes * a.carriers)]

    def netgen(self, mode, flags, check=True):
        a = self.args
        r = sh(f"taskset -c {self.load_cores} ip netns exec {NS_C} sh -c 'ulimit -n {NOFILE}; "
               f"exec {a.netgen} {mode} -target {TARGET_IP}:{TARGET_PORT} -timeout 60s {flags}'", check=False)
        try:
            return json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            if check:
                raise RuntimeError(f"netgen {mode}: {r.stdout[-300:]} {r.stderr[-300:]}")
            return {}

    def measure(self, server, proto, shape, run):
        """Runs `run` (a netgen call) while sampling the server."""
        pid = self.server.pid
        base_rss, base_cpu = rss_kb(pid), cpu_s(pid)
        before = {ns: tcp_counters(ns) for ns in (NS_S, NS_C)}
        before_drops = softnet_dropped()
        t0 = time.time()
        import threading
        peak = {"rss": base_rss, "sockets": 0}
        done = threading.Event()

        def sample():
            while not done.wait(1):
                try:
                    peak["rss"] = max(peak["rss"], rss_kb(pid))
                    peak["sockets"] = max(peak["sockets"], sockstat(NS_S))
                except FileNotFoundError:
                    return

        # The TCP connections the load holds to the server, at most: one a
        # stream for most protocols (AnyTLS too: its clients carry one
        # stream a session at a time), one a session of up to 8 streams
        # for Sail/1, none for QUIC. Only for idle,
        # where they are held, and every 5 s on the load's cores: ss over
        # tens of thousands of sockets is not free.
        if shape == "idle":
            peak["tcp_conns"] = 0

        def sample_conns():
            while not done.wait(5):
                peak["tcp_conns"] = max(peak["tcp_conns"], tcp_conns_to_server(self.load_cores))

        th = threading.Thread(target=sample)
        th.start()
        tc = threading.Thread(target=sample_conns) if shape == "idle" else None
        if tc:
            tc.start()
        result = run()
        done.set()
        th.join()
        if tc:
            tc.join()
        time.sleep(2)
        delta = {ns: {k: v - before[ns].get(k, 0) for k, v in tcp_counters(ns).items()} for ns in (NS_S, NS_C)}
        return {"tcp_server_ns": delta[NS_S], "tcp_load_ns": delta[NS_C],
                "softnet_dropped": softnet_dropped() - before_drops,"server": server, "proto": proto, "shape": shape, "netgen": result,
                "seconds": round(time.time() - t0, 2), "rss_base_kb": base_rss, "rss_peak_kb": peak["rss"],
                "rss_after_kb": rss_kb(pid), "cpu_s": round(cpu_s(pid) - base_cpu, 3),
                "server_sockets_peak": peak["sockets"], "load": open("/proc/loadavg").read().split()[0],
                "server_cores": self.server_cores, "client": self.args.client,
                "client_tcp_conns_peak": peak.get("tcp_conns")}

    def stop(self):
        stop(*self.clients, self.server)


def shapes(r, server, proto, a):
    out = []
    if "idle" in a.shapes:
        out.append(r.measure(server, proto, "idle", lambda: r.netgen(
            "hold", f"-proxies {','.join(r.proxies())} -targets {','.join(targets())} "
                    f"-conns {a.conns} -rate {a.rate} -hold {a.hold}s")))
    if "churn" in a.shapes:
        out.append(r.measure(server, proto, "churn", lambda: r.netgen(
            "churn", f"-proxy {r.proxies()[0]} -rate {a.churn_rate} -duration {a.churn_seconds}s")))
    if "bulk" in a.shapes:
        for direction in ("down", "up"):
            out.append(r.measure(server, proto, f"bulk-{direction}", lambda d=direction: r.netgen(
                "bulk", f"-proxy {r.proxies()[0]} -streams 8 -bytes {a.bulk_mib << 20} -dir {d}")))
    for m in out:
        g = m["netgen"]
        n = g.get("established") or g.get("ok") or 0
        m["server_kb_per_conn"] = round((m["rss_peak_kb"] - m["rss_base_kb"]) / n, 2) if n and m["shape"] == "idle" else None
        # Per TCP connection to the server: per session where streams share
        # one (Sail/1), the same as per stream where they do not. The
        # streams' own cost (and their connections to the target) is in it.
        tcp = m.get("client_tcp_conns_peak")
        m["server_kb_per_session"] = (round((m["rss_peak_kb"] - m["rss_base_kb"]) / tcp, 2)
                                      if tcp and m["shape"] == "idle" else None)
        if m["shape"].startswith("bulk") and g.get("bytes"):
            m["cpu_s_per_gib"] = round(m["cpu_s"] / (g["bytes"] / (1 << 30)), 3)
    return out


def summarize(results, servers):
    """Medians per (shape, protocol, server), and the paired ratio of the
    first server to the second per round with a t-based 95% interval."""
    keys = {"idle": ["server_kb_per_conn", "server_kb_per_session", "client_tcp_conns_peak",
                     ("netgen", "setup", "p99_ms"), ("netgen", "setup", "p999_ms")],
            "churn": [("netgen", "setup", "p99_ms"), "cpu_s"],
            "bulk-down": ["cpu_s_per_gib", ("netgen", "mbps")], "bulk-up": ["cpu_s_per_gib", ("netgen", "mbps")]}

    def get(m, k):
        if isinstance(k, tuple):
            v = m
            for part in k:
                v = v.get(part, {}) if isinstance(v, dict) else None
            return v if isinstance(v, (int, float)) else None
        return m.get(k)

    out = {}
    for shape, ks in keys.items():
        for proto in {m["proto"] for m in results}:
            for k in ks:
                name = k if isinstance(k, str) else ".".join(k[1:])
                vals = {}
                for server in servers:
                    vals[server] = [(m["round"], get(m, k)) for m in results
                                    if m["shape"] == shape and m["proto"] == proto and m["server"] == server
                                    and get(m, k) is not None]
                row = {s: statistics.median([v for _, v in vs]) if vs else None for s, vs in vals.items()}
                pairs = ([a / b for (ra, a) in vals[servers[0]] for (rb, b) in vals[servers[1]] if ra == rb and b]
                         if len(servers) >= 2 else [])
                if len(pairs) >= 2:
                    mean, sd = statistics.mean(pairs), statistics.stdev(pairs)
                    t = {2: 12.71, 3: 4.30, 4: 3.18, 5: 2.78, 6: 2.57}.get(len(pairs), 2.2)
                    half = t * sd / math.sqrt(len(pairs))
                    row["ratio"], row["ratio_ci95"] = round(mean, 4), [round(mean - half, 4), round(mean + half, 4)]
                elif pairs:
                    row["ratio"] = round(pairs[0], 4)
                out[f"{shape}/{proto}/{name}"] = row
    return out


def soak(r, a, out):
    """A mixed load for --soak hours: `conns` held, churn and a bulk
    transfer every 10 minutes; the server's RSS every minute, and its slope
    after the first hour."""
    proto, server = a.protocols[0], a.servers[0]
    r.start(server, proto)
    held = subprocess.Popen(["taskset", "-c", r.load_cores, "ip", "netns", "exec", NS_C, "sh", "-c",
                             f"ulimit -n {NOFILE}; exec {a.netgen} hold -targets {','.join(targets())} "
                             f"-proxies {','.join(r.proxies())} -conns {a.conns} -rate {a.rate} "
                             f"-hold {int(a.soak * 3600)}s -timeout 60s"],
                            stdout=open(f"{out}/soak-hold.json", "w"), stderr=subprocess.DEVNULL)
    churn = subprocess.Popen(["taskset", "-c", r.load_cores, "ip", "netns", "exec", NS_C, "sh", "-c",
                              f"exec {a.netgen} churn -target {TARGET_IP}:{TARGET_PORT} -proxy {r.proxies()[0]} "
                              f"-rate {a.churn_rate} -duration {int(a.soak * 3600)}s -timeout 60s"],
                             stdout=open(f"{out}/soak-churn.json", "w"), stderr=subprocess.DEVNULL)
    samples, start = [], time.time()
    with open(f"{out}/soak-rss.csv", "w") as f:
        while time.time() - start < a.soak * 3600:
            minute = (time.time() - start) / 60
            samples.append((minute, rss_kb(r.server.pid)))
            f.write(f"{minute:.1f},{samples[-1][1]}\n")
            f.flush()
            if int(minute) % 10 == 5:
                r.netgen("bulk", f"-proxy {r.proxies()[1]} -streams 4 -bytes {64 << 20} -dir down", check=False)
            time.sleep(max(0, 60 - (time.time() - start) % 60))
    stop(churn, held)
    r.stop()
    xs = [(m, kb / 1024) for m, kb in samples if m >= 60]
    if len(xs) >= 3:
        n = len(xs)
        mx, my = sum(x for x, _ in xs) / n, sum(y for _, y in xs) / n
        sxx = sum((x - mx) ** 2 for x, _ in xs)
        slope = sum((x - mx) * (y - my) for x, y in xs) / sxx
        resid = sum((y - my - slope * (x - mx)) ** 2 for x, y in xs) / (n - 2)
        se = math.sqrt(resid / sxx)
        res = {"server": server, "proto": proto, "hours": a.soak, "samples": n,
               "slope_mb_per_hour": round(slope * 60, 3),
               "slope_ci95_mb_per_hour": [round((slope - 1.96 * se) * 60, 3), round((slope + 1.96 * se) * 60, 3)]}
    else:
        res = {"error": "too few samples"}
    with open(f"{out}/soak.json", "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res))


def cpu_set(spec):
    """The CPUs of a taskset list, as "0-1", "2,3,6" or "2-3,6": a hostq
    lease's CPUs ($HOSTQ_CPUS) need not be contiguous."""
    cpus = set()
    for part in spec.split(","):
        first, _, last = part.partition("-")
        cpus.update(range(int(first), int(last or first) + 1))
    return cpus


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--sail", required=True)
    ap.add_argument("--sail-base", help="a second sail, the server sail-base, for new/base comparisons")
    ap.add_argument("--singbox", required=True)
    ap.add_argument("--netgen", required=True)
    ap.add_argument("--protocols", default=",".join(PROTOCOLS))
    ap.add_argument("--servers", default="sail,sing-box", help="of sail, sail-base, sing-box")
    ap.add_argument("--shapes", default="idle,churn,bulk")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--conns", type=int, default=10000)
    ap.add_argument("--rate", type=int, default=1000)
    ap.add_argument("--hold", type=int, default=60)
    ap.add_argument("--churn-rate", type=int, default=500)
    ap.add_argument("--churn-seconds", type=int, default=60)
    ap.add_argument("--bulk-mib", type=int, default=256)
    ap.add_argument("--processes", type=int, default=4)
    ap.add_argument("--carriers", type=int, default=25)
    ap.add_argument("--server-cores", default="0", help="e.g. 0 or 0-1")
    ap.add_argument("--load-cores", help="e.g. 4-11; default: every core but the server's")
    ap.add_argument("--name", default="p36", help="the namespaces are <name>c and <name>s")
    ap.add_argument("--net", type=int, default=98, help="the link is 10.<net>.0.0/24")
    ap.add_argument("--soak", type=float, default=0, help="hours of the mixed load instead of the rounds")
    ap.add_argument("--client", choices=["sing-box", "sail"], default="sing-box",
                    help="what the load's client processes are (default sing-box)")
    ap.add_argument("--sail-client", help="the sail binary of --client sail (default: --sail)")
    ap.add_argument("--client-profile", default="server",
                    help="the runtime profile of --client sail (default server)")
    a = ap.parse_args()
    a.protocols, a.servers = a.protocols.split(","), a.servers.split(",")
    a.sail_client = a.sail_client or a.sail
    if not set(a.servers) <= {"sail", "sail-base", "sing-box"}:
        sys.exit("--servers: of sail, sail-base, sing-box")
    if "sail-base" in a.servers and not a.sail_base:
        sys.exit("--servers sail-base needs --sail-base")
    if not set(a.protocols) <= set(PROTOCOLS) | SAIL_ONLY:
        sys.exit(f"--protocols: of {','.join(PROTOCOLS + sorted(SAIL_ONLY))}")
    sail_only = SAIL_ONLY & set(a.protocols)
    if sail_only and a.client != "sail":
        sys.exit(f"--protocols {','.join(sorted(sail_only))}: only sail speaks it; --client sail")
    if sail_only and "sing-box" in a.servers:
        sys.exit(f"--protocols {','.join(sorted(sail_only))}: only sail serves it; --servers of "
                 f"sail, sail-base")
    configure(a.name, a.net)
    ncpu = os.cpu_count()
    used = cpu_set(a.server_cores)
    load_cores = a.load_cores or ",".join(str(c) for c in range(ncpu) if c not in used)
    if not load_cores:
        sys.exit("--server-cores leaves no core for the load")
    out = f"{a.work}/results/{time.strftime('%Y%m%dT%H%M%S')}"
    os.makedirs(out)
    # The servers' certificate, made once, as netem's run.py makes its own.
    if not os.path.exists(f"{a.work}/cert.pem"):
        sh(f"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
           f"-subj /CN=localhost -addext subjectAltName=DNS:localhost -days 30 "
           f"-keyout {a.work}/key.pem -out {a.work}/cert.pem")
    keys = sh(f"{a.singbox} generate reality-keypair").stdout.split()
    keys = (keys[1], keys[3])
    up()
    target = hs = None
    try:
        target = [spawn(NS_C, load_cores, f"{a.netgen} serve -listen {t}", f"{out}/log-target-{i}.txt")
                  for i, t in enumerate(targets())]
        hs_cfg = write(f"{out}/handshake.json", {"log": {"level": "error"}, "inbounds": [
            {"type": "trojan", "listen": SERVER_IP, "listen_port": HS_PORT, "users": [{"password": "x"}],
             "tls": server_tls(a.work)}], "outbounds": [{"type": "direct"}]})
        hs = spawn(NS_S, load_cores, f"{a.singbox} run -c {hs_cfg}", f"{out}/log-handshake.txt")
        r = Run(a, out, keys, a.server_cores, load_cores)
        if a.soak:
            soak(r, a, out)
            return
        results = []
        for rnd in range(a.rounds):
            for i, proto in enumerate(a.protocols):
                order = a.servers if (rnd + i) % 2 == 0 else list(reversed(a.servers))
                for server in order:
                    r.start(server, proto)
                    try:
                        for m in shapes(r, server, proto, a):
                            m["round"] = rnd
                            results.append(m)
                            print(json.dumps(m), flush=True)
                    finally:
                        r.stop()
                    with open(f"{out}/results.json", "w") as f:
                        json.dump(results, f, indent=1)
        with open(f"{out}/summary.json", "w") as f:
            json.dump(summarize(results, a.servers), f, indent=1)
        print(f"results in {out}")
        # A cell where nothing connected measured nothing: a server that did
        # not start, or a client that cannot reach it. Not a result.
        empty = [f"{m['proto']}/{m['shape']}/{m['server']}" for m in results
                 if isinstance(m.get("netgen"), dict) and not m["netgen"].get("ok")]
        if empty:
            sys.exit(f"nothing connected in: {', '.join(empty)}")
    finally:
        stop(hs, *(target or []))
        down()


if __name__ == "__main__":
    main()
