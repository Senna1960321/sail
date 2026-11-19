// netgen drives checked traffic through a SOCKS5 proxy (or directly) to its
// own server, for the weak-network and long-run tests (roadmap 5.5). Every
// byte either side sends comes from a seeded generator, so the other side
// checks it: a corrupted, short or reordered transfer is counted, not
// missed.
//
//	netgen serve -listen 10.95.0.2:9000[,10.95.0.2:9001,...][,10.95.0.2:9100/bbr]
//	netgen bulk       -proxy P -target T -streams 8 -bytes 67108864 -dir down|up
//	netgen echo       -proxy P -target T -conns 16 -rounds 200 -size 4096
//	netgen setup      -proxy P -target T -n 500
//	netgen concurrent -proxy P -target T -conns 2000 -hold 20s
//	netgen hold       -proxies P1,P2 -targets T1,T2 -conns 100000 -rate 2000 -hold 60s
//	netgen churn      -proxy P -targets T1,T2 -rate 200 -duration 30s
//	netgen halfclose  -proxy P -target T -n 50 -bytes 1048576
//	netgen stall      -proxy P -target T -conns 20 -bytes 1073741824 -hold 3600s
//	netgen stallup    -proxy P -target T -conns 20 -bytes 1073741824 -hold 3600s
//	netgen probe      -proxy P -target T -duration 60s -interval 100ms
//
// Without -proxy it dials the target directly. -cc gives the connections a
// client mode dials a congestion control of their own, and a listen address
// ending in /NAME its accepted connections (Linux). Every client mode prints
// one JSON object on stdout.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	cmdDown       = 'D' // server sends A bytes of pattern(seed)
	cmdUp         = 'U' // client sends A bytes; server checks them, answers 1 (ok) or 0
	cmdEcho       = 'E' // server echoes until EOF
	cmdHalfClient = 'H' // client sends A bytes and shuts down its write side; server checks, then sends B bytes of pattern(seed+1) and closes
	cmdHalfServer = 'S' // server sends A bytes and shuts down its write side; client checks, then sends B bytes of pattern(seed+1) and shuts down; server checks and keeps the verdict
	cmdVerdict    = 'V' // server answers the verdict it kept for seed: 1 ok, 0 corrupt, 3 short (the data ended early), 2 none (yet)
	cmdSink       = 'K' // server reads nothing for A milliseconds, then closes: a target that stopped reading
	headerLen     = 25
)

// timeout bounds every single operation of a client mode.
var timeout = 10 * time.Second

// congestion, if set, is what the connections a client mode dials use.
var congestion string

// withCongestion sets `name` on a socket about to connect or listen; none
// if empty.
func withCongestion(name string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		if name == "" {
			return nil
		}
		return setCongestion(c, name)
	}
}

// ackTimeout bounds the wait for an upload's verdict once all of it is
// written: the buffers on the way may hold seconds of it on a slow link.
const ackTimeout = 120 * time.Second

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: netgen serve|bulk|echo|setup|concurrent|hold|stall|stallup|churn|halfclose|probe [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:9000", "serve: listen addresses, comma-separated, one handler")
	proxy := fs.String("proxy", "", "SOCKS5 proxy; empty dials the target directly")
	proxies := fs.String("proxies", "", "hold: SOCKS5 proxies, comma-separated, taken in turn; overrides -proxy")
	targets := fs.String("targets", "", "hold/churn: servers, comma-separated, taken in turn; overrides -target")
	target := fs.String("target", "127.0.0.1:9000", "server address, as the proxy sees it")
	streams := fs.Int("streams", 8, "bulk: parallel streams")
	size := fs.Int64("bytes", 64<<20, "bulk/halfclose/stall/stallup: bytes per stream")
	dir := fs.String("dir", "down", "bulk: down|up")
	conns := fs.Int("conns", 16, "echo/concurrent/hold/stall/stallup: connections")
	rounds := fs.Int("rounds", 200, "echo: round trips per connection")
	msg := fs.Int("size", 4096, "echo: largest message")
	n := fs.Int("n", 500, "setup/halfclose: connections")
	hold := fs.Duration("hold", 20*time.Second, "concurrent/hold/stall/stallup: how long connections stay open")
	rate := fs.Int("rate", 200, "churn/hold: connections per second")
	duration := fs.Duration("duration", 30*time.Second, "churn/probe: how long")
	interval := fs.Duration("interval", 100*time.Millisecond, "probe: between attempts")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "per-operation timeout")
	fs.StringVar(&congestion, "cc", "", "client modes: the congestion control of the connections dialed (Linux); empty, the system's")
	fs.Parse(os.Args[2:])

	d := dialer{proxy: *proxy, target: *target}
	switch os.Args[1] {
	case "hold", "churn":
		// A ticker needs an interval of at least a nanosecond.
		if *rate <= 0 || time.Second/time.Duration(*rate) <= 0 {
			usage("-rate must be 1 to 1000000000 a second")
		}
	}
	switch os.Args[1] {
	case "hold", "concurrent", "echo", "stall", "stallup":
		if *conns <= 0 {
			usage("-conns must be at least 1")
		}
	}
	var res any
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(list("-listen", *listen))
	case "bulk":
		res = runBulk(d, *streams, *size, *dir)
	case "echo":
		res = runEcho(d, *conns, *rounds, *msg)
	case "setup":
		res = runSetup(d, *n)
	case "concurrent":
		res = runConcurrent(d, *conns, *hold)
	case "hold":
		// Connection i goes through proxy i mod P to target i mod T: one
		// source cannot reach one address and port more than its
		// ephemeral ports allow.
		ps, ts := []string{*proxy}, []string{*target}
		if *proxies != "" {
			ps = list("-proxies", *proxies)
		}
		if *targets != "" {
			ts = list("-targets", *targets)
		}
		dial := func(i int) dialer { return dialer{proxy: ps[i%len(ps)], target: ts[i%len(ts)]} }
		res = runHold(dial, *conns, *rate, *hold)
	case "stall":
		res = runStall(d, *conns, *size, *hold, false)
	case "stallup":
		res = runStall(d, *conns, *size, *hold, true)
	case "churn":
		// Connection i to target i mod T: short connections to one address
		// and port leave the side that closes first a TIME-WAIT each, and
		// at hundreds a second the kernel's search for a free source port
		// among them, not the proxy, becomes what is measured.
		ts := []string{*target}
		if *targets != "" {
			ts = list("-targets", *targets)
		}
		dial := func(i int) dialer { return dialer{proxy: *proxy, target: ts[i%len(ts)]} }
		res = runChurn(dial, *rate, *duration)
	case "halfclose":
		res = runHalfClose(d, *n, *size)
	case "probe":
		res = runProbe(d, *duration, *interval)
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(res)
}

// list splits a comma-separated flag, refusing an empty entry.
func list(flag, value string) []string {
	items := strings.Split(value, ",")
	for _, item := range items {
		if item == "" {
			usage(flag + " has an empty entry")
		}
	}
	return items
}

func usage(why string) {
	fmt.Fprintln(os.Stderr, "usage:", why)
	os.Exit(2)
}

// ---- the pattern ----

// pattern is an endless byte stream from a seed (xorshift64*), which the
// receiving side regenerates to check what it got.
type pattern struct{ s uint64 }

func newPattern(seed uint64) *pattern { return &pattern{s: seed | 1} }

func (p *pattern) fill(b []byte) {
	for i := 0; i < len(b); i += 8 {
		p.s ^= p.s >> 12
		p.s ^= p.s << 25
		p.s ^= p.s >> 27
		var w [8]byte
		binary.LittleEndian.PutUint64(w[:], p.s*2685821657736338717)
		copy(b[i:], w[:])
	}
}

var errCorrupt = errors.New("corrupt data")

// send writes n bytes of pattern(seed).
func send(c net.Conn, seed uint64, n int64) error {
	p := newPattern(seed)
	buf := make([]byte, 64<<10)
	for n > 0 {
		k := int64(len(buf))
		if n < k {
			k = n
		}
		p.fill(buf[:k])
		if _, err := c.Write(buf[:k]); err != nil {
			return err
		}
		n -= k
	}
	return nil
}

// expect reads n bytes and checks them against pattern(seed).
func expect(c net.Conn, seed uint64, n int64) error {
	p := newPattern(seed)
	buf := make([]byte, 64<<10)
	want := make([]byte, 64<<10)
	for n > 0 {
		k := int64(len(buf))
		if n < k {
			k = n
		}
		if _, err := io.ReadFull(c, buf[:k]); err != nil {
			return err
		}
		p.fill(want[:k])
		for i := int64(0); i < k; i++ {
			if buf[i] != want[i] {
				return errCorrupt
			}
		}
		n -= k
	}
	return nil
}

func header(cmd byte, a, b, seed uint64) []byte {
	h := make([]byte, headerLen)
	h[0] = cmd
	binary.BigEndian.PutUint64(h[1:], a)
	binary.BigEndian.PutUint64(h[9:], b)
	binary.BigEndian.PutUint64(h[17:], seed)
	return h
}

func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("no half-close on this connection")
}

// ---- server ----

func serve(addrs []string) error {
	errs := make(chan error, len(addrs))
	for _, addr := range addrs {
		addr, cc, _ := strings.Cut(addr, "/")
		lc := net.ListenConfig{Control: withCongestion(cc)}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return err
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					errs <- err
					return
				}
				go handle(c)
			}
		}()
	}
	return <-errs
}

func handle(c net.Conn) {
	defer c.Close()
	var h [headerLen]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return
	}
	a := int64(binary.BigEndian.Uint64(h[1:]))
	b := int64(binary.BigEndian.Uint64(h[9:]))
	seed := binary.BigEndian.Uint64(h[17:])
	switch h[0] {
	case cmdDown:
		send(c, seed, a)
	case cmdUp:
		c.Write([]byte{verdict(expect(c, seed, a))})
	case cmdEcho:
		io.Copy(c, c)
	case cmdHalfClient:
		err := expect(c, seed, a)
		if err == nil {
			// The client's write side is shut: nothing more comes.
			var extra [1]byte
			if n, _ := c.Read(extra[:]); n != 0 {
				err = errCorrupt
			}
		}
		if err == nil {
			send(c, seed+1, b)
		}
	case cmdHalfServer:
		if send(c, seed, a) != nil || closeWrite(c) != nil {
			return
		}
		// Its write side is shut: the verdict is asked for on another
		// connection.
		verdicts.Store(seed, verdict(expect(c, seed+1, b)))
	case cmdVerdict:
		v, found := verdicts.LoadAndDelete(seed)
		if !found {
			c.Write([]byte{2})
			return
		}
		c.Write([]byte{v.(byte)})
	case cmdSink:
		time.Sleep(time.Duration(a) * time.Millisecond)
	}
}

// verdicts holds what the server found of half-closed connections' data, by
// seed, until asked.
var verdicts sync.Map

// verdict tells a corrupted transfer from one that ended early.
func verdict(err error) byte {
	switch {
	case err == nil:
		return 1
	case errors.Is(err, errCorrupt):
		return 0
	default:
		return 3
	}
}

// ---- client ----

type dialer struct{ proxy, target string }

func (d dialer) dial() (net.Conn, error) {
	nd := net.Dialer{Timeout: timeout, Control: withCongestion(congestion)}
	if d.proxy == "" {
		return nd.Dial("tcp", d.target)
	}
	host, portStr, err := net.SplitHostPort(d.target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, errors.New("target must be an IPv4 address")
	}
	c, err := nd.Dial("tcp", d.proxy)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(timeout))
	req := []byte{5, 1, 0, 5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	var resp [12]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks handshake: %w", err)
	}
	if resp[1] != 0 || resp[3] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks rejected: method=%d rep=%d", resp[1], resp[3])
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// counts gathers the outcomes of a mode's operations.
type counts struct {
	OK      int64 `json:"ok"`
	Failed  int64 `json:"failed"`
	Corrupt int64 `json:"corrupt"`
	// A few of the errors, for the report.
	Errors []string `json:"errors,omitempty"`
	mu     sync.Mutex
}

func (c *counts) add(err error) {
	switch {
	case err == nil:
		atomic.AddInt64(&c.OK, 1)
		return
	case errors.Is(err, errCorrupt):
		atomic.AddInt64(&c.Corrupt, 1)
	default:
		atomic.AddInt64(&c.Failed, 1)
	}
	c.mu.Lock()
	if len(c.Errors) < 5 {
		c.Errors = append(c.Errors, err.Error())
	}
	c.mu.Unlock()
}

func deadline(c net.Conn, d time.Duration) { c.SetDeadline(time.Now().Add(d)) }

// ---- modes ----

type bulkResult struct {
	counts
	Streams int     `json:"streams"`
	Bytes   int64   `json:"bytes"`
	Seconds float64 `json:"seconds"`
	Mbps    float64 `json:"mbps"`
	// Each stream's own rate, from its start to its end, in the order the
	// streams were started (null for one that failed): streams of one
	// multiplexed session share a TCP connection's window, separate
	// connections each have one.
	StreamMbps []*float64 `json:"stream_mbps"`
}

func runBulk(d dialer, streams int, size int64, dir string) any {
	r := &bulkResult{Streams: streams, StreamMbps: make([]*float64, streams)}
	var moved atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seed := uint64(time.Now().UnixNano()) + uint64(i)
			began := time.Now()
			c, err := d.dial()
			if err != nil {
				r.add(err)
				return
			}
			defer c.Close()
			// A stream may take long on a slow link; an idle one fails.
			idle := &idleConn{Conn: c}
			if dir == "up" {
				if _, err = c.Write(header(cmdUp, uint64(size), 0, seed)); err == nil {
					if err = send(idle, seed, size); err == nil {
						// What was sent may still sit in buffers on the
						// way, draining at the link's pace: the verdict
						// waits for it, with no progress to see.
						deadline(c, ackTimeout)
						var ack [1]byte
						if _, err = io.ReadFull(c, ack[:]); err == nil {
							switch ack[0] {
							case 1:
							case 0:
								err = errCorrupt
							default:
								err = errors.New("the server's read ended early")
							}
						}
					}
				}
			} else if _, err = c.Write(header(cmdDown, uint64(size), 0, seed)); err == nil {
				err = expect(idle, seed, size)
			}
			if err == nil {
				moved.Add(size)
				mbps := float64(size) * 8 / time.Since(began).Seconds() / 1e6
				r.StreamMbps[i] = &mbps
			}
			r.add(err)
		}(i)
	}
	wg.Wait()
	r.Seconds = time.Since(start).Seconds()
	r.Bytes = moved.Load()
	r.Mbps = float64(r.Bytes) * 8 / r.Seconds / 1e6
	return r
}

// idleConn fails a read or write that makes no progress for `timeout`.
type idleConn struct{ net.Conn }

func (c *idleConn) Read(b []byte) (int, error) {
	deadline(c.Conn, timeout)
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	deadline(c.Conn, timeout)
	return c.Conn.Write(b)
}

type latencies struct {
	P50ms  float64 `json:"p50_ms"`
	P90ms  float64 `json:"p90_ms"`
	P99ms  float64 `json:"p99_ms"`
	P999ms float64 `json:"p999_ms"`
	MaxMs  float64 `json:"max_ms"`
}

func summarize(ds []time.Duration) latencies {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	at := func(p float64) float64 {
		if len(ds) == 0 {
			return 0
		}
		i := int(p*float64(len(ds)+1)) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(ds) {
			i = len(ds) - 1
		}
		return float64(ds[i].Microseconds()) / 1000
	}
	return latencies{at(0.50), at(0.90), at(0.99), at(0.999), at(1)}
}

type echoResult struct {
	counts
	Rounds int64     `json:"rounds"`
	RTT    latencies `json:"rtt"`
}

// runEcho keeps `conns` connections, each doing `rounds` round trips of a
// random size up to `size`, each checked.
func runEcho(d dialer, conns, rounds, size int) any {
	r := &echoResult{}
	var mu sync.Mutex
	var rtts []time.Duration
	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(i) + time.Now().UnixNano()))
			c, err := d.dial()
			if err != nil {
				r.add(err)
				return
			}
			defer c.Close()
			if _, err := c.Write(header(cmdEcho, 0, 0, 0)); err != nil {
				r.add(err)
				return
			}
			buf := make([]byte, size)
			got := make([]byte, size)
			var mine []time.Duration
			for k := 0; k < rounds; k++ {
				n := 1 + rng.Intn(size)
				newPattern(rng.Uint64()).fill(buf[:n])
				deadline(c, timeout)
				t0 := time.Now()
				_, err := c.Write(buf[:n])
				if err == nil {
					_, err = io.ReadFull(c, got[:n])
				}
				if err == nil && string(got[:n]) != string(buf[:n]) {
					err = errCorrupt
				}
				r.add(err)
				if err != nil {
					break
				}
				mine = append(mine, time.Since(t0))
				atomic.AddInt64(&r.Rounds, 1)
			}
			mu.Lock()
			rtts = append(rtts, mine...)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	r.RTT = summarize(rtts)
	return r
}

type setupResult struct {
	counts
	Setup setupLatencies `json:"setup"`
}

// setupLatencies are the percentiles of all the connections, and the first
// one's own: a pooled or multiplexed protocol's first connection carries
// the session's TCP and TLS handshakes, which the rest reuse, and in the
// percentiles of 150 it is only the maximum.
type setupLatencies struct {
	latencies
	// None (null) when the first connection failed.
	FirstMs *float64 `json:"first_ms"`
}

// runSetup opens connections one after another: the time from dialing to
// the first echoed byte.
func runSetup(d dialer, n int) any {
	r := &setupResult{}
	var setups []time.Duration
	for i := 0; i < n; i++ {
		t0 := time.Now()
		err := echoOnce(d, 64)
		r.add(err)
		if err == nil {
			took := time.Since(t0)
			setups = append(setups, took)
			if i == 0 {
				ms := float64(took.Microseconds()) / 1000
				r.Setup.FirstMs = &ms
			}
		}
	}
	r.Setup.latencies = summarize(setups)
	return r
}

// echoOnce opens a connection, round-trips `size` checked bytes, closes.
func echoOnce(d dialer, size int) error {
	c, err := d.dial()
	if err != nil {
		return err
	}
	defer c.Close()
	deadline(c, timeout)
	msg := make([]byte, size)
	newPattern(uint64(time.Now().UnixNano())).fill(msg)
	if _, err := c.Write(append(header(cmdEcho, 0, 0, 0), msg...)); err != nil {
		return err
	}
	got := make([]byte, size)
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != string(msg) {
		return errCorrupt
	}
	return nil
}

type concurrentResult struct {
	counts
	Conns       int     `json:"conns"`
	Established int     `json:"established"`
	OpenSeconds float64 `json:"open_seconds"`
	// Those still working after the hold: each round-trips again.
	Survived int `json:"survived"`
}

// runConcurrent opens `conns` echo connections, keeps them open for `hold`
// (the harness samples memory meanwhile), then checks each still works.
func runConcurrent(d dialer, conns int, hold time.Duration) any {
	r := &concurrentResult{Conns: conns}
	var mu sync.Mutex
	open := make([]net.Conn, 0, conns)
	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < conns; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := d.dial()
			if err == nil {
				err = roundTrip(c, append(header(cmdEcho, 0, 0, 0), 'x'), 1)
			}
			r.add(err)
			if err != nil {
				if c != nil {
					c.Close()
				}
				return
			}
			mu.Lock()
			open = append(open, c)
			mu.Unlock()
		}()
	}
	wg.Wait()
	r.OpenSeconds = time.Since(start).Seconds()
	r.Established = len(open)
	fmt.Fprintf(os.Stderr, "HOLDING %d\n", len(open))
	time.Sleep(hold)
	var survived atomic.Int32
	for _, c := range open {
		wg.Add(1)
		sem <- struct{}{}
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { <-sem }()
			if roundTrip(c, []byte{'y'}, 1) == nil {
				survived.Add(1)
			}
			c.Close()
		}(c)
	}
	wg.Wait()
	r.Survived = int(survived.Load())
	return r
}

type holdResult struct {
	counts
	Conns       int `json:"conns"`
	Rate        int `json:"rate"`
	Established int `json:"established"`
	// Until the last dial started: conns over it is the rate offered,
	// lower than -rate when the dials fell behind the ticker.
	OfferedSeconds float64 `json:"offered_seconds"`
	// Until the slowest dial finished.
	OpenSeconds float64 `json:"open_seconds"`
	// From dialing to the first checked echo, for those established. With
	// fewer than about 1000 samples, p999 is the maximum.
	Setup        latencies `json:"setup"`
	SetupSamples int       `json:"setup_samples"`
	// Those still echoing checked bytes after the hold.
	Survived int `json:"survived"`
}

// runHold opens `conns` echo connections at `rate` a second, connection i
// through dial(i), each checked by a seeded echo; keeps those established
// open for `hold` (the harness samples meanwhile; "HOLDING n" on stderr
// marks the start), then checks each again with seeded bytes.
func runHold(dial func(int) dialer, conns, rate int, hold time.Duration) any {
	r := &holdResult{Conns: conns, Rate: rate}
	var mu sync.Mutex
	open := make([]net.Conn, 0, conns)
	setups := make([]time.Duration, 0, conns)
	var wg sync.WaitGroup
	tick := time.NewTicker(time.Second / time.Duration(rate))
	start := time.Now()
	for i := 0; i < conns; i++ {
		<-tick.C
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			t0 := time.Now()
			c, err := dial(i).dial()
			if err == nil {
				msg := make([]byte, 64)
				newPattern(uint64(i)).fill(msg)
				err = roundTrip(c, append(header(cmdEcho, 0, 0, 0), msg...), len(msg))
			}
			r.add(err)
			if err != nil {
				if c != nil {
					c.Close()
				}
				return
			}
			took := time.Since(t0)
			mu.Lock()
			open = append(open, c)
			setups = append(setups, took)
			mu.Unlock()
		}(i)
	}
	r.OfferedSeconds = time.Since(start).Seconds()
	tick.Stop()
	wg.Wait()
	r.OpenSeconds = time.Since(start).Seconds()
	r.Established = len(open)
	r.SetupSamples = len(setups)
	r.Setup = summarize(setups)
	fmt.Fprintf(os.Stderr, "HOLDING %d\n", len(open))
	time.Sleep(hold)
	var survived atomic.Int32
	sem := make(chan struct{}, 200)
	for i, c := range open {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c net.Conn) {
			defer wg.Done()
			defer func() { <-sem }()
			msg := make([]byte, 16)
			newPattern(uint64(i) << 32).fill(msg)
			if roundTrip(c, msg, len(msg)) == nil {
				survived.Add(1)
			}
			c.Close()
		}(i, c)
	}
	wg.Wait()
	r.Survived = int(survived.Load())
	return r
}

func roundTrip(c net.Conn, send []byte, want int) error {
	deadline(c, timeout)
	if _, err := c.Write(send); err != nil {
		return err
	}
	got := make([]byte, want)
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != string(send[len(send)-want:]) {
		return errCorrupt
	}
	return nil
}

type churnResult struct {
	counts
	Rate    int       `json:"rate"`
	Seconds float64   `json:"seconds"`
	Setup   latencies `json:"setup"`
}

// runChurn opens short connections at `rate` a second for `duration`,
// connection i through dial(i).
func runChurn(dial func(int) dialer, rate int, duration time.Duration) any {
	r := &churnResult{Rate: rate}
	var mu sync.Mutex
	var setups []time.Duration
	var wg sync.WaitGroup
	tick := time.NewTicker(time.Second / time.Duration(rate))
	defer tick.Stop()
	start := time.Now()
	for i := 0; time.Since(start) < duration; i++ {
		<-tick.C
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			t0 := time.Now()
			err := echoOnce(dial(i), 64)
			r.add(err)
			if err == nil {
				mu.Lock()
				setups = append(setups, time.Since(t0))
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	r.Seconds = time.Since(start).Seconds()
	r.Setup = summarize(setups)
	return r
}

type halfCloseResult struct {
	ClientFirst *counts `json:"client_first"`
	ServerFirst *counts `json:"server_first"`
}

// runHalfClose checks both directions of a half-closed connection `n`
// times each: the side that has shut down its write side still receives
// everything, and the other side sees its EOF.
func runHalfClose(d dialer, n int, size int64) any {
	r := halfCloseResult{&counts{}, &counts{}}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i := 0; i < n; i++ {
		wg.Add(2)
		seed := uint64(time.Now().UnixNano()) + uint64(i)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r.ClientFirst.add(clientFirst(d, seed, size))
		}()
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r.ServerFirst.add(serverFirst(d, seed, size))
		}()
	}
	wg.Wait()
	return r
}

func clientFirst(d dialer, seed uint64, size int64) error {
	c, err := d.dial()
	if err != nil {
		return err
	}
	defer c.Close()
	ic := &idleConn{Conn: c}
	if _, err := c.Write(header(cmdHalfClient, uint64(size), uint64(size), seed)); err != nil {
		return err
	}
	if err := send(ic, seed, size); err != nil {
		return err
	}
	if err := closeWrite(c); err != nil {
		return err
	}
	if err := expect(ic, seed+1, size); err != nil {
		return err
	}
	var extra [1]byte
	if n, err := ic.Read(extra[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("no EOF after the reply: %v", err)
	}
	return nil
}

func serverFirst(d dialer, seed uint64, size int64) error {
	c, err := d.dial()
	if err != nil {
		return err
	}
	defer c.Close()
	ic := &idleConn{Conn: c}
	if _, err := c.Write(header(cmdHalfServer, uint64(size), uint64(size), seed)); err != nil {
		return err
	}
	if err := expect(ic, seed, size); err != nil {
		return fmt.Errorf("reading the server's data: %w", err)
	}
	var extra [1]byte
	if n, err := ic.Read(extra[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("no EOF from the server: %v", err)
	}
	if err := send(ic, seed+1, size); err != nil {
		return fmt.Errorf("sending after the server's EOF: %w", err)
	}
	if err := closeWrite(c); err != nil {
		return err
	}
	// The server has shut its side: when it has read everything is only
	// known by asking, until it knows.
	give := time.Now().Add(timeout)
	for {
		err := askVerdict(d, seed)
		if !errors.Is(err, errNoVerdict) || time.Now().After(give) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

var errNoVerdict = errors.New("the server has no verdict")

// askVerdict asks, on a new connection, what the server found of the data
// of the half-closed connection `seed`.
func askVerdict(d dialer, seed uint64) error {
	c, err := d.dial()
	if err != nil {
		return fmt.Errorf("asking the verdict: %w", err)
	}
	defer c.Close()
	deadline(c, timeout)
	if _, err := c.Write(header(cmdVerdict, 0, 0, seed)); err != nil {
		return fmt.Errorf("asking the verdict: %w", err)
	}
	var v [1]byte
	if _, err := io.ReadFull(c, v[:]); err != nil {
		return fmt.Errorf("asking the verdict: %w", err)
	}
	switch v[0] {
	case 1:
		return nil
	case 0:
		return errCorrupt
	case 3:
		return errors.New("the server's read of the reply ended early")
	default:
		return errNoVerdict
	}
}

// event is a change seen by a probe: a new connection's attempts starting
// to fail or to succeed again, or the long-lived connection ending.
type event struct {
	AtMs int64  `json:"at_ms"` // since the Unix epoch
	What string `json:"what"`  // "new_ok", "new_fail", "long_fail", "long_reopened"
	Err  string `json:"err,omitempty"`
}

type probeResult struct {
	New    counts  `json:"new"`
	Events []event `json:"events"`
	// Every new connection, when it started and ended: the outcome
	// changes in Events follow completion order, so one that started before
	// a cut and failed slowly can follow a later one that worked.
	Conns []probeConn `json:"conns"`
}

type probeConn struct {
	StartMs int64 `json:"start_ms"`
	EndMs   int64 `json:"end_ms"`
	Ok      bool  `json:"ok"`
}

// runProbe tries a new connection every `interval` and keeps one
// long-lived connection round-tripping at the same pace, and records the
// moments their outcome changes: the harness sets these against when it
// cut and restored the link.
func runProbe(d dialer, duration, interval time.Duration) any {
	r := &probeResult{}
	var mu sync.Mutex
	record := func(what string, err error) {
		e := event{AtMs: time.Now().UnixMilli(), What: what}
		if err != nil {
			e.Err = err.Error()
		}
		mu.Lock()
		r.Events = append(r.Events, e)
		mu.Unlock()
	}
	stop := time.Now().Add(duration)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var c net.Conn
		for time.Now().Before(stop) {
			if c == nil {
				if nc, err := d.dial(); err == nil {
					if _, err = nc.Write(header(cmdEcho, 0, 0, 0)); err == nil {
						c = nc
						record("long_reopened", nil)
					} else {
						nc.Close()
					}
				}
			} else if err := roundTrip(c, []byte{'p'}, 1); err != nil {
				record("long_fail", err)
				c.Close()
				c = nil
			}
			time.Sleep(interval)
		}
		if c != nil {
			c.Close()
		}
	}()
	ok := true
	for time.Now().Before(stop) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now().UnixMilli()
			err := echoOnce(d, 16)
			r.New.add(err)
			mu.Lock()
			r.Conns = append(r.Conns, probeConn{StartMs: start, EndMs: time.Now().UnixMilli(), Ok: err == nil})
			changed := (err == nil) != ok
			ok = err == nil
			mu.Unlock()
			if changed {
				if err == nil {
					record("new_ok", nil)
				} else {
					record("new_fail", err)
				}
			}
		}()
		time.Sleep(interval)
	}
	wg.Wait()
	sort.Slice(r.Events, func(i, j int) bool { return r.Events[i].AtMs < r.Events[j].AtMs })
	return r
}

type stallResult struct {
	counts
	Conns       int `json:"conns"`
	Established int `json:"established"`
	// Of those established, the ones the proxy had ended (closed or reset)
	// by the time the hold ended or netgen was told to stop, before netgen
	// closed any; and the TCP states they were in. A stalled stream's
	// unread data stays ahead of a FIN, so the state (TCP_INFO), not a
	// read, tells.
	Ended  int            `json:"ended"`
	States map[string]int `json:"states"`
}

// runStall opens `conns` downloads of `size` bytes each and reads none of
// them for `hold`: clients that stopped reading, whose data fills every
// buffer on the way. With `up`, uploads of `size` bytes each to a target
// that reads none of them: the same through the server. "STALLING n" on
// stderr once they are all asked. SIGTERM or SIGINT ends the hold early,
// and the result is still printed: the harness stops it when the workload
// beside it is done.
func runStall(d dialer, conns int, size int64, hold time.Duration, up bool) any {
	// Before the first dial: a stop that comes once STALLING is out must
	// find the handler in place.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	r := &stallResult{Conns: conns, States: map[string]int{}}
	var mu sync.Mutex
	open := make([]net.Conn, 0, conns)
	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := d.dial()
			if err == nil {
				c.SetWriteDeadline(time.Now().Add(timeout))
				if up {
					_, err = c.Write(header(cmdSink, uint64(hold.Milliseconds()), 0, uint64(i)))
				} else {
					_, err = c.Write(header(cmdDown, uint64(size), 0, uint64(i)))
				}
			}
			if err == nil && up {
				// Written until every buffer on the way is full; the
				// error at the deadline is the point.
				go func() {
					c.SetWriteDeadline(time.Now().Add(hold))
					send(c, uint64(i), size)
				}()
			}
			r.add(err)
			if err != nil {
				if c != nil {
					c.Close()
				}
				return
			}
			mu.Lock()
			open = append(open, c)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	r.Established = len(open)
	fmt.Fprintf(os.Stderr, "STALLING %d\n", len(open))
	select {
	case <-time.After(hold):
	case <-stop:
	}
	// Each one's state before any is closed: none of netgen's own closes
	// is counted as the proxy's.
	for _, c := range open {
		state, err := tcpState(c)
		if err != nil {
			state = "unknown"
		}
		r.States[state]++
		if state != "ESTABLISHED" && state != "unknown" {
			r.Ended++
		}
	}
	for _, c := range open {
		c.Close()
	}
	return r
}
