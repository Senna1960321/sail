// yamux-peer speaks hashicorp/yamux, with its default configuration, to
// muxcore's yamux in the interop tests (transport::mux::yamux_interop).
//
//	yamux-peer serve
//	yamux-peer dial -addr A -streams 500 -size 65536
//
// serve listens on a loopback port, which it prints as "listening PORT",
// and echoes every stream of every session until the stream's end, then
// finishes it. dial opens -streams streams at once on one session to A,
// sends -size bytes on each, finishes it, reads the bytes back and
// prints one JSON object: how many streams came back whole, and the first
// error.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/hashicorp/yamux"
)

func config() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	return c
}

func serve() error {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	fmt.Printf("listening %d\n", l.Addr().(*net.TCPAddr).Port)
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			session, err := yamux.Server(conn, config())
			if err != nil {
				conn.Close()
				return
			}
			for {
				stream, err := session.AcceptStream()
				if err != nil {
					return
				}
				go func() {
					io.Copy(stream, stream)
					stream.Close()
				}()
			}
		}()
	}
}

type result struct {
	Whole int    `json:"whole"`
	Error string `json:"error,omitempty"`
}

func dial(addr string, streams, size int) result {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return result{Error: err.Error()}
	}
	session, err := yamux.Client(conn, config())
	if err != nil {
		return result{Error: err.Error()}
	}
	defer session.Close()
	var mu sync.Mutex
	var res result
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := func() error {
				stream, err := session.OpenStream()
				if err != nil {
					return err
				}
				defer stream.Close()
				data := bytes.Repeat([]byte{byte(i)}, size)
				go func() {
					stream.Write(data)
					stream.Close()
				}()
				back, err := io.ReadAll(stream)
				if err != nil {
					return err
				}
				if !bytes.Equal(back, data) {
					return fmt.Errorf("stream %d: %d bytes back of %d", i, len(back), size)
				}
				return nil
			}()
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				res.Whole++
			} else if res.Error == "" {
				res.Error = err.Error()
			}
		}(i)
	}
	wg.Wait()
	return res
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: yamux-peer serve | dial -addr A -streams N -size S")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "dial":
		fs := flag.NewFlagSet("dial", flag.ExitOnError)
		addr := fs.String("addr", "", "")
		streams := fs.Int("streams", 500, "")
		size := fs.Int("size", 65536, "")
		fs.Parse(os.Args[2:])
		json.NewEncoder(os.Stdout).Encode(dial(*addr, *streams, *size))
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}
