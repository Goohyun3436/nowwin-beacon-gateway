package main

import (
	"beacon-scanner-test/parser"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"
)

//go:embed index.html
var assets embed.FS

type Event struct {
	At                                              time.Time
	Remote, Kind, Format, ScannerMAC, RawHex, Error string
	Readings                                        []parser.Reading
}
type Seen struct {
	Order                   int
	MAC, ScannerMAC, Remote string
	RSSI                    int
	Count                   int
	LastSeen                time.Time
}
type State struct {
	LogSequence                            uint64
	Events                                 []Event
	Beacons                                map[string]Seen
	Connections, Packets, Errors, Filtered int
	TCP, Mode                              string
}
type Store struct {
	sync.Mutex
	state       State
	subscribers map[chan struct{}]struct{}
}

func (s *Store) add(e Event) {
	s.Lock()
	defer s.Unlock()
	defer s.notifyLocked()
	if e.Kind == "packet" {
		s.state.LogSequence++
	}
	s.state.Events = append(s.state.Events, e)
	if len(s.state.Events) > 200 {
		s.state.Events = s.state.Events[1:]
	}
	if e.Kind != "packet" {
		return
	}
	s.state.Packets++
	if e.Error != "" {
		s.state.Errors++
		return
	}
	for _, r := range e.Readings {
		if !parser.Allowed(r.BeaconMAC) {
			s.state.Filtered++
			continue
		}
		key := e.ScannerMAC + "/" + r.BeaconMAC
		v, exists := s.state.Beacons[key]
		if !exists {
			v.Order = len(s.state.Beacons) + 1
		}
		v.MAC = r.BeaconMAC
		v.ScannerMAC = e.ScannerMAC
		v.Remote = e.Remote
		v.RSSI = r.RSSI
		v.Count++
		v.LastSeen = e.At
		s.state.Beacons[key] = v
	}
}
func main() {
	tcp := flag.String("tcp", ":7001", "TCP listen address")
	web := flag.String("web", ":8080", "dashboard listen address")
	mode := flag.String("format", "auto", "auto | binary-long | csv")
	flag.String("log", "", "deprecated: captures are memory-only; this flag is ignored")
	flag.Parse()
	if *mode != "auto" && *mode != "csv" && *mode != "binary-long" {
		log.Fatal("unsupported format")
	}
	s := &Store{state: State{Beacons: map[string]Seen{}, TCP: *tcp, Mode: *mode, Events: []Event{}}}
	ln, e := net.Listen("tcp", *tcp)
	if e != nil {
		log.Fatal(e)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				remote := c.RemoteAddr().String()
				s.Lock()
				s.state.Connections++
				s.Unlock()
				defer func() {
					s.Lock()
					s.state.Connections--
					s.Unlock()
					s.add(Event{At: time.Now(), Remote: remote, Kind: "disconnect"})
				}()
				s.add(Event{At: time.Now(), Remote: remote, Kind: "connect"})
				e := parser.ReadStream(c, *mode, func(b []byte) {
					s.add(Event{At: time.Now(), Remote: remote, Kind: "raw-chunk", RawHex: hex.EncodeToString(b)})
				}, func(p parser.Packet) {
					v := Event{At: time.Now(), Remote: remote, Kind: "packet", Format: p.Format, ScannerMAC: p.ScannerMAC, Readings: p.Readings, RawHex: hex.EncodeToString(p.Raw)}
					if p.Err != nil {
						v.Error = p.Err.Error()
					}
					s.add(v)
				})
				if e != nil && e != io.EOF {
					s.add(Event{At: time.Now(), Remote: remote, Kind: "connection-error", Error: e.Error()})
				}
			}()
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.serveWS)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		b, _ := assets.ReadFile("index.html")
		w.Write(b)
	})
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		s.Lock()
		defer s.Unlock()
		json.NewEncoder(w).Encode(s.state)
	})
	srv := &http.Server{Addr: *web, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { ch := make(chan os.Signal, 1); signal.Notify(ch, os.Interrupt); <-ch; ln.Close(); srv.Close() }()
	host, port, _ := net.SplitHostPort(*web)
	if host == "" {
		host = "localhost"
	}
	fmt.Printf("TCP %s (%s), dashboard http://%s (memory-only)\n", *tcp, *mode, net.JoinHostPort(host, port))
	if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
