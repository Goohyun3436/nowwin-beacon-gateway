package main

import (
	"beacon-scanner-test/parser"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebSocketInitialAndLiveUpdates(t *testing.T) {
	s := &Store{state: State{Beacons: map[string]Seen{}, Events: []Event{}}}
	srv := httptest.NewServer(http.HandlerFunc(s.serveWS))
	defer srv.Close()
	var clients []*websocket.Conn
	for i := 0; i < 2; i++ {
		c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		clients = append(clients, c)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var initial State
		if err := c.ReadJSON(&initial); err != nil {
			t.Fatal(err)
		}
		if initial.Packets != 0 {
			t.Fatal(initial)
		}
	}
	s.add(Event{Kind: "packet", At: time.Now(), ScannerMAC: "test", Readings: []parser.Reading{{BeaconMAC: "00:C0:B1:C1:6B:AD", RSSI: -60}}})
	for _, c := range clients {
		var state State
		if err := c.ReadJSON(&state); err != nil {
			t.Fatal(err)
		}
		if state.Packets != 1 || state.LogSequence != 1 || len(state.Beacons) != 1 {
			t.Fatalf("missing push: %+v", state)
		}
	}
}
