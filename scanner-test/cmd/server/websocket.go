package main

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"net/http"
	"time"
)

// Each viewer has one pending notification; slow viewers receive the latest state
// without blocking TCP ingestion or accumulating an unbounded queue.
func (s *Store) notifyLocked() {
	for ch := range s.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
func (s *Store) snapshot() []byte {
	s.Lock()
	defer s.Unlock()
	b, _ := json.Marshal(s.state)
	return b
}

var upgrader = websocket.Upgrader{HandshakeTimeout: 5 * time.Second}

func (s *Store) serveWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	changed := make(chan struct{}, 1)
	s.Lock()
	if s.subscribers == nil {
		s.subscribers = make(map[chan struct{}]struct{})
	}
	s.subscribers[changed] = struct{}{}
	s.Unlock()
	defer func() { s.Lock(); delete(s.subscribers, changed); s.Unlock() }()
	done := make(chan struct{})
	c.SetReadLimit(1024)
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.SetPongHandler(func(string) error { return c.SetReadDeadline(time.Now().Add(60 * time.Second)) })
	go func() {
		defer close(done)
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}()
	send := func() error {
		b := s.snapshot()
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return c.WriteMessage(websocket.TextMessage, b)
	}
	if send() != nil {
		return
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-done:
			return
		case <-r.Context().Done():
			return
		case <-changed:
			if send() != nil {
				return
			}
		case <-ping.C:
			if c.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)) != nil {
				return
			}
		}
	}
}
