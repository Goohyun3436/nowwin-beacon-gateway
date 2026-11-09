package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"testing"
)

func fixture(version byte) []byte {
	b := []byte{0xBB, version, 0, 0, 0, 0, 0xA0, 6, 0, 0, 0, 1, 0, 2}
	for _, mac := range []string{"C30000000001", "00C0B1C16BAD"} {
		m, _ := hex.DecodeString(mac)
		b = append(b, m...)
		b = append(b, 0, 1)
		if version == 1 {
			b = append(b, 3, 2, 1, 6, 0)
		}
		b = append(b, 0xC4)
	}
	b = append(b, 0xDD)
	binary.BigEndian.PutUint32(b[2:6], uint32(len(b)))
	return b
}

type fragmented struct{ r io.Reader }

func (f fragmented) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return f.r.Read(b)
}
func TestStreamFragmentedAndCoalesced(t *testing.T) {
	for _, v := range []byte{0, 1} {
		b := fixture(v)
		var captured []byte
		var packets []Packet
		err := ReadStream(fragmented{bytes.NewReader(append(append([]byte{}, b...), b...))}, "auto", func(b []byte) { captured = append(captured, b...) }, func(p Packet) { packets = append(packets, p) })
		if err != io.EOF || len(packets) != 2 || len(captured) != len(b)*2 {
			t.Fatalf("stream: %v %d %d", err, len(packets), len(captured))
		}
		for _, p := range packets {
			if p.Err != nil || p.ScannerMAC != "A0:06:00:00:00:01" || len(p.Readings) != 2 || p.Readings[1].RSSI != -60 {
				t.Fatalf("packet: %+v", p)
			}
			if v == 1 && p.Readings[0].Advertisement != "020106" {
				t.Fatal("advertisement lost")
			}
		}
	}
}
func TestMalformed(t *testing.T) {
	b := fixture(1)
	for n := 0; n < len(b); n++ {
		if _, _, e := ParseBinary(b[:n]); e == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	b[len(b)-1] = 0
	if _, _, e := ParseBinary(b); e == nil {
		t.Fatal("bad end accepted")
	}
	bad := []byte{0xBB, 0, 0x7f, 0xff, 0xff, 0xff}
	var packet Packet
	err := ReadStream(bytes.NewReader(bad), "auto", func([]byte) {}, func(p Packet) { packet = p })
	if err == nil || packet.Err == nil {
		t.Fatal("bad length accepted")
	}
}
func TestCSVAndFilter(t *testing.T) {
	m, r, e := ParseCSV([]byte("123,0x00c0b1c16bad,-72,0,a00600000001"))
	if e != nil || m != "A0:06:00:00:00:01" || r[0].RSSI != -72 {
		t.Fatalf("csv %v", e)
	}
	for _, m := range []string{"C3:00:00:01:02:03", "00:C0:B1:C1:6B:AD", "00:C0:B1:00:00:01"} {
		if !Allowed(m) {
			t.Fatal(m)
		}
	}
	if Allowed("AA:BB:CC:00:00:01") {
		t.Fatal("filter")
	}
	if _, _, e := ParseCSV([]byte("0,001122334455,garbage,0,a00600000001")); e == nil {
		t.Fatal("RSSI accepted")
	}
}
