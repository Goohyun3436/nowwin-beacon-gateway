package parser

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const MaxFrame = 1024 * 1024

// Packet separates stream framing from payload decoding and application policy.
type Packet struct {
	Format     string
	Raw        []byte
	ScannerMAC string
	Readings   []Reading
	Err        error
}

func Allowed(mac string) bool {
	return strings.HasPrefix(mac, "C3:00:00:") || strings.HasPrefix(mac, "00:C0:B1:")
}
func MAC(s string) (string, error) {
	s = strings.NewReplacer(":", "", "-", "").Replace(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 6 {
		return "", fmt.Errorf("invalid MAC %q", s)
	}
	return macBytesToString(b), nil
}
func ParseCSV(raw []byte) (string, []Reading, error) {
	s := strings.TrimSpace(string(raw))
	if strings.HasPrefix(s, "0x") && len(s) > 14 && strings.Trim(s[14:], "0") == "" {
		m, e := MAC(s[2:14])
		return m, nil, e
	}
	p := strings.Split(s, ",")
	if len(p) != 5 {
		return "", nil, fmt.Errorf("expected time,beacon,rssi,unused,scanner")
	}
	b, e := MAC(p[1])
	if e != nil {
		return "", nil, e
	}
	m, e := MAC(p[4])
	if e != nil {
		return "", nil, e
	}
	r, e := strconv.Atoi(strings.TrimSpace(p[2]))
	if e != nil || r < -128 || r > 127 {
		return "", nil, fmt.Errorf("invalid RSSI")
	}
	return m, []Reading{{BeaconMAC: b, RSSI: r}}, nil
}

// ReadStream uses lengths, never TCP Read boundaries. Capture receives even partial/invalid bytes.
func ReadStream(r io.Reader, mode string, capture func([]byte), emit func(Packet)) error {
	br := bufio.NewReader(io.TeeReader(r, writerFunc(func(b []byte) (int, error) { capture(append([]byte(nil), b...)); return len(b), nil })))
	for {
		first, e := br.Peek(1)
		if e != nil {
			return e
		}
		format := mode
		if format == "auto" {
			if first[0] == 0xBB {
				format = "binary-long"
			} else {
				format = "csv"
			}
		}
		p := Packet{Format: format}
		if format == "binary-long" {
			h := make([]byte, 6)
			n, e := io.ReadFull(br, h)
			if e != nil {
				emit(Packet{Format: format, Raw: h[:n], Err: e})
				return e
			}
			size := int(binary.BigEndian.Uint32(h[2:]))
			if h[0] != 0xBB || size < 15 || size > MaxFrame {
				p.Raw = h
				p.Err = fmt.Errorf("invalid frame header/length: %d; inspect raw capture", size)
				emit(p)
				return p.Err
			}
			p.Raw = make([]byte, size)
			copy(p.Raw, h)
			n, e = io.ReadFull(br, p.Raw[6:])
			if e != nil {
				p.Raw = p.Raw[:6+n]
				p.Err = e
				emit(p)
				return e
			}
			p.ScannerMAC, p.Readings, p.Err = ParseBinary(p.Raw)
		} else {
			var line []byte
			for {
				part, more, e := br.ReadLine()
				line = append(line, part...)
				if len(line) > MaxFrame {
					return fmt.Errorf("line exceeds limit")
				}
				if e != nil {
					if len(line) == 0 {
						return e
					}
					break
				}
				if !more {
					break
				}
			}
			p.Raw = line
			p.ScannerMAC, p.Readings, p.Err = ParseCSV(line)
		}
		emit(p)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
