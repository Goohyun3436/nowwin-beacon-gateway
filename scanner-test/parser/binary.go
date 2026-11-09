package parser

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseBinary follows the existing main.go layout; verify against real gateway captures.
type Reading struct {
	BeaconMAC     string
	RSSI          int
	Advertisement string `json:",omitempty"`
}

func ParseBinary(frame []byte) (string, []Reading, error) {
	if len(frame) < 15 || frame[0] != 0xBB || frame[len(frame)-1] != 0xDD {
		return "", nil, fmt.Errorf("invalid binary frame boundary")
	}
	if int(binary.BigEndian.Uint32(frame[2:6])) != len(frame) {
		return "", nil, fmt.Errorf("binary frame length mismatch")
	}

	if frame[1] != 0 && frame[1] != 1 {
		return "", nil, fmt.Errorf("unsupported binary protocol: %d", frame[1])
	}

	offset := 6
	hygateMAC := macBytesToString(frame[offset : offset+6])
	offset += 6
	beaconCount := int(binary.BigEndian.Uint16(frame[offset : offset+2]))
	offset += 2
	readings := make([]Reading, 0)

	for beaconIndex := 0; beaconIndex < beaconCount; beaconIndex++ {
		if offset+8 > len(frame)-1 {
			return "", nil, fmt.Errorf("truncated binary beacon entry")
		}
		beaconMAC := macBytesToString(frame[offset : offset+6])
		offset += 6
		rssiCount := int(binary.BigEndian.Uint16(frame[offset : offset+2]))
		offset += 2
		if frame[1] == 1 {
			// Version 1 carries advertisement samples instead of bare RSSI bytes.
			// Each sample is: advertisement length (u8), advertisement,
			// metadata (u8), RSSI (signed i8).
			if rssiCount < 1 {
				return "", nil, fmt.Errorf("invalid binary sample count: %d", rssiCount)
			}
			for sample := 0; sample < rssiCount; sample++ {
				if offset >= len(frame)-1 {
					return "", nil, fmt.Errorf("truncated advertisement length")
				}
				advertisementLength := int(frame[offset])
				offset++
				if offset+advertisementLength+2 > len(frame)-1 {
					return "", nil, fmt.Errorf("truncated advertisement sample")
				}
				advertisement := hex.EncodeToString(frame[offset : offset+advertisementLength])
				offset += advertisementLength
				readings = append(readings, Reading{
					BeaconMAC:     beaconMAC,
					RSSI:          int(int8(frame[offset+1])),
					Advertisement: advertisement,
				})
				offset += 2
			}
			continue
		}
		if rssiCount < 1 || offset+rssiCount > len(frame)-1 {
			return "", nil, fmt.Errorf("invalid binary RSSI count: %d", rssiCount)
		}
		for _, value := range frame[offset : offset+rssiCount] {
			readings = append(readings, Reading{
				BeaconMAC: beaconMAC,
				RSSI:      int(int8(value)),
			})
		}
		offset += rssiCount
	}

	if offset != len(frame)-1 {
		return "", nil, fmt.Errorf("unexpected binary frame payload length")
	}
	return hygateMAC, readings, nil
}

func macBytesToString(value []byte) string {
	parts := make([]string, len(value))
	for index, item := range value {
		parts[index] = fmt.Sprintf("%02X", item)
	}
	return strings.Join(parts, ":")
}
