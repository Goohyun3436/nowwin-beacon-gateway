package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	influxdb2api "github.com/influxdata/influxdb-client-go/v2/api"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

/* ===================== Config & Const ===================== */

const (
	TCP_PORT = ":7001"

	OWNER_EXPIRE_SEC            = 3 * time.Minute
	NEARBY_SCAN_WINDOW_SEC      = 2 * time.Second
	OWNER_CANDIDATE_WINDOW_SEC  = 3 * time.Second
	OWNER_SWITCH_CONFIRM_COUNT  = 3
	STOP_SAVE_THRESHOLD         = 1 * time.Minute
	STOP_THRESHOLD              = 3 * time.Minute
	EXIT_CONFIRM_WAIT           = 5 * time.Minute
	EXIT_CONFIRM_WAIT_ORDER_1   = 2 * time.Minute
	MISSING_KEEPALIVE_THRESHOLD = 1 * time.Hour
	MISSING_HEARTBIT_THRESHOLD  = 1 * time.Hour
	BATCH_FLUSH_COUNT           = 5
	BATCH_FLUSH_TIME            = 250 * time.Millisecond
	SUMMARY_INTERVAL            = 300 * time.Second
	MONITOR_INTERVAL            = 10 * time.Second

	DEFAULT_MAC_PREFIX = "00:C0:B1"
	BINARY_FRAME_START = 0xBB
	BINARY_FRAME_END   = 0xDD
	BINARY_FRAME_MIN   = 15
	BINARY_FRAME_MAX   = 1024 * 1024

	influxURL = "http://influxdb2:8086"
	token     = "2bq9r-S3qb3e-ter4-w2kid"
	org       = "location-monitor"
	bucket    = "location-monitor"
	bucketBcn = "location-monitor-beacon"

	mongoURL = "mongodb://admin:Admin123!@mongodb:27017"
)

/* ===================== Types ===================== */

type Direction int

const (
	DirectionStop Direction = iota
	DirectionUp
	DirectionDown
)

type Tunnel int

const (
	TunnelOutside Tunnel = iota
	TunnelInside
)

type BeaconData struct {
	HygateMAC string
	BeaconMAC string
	Name      string
	Number    string
	Type      string
	RSSI      int
	Timestamp time.Time
	RemoteIP  string
	Direction Direction
}

type OwnerInfo struct {
	HygateMAC         string
	RSSI              int
	Timestamp         time.Time
	Order             int
	Direction         Direction
	LastMoveTimestamp time.Time
}

type OwnerCandidate struct {
	HygateMAC string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

type LastFix struct {
	HygateMAC string
	RSSI      int
	RemoteIP  string
	Timestamp time.Time
}

type ExitCandidate struct {
	DetectedAt time.Time
	GateOrder  int
}

type PresentSession struct {
	ScannerMAC string
	EnteredAt  time.Time
	LastSeenAt time.Time
}

/* ===================== Events ===================== */

type Event interface{ isEvent() }

type EKeepalive struct {
	HygateMAC string
	At        time.Time
	RemoteIP  string
}

func (EKeepalive) isEvent() {}

type ETCPConnect struct {
	RemoteIP string
}

func (ETCPConnect) isEvent() {}

type EHeartbit struct {
	BeaconMAC, HygateMAC string
	RSSI                 int
	At                   time.Time
}

func (EHeartbit) isEvent() {}

type EBeacon struct {
	BeaconMAC, HygateMAC, RemoteIP string
	RSSI                           int
	At                             time.Time
	Direction                      Direction
}

func (EBeacon) isEvent() {}

type ETick struct{ Now time.Time } // monitor tick
func (ETick) isEvent()             {}

type ESummarize struct{ Now time.Time } // summary tick
func (ESummarize) isEvent()             {}

/* ===================== Engine (single owner of state) ===================== */

type Engine struct {
	// external
	mongo *mongo.Client

	influxClient       influxdb2.Client
	influxWriteBeacon  influxdb2api.WriteAPIBlocking
	influxWriteSummary influxdb2api.WriteAPIBlocking

	// input
	evCh chan Event

	// output workers
	influxQueue chan BeaconData

	// static dictionaries (loaded at boot)
	workerInfo   map[string]bson.M
	vehicleInfo  map[string]bson.M
	heartbitInfo map[string]bson.M
	scannerInfo  map[string]bson.M

	VALID_HYGATE_MACS map[string]bool
	VALID_BEACON_MACS map[string]bool
	UNREGISTERED_MACS map[string]bool

	scannerNumberMap     map[string]int
	orderToScannerMac    map[int]string
	ipToScannerMac       map[string]string
	beaconType           map[string]string // worker/vehicle
	scannerToHeartbitMAC map[string]string
	macPrefixes          []string
	hygateMACPatterns    []string
	heartbitMACPatterns  []string

	// dynamic state (ENGINE OWNS ALL)
	activeConnections map[string]bool // hygate mac -> TCP connection seen in this process
	lastSeenMap       map[string]time.Time
	lastGateSeenAt    map[string]ExitCandidate
	heartbitLastSeen  map[string]time.Time
	keepaliveLastSeen map[string]time.Time

	beaconOwnerMap          map[string]OwnerInfo
	beaconOwnerCandidateMap map[string]OwnerCandidate
	lastOwnerMap            map[string]string
	lastFixMap              map[string]LastFix
	lastStopPersistAt       map[string]time.Time

	beaconTunnelState     map[string]Tunnel
	beaconExitCandidateAt map[string]ExitCandidate
	activeBeaconSet       map[string]bool
	presentSessions       map[string]PresentSession

	exitGateScannerMode string
	exitDefaultDuration time.Duration
	exitGateDurations   map[int]time.Duration

	warnScannerList    map[string]bool
	warnHeartbitList   map[string]bool
	warnBeaconList     map[string]bool
	overstayBeaconList map[string]bool
	absenceBeaconList  map[string]bool

	prevWarnScannerState  map[string]bool
	prevWarnBeaconState   map[string]bool
	prevWarnHeartbitState map[string]bool
	prevOverstayState     map[string]bool
	workerEnteredAt       map[string]time.Time
	workerExitedAt        map[string]time.Time
	overstayEnabled       bool
	overstayDuration      time.Duration
	warnEnabled           bool
	warnDuration          time.Duration
	absenceEnabled        bool
	absenceDuration       time.Duration

	// buffers for summary
	hygateBuffers map[string][]BeaconData

	// timezone
	kstLoc *time.Location
}

func NewEngine(m *mongo.Client, iCli influxdb2.Client) *Engine {
	e := &Engine{
		mongo:              m,
		influxClient:       iCli,
		influxWriteBeacon:  iCli.WriteAPIBlocking(org, bucketBcn),
		influxWriteSummary: iCli.WriteAPIBlocking(org, bucket),
		evCh:               make(chan Event, 2048),
		influxQueue:        make(chan BeaconData, 1024),

		workerInfo:   map[string]bson.M{},
		vehicleInfo:  map[string]bson.M{},
		heartbitInfo: map[string]bson.M{},
		scannerInfo:  map[string]bson.M{},

		VALID_HYGATE_MACS: map[string]bool{},
		VALID_BEACON_MACS: map[string]bool{},
		UNREGISTERED_MACS: map[string]bool{},

		scannerNumberMap:     map[string]int{},
		orderToScannerMac:    map[int]string{},
		ipToScannerMac:       map[string]string{},
		beaconType:           map[string]string{},
		scannerToHeartbitMAC: map[string]string{},
		macPrefixes:          []string{DEFAULT_MAC_PREFIX},
		hygateMACPatterns:    []string{"A0:06", "A0:07"},
		heartbitMACPatterns:  []string{"C1:54", "C1:55"},

		activeConnections: map[string]bool{},
		lastSeenMap:       map[string]time.Time{},
		lastGateSeenAt:    map[string]ExitCandidate{},
		heartbitLastSeen:  map[string]time.Time{},
		keepaliveLastSeen: map[string]time.Time{},

		beaconOwnerMap:          map[string]OwnerInfo{},
		beaconOwnerCandidateMap: map[string]OwnerCandidate{},
		lastOwnerMap:            map[string]string{},
		lastFixMap:              map[string]LastFix{},
		lastStopPersistAt:       map[string]time.Time{},
		beaconTunnelState:       map[string]Tunnel{},
		beaconExitCandidateAt:   map[string]ExitCandidate{},
		activeBeaconSet:         map[string]bool{},
		presentSessions:         map[string]PresentSession{},
		exitGateScannerMode:     "selected",
		exitDefaultDuration:     EXIT_CONFIRM_WAIT,
		exitGateDurations: map[int]time.Duration{
			1: EXIT_CONFIRM_WAIT_ORDER_1,
			2: EXIT_CONFIRM_WAIT,
			3: EXIT_CONFIRM_WAIT,
		},

		warnScannerList:       map[string]bool{},
		warnHeartbitList:      map[string]bool{},
		warnBeaconList:        map[string]bool{},
		overstayBeaconList:    map[string]bool{},
		absenceBeaconList:     map[string]bool{},
		prevWarnScannerState:  map[string]bool{},
		prevWarnBeaconState:   map[string]bool{},
		prevWarnHeartbitState: map[string]bool{},
		prevOverstayState:     map[string]bool{},
		workerEnteredAt:       map[string]time.Time{},
		workerExitedAt:        map[string]time.Time{},
		warnEnabled:           true,
		warnDuration:          180 * time.Minute,
		absenceDuration:       30 * time.Minute,
		hygateBuffers:         map[string][]BeaconData{},
	}
	// KST
	if loc, err := time.LoadLocation("Asia/Seoul"); err == nil {
		e.kstLoc = loc
	} else {
		e.kstLoc = time.FixedZone("KST", 9*60*60)
	}
	return e
}

func (e *Engine) Run() {
	go e.influxWorker()
	for ev := range e.evCh {
		switch v := ev.(type) {
		case ETCPConnect:
			e.onTCPConnect(v)
		case EKeepalive:
			e.onKeepalive(v)
		case EHeartbit:
			e.onHeartbit(v)
		case EBeacon:
			e.onBeacon(v)
		case ETick:
			e.onMonitorTick(v.Now)
		case ESummarize:
			e.onSummaryTick(v.Now)
		}
	}
}

/* ===================== Event handlers ===================== */

func (e *Engine) onTCPConnect(ev ETCPConnect) {
	hmac, ok := e.ipToScannerMac[ev.RemoteIP]
	if !ok || hmac == "" {
		return
	}
	if !e.activeConnections[hmac] {
		e.activeConnections[hmac] = true
		e.logConnection("connect", hmac, ev.RemoteIP)
	}

	// TCP CONNECT 된 스캐너는 즉시 정상으로 간주
	delete(e.warnScannerList, hmac)
	_, _ = e.col("warnScanner").DeleteOne(context.Background(), bson.M{"mac": hmac})
}

func (e *Engine) onKeepalive(ev EKeepalive) {
	e.keepaliveLastSeen[ev.HygateMAC] = ev.At
	// 프로세스가 해당 스캐너를 처음 살아있다고 인식한 시점에만 1회 기록
	if !e.activeConnections[ev.HygateMAC] {
		e.activeConnections[ev.HygateMAC] = true
		e.logConnection("connect", ev.HygateMAC, ev.RemoteIP)
	}

	// CONNECT 된 스캐너는 즉시 정상으로 간주
	delete(e.warnScannerList, ev.HygateMAC)
	_, _ = e.col("warnScanner").DeleteOne(context.Background(), bson.M{"mac": ev.HygateMAC})
}

func (e *Engine) onHeartbit(ev EHeartbit) {
	// 스캐너가 자신의 측정태그를 읽었을 때만 유효
	if hb, ok := e.scannerToHeartbitMAC[ev.HygateMAC]; !ok || hb != ev.BeaconMAC {
		return
	}
	e.heartbitLastSeen[ev.HygateMAC] = ev.At
	e.keepaliveLastSeen[ev.HygateMAC] = ev.At // 하트비트가 되면 keepalive도 만족

	// warnHeartbit 해제 / warnScanner도 함께 해제
	delete(e.warnHeartbitList, ev.HygateMAC)
	delete(e.warnScannerList, ev.HygateMAC)
}

func (e *Engine) onBeacon(ev EBeacon) {
	// Heartbit는 EHeartbit로만 처리
	if e.isHeartbitMAC(ev.BeaconMAC) {
		return
	}

	// 미등록 체크
	if !(e.VALID_HYGATE_MACS[ev.HygateMAC] && e.VALID_BEACON_MACS[ev.BeaconMAC]) {
		if !e.UNREGISTERED_MACS[ev.BeaconMAC] && !e.UNREGISTERED_MACS[ev.HygateMAC] {
			// 새 미등록 디바이스 기록
			e.markUnregistered(ev.BeaconMAC, "-")
			e.markUnregistered(ev.HygateMAC, ev.RemoteIP)
		}
		return
	}

	// 마지막 감지 시각 업데이트 & warnBeacon 해제
	e.lastSeenMap[ev.BeaconMAC] = ev.At
	e.cancelAbsence(ev.BeaconMAC)
	delete(e.warnBeaconList, ev.BeaconMAC)
	e.prevWarnBeaconState[ev.BeaconMAC] = false
	// 컬렉션에서도 즉시 삭제 (중복 표시 방지)
	e.col("warnBeacon").DeleteOne(context.Background(), bson.M{"mac": ev.BeaconMAC})

	// 미동작 스캐너는 influx 저장 스킵 (경고 상태는 tick에서 갱신)
	skipInflux := e.warnScannerList[ev.HygateMAC]

	// 소유권/방향/갱도判定
	if !e.isOwner(&ev) {
		return
	}

	// activeBeacon 실시간 터치
	if e.activeBeaconSet[ev.BeaconMAC] {
		e.updateActiveBeaconTouch(ev.BeaconMAC, ev.HygateMAC, ev.At)
	}

	// Influx(실시간) & 요약 버퍼
	if !skipInflux {
		info := e.mergeBeaconInfo(ev.BeaconMAC)
		name, _ := info["name"].(string)
		number, _ := info["number"].(string)
		if name == "" {
			name = "-"
		}
		if number == "" {
			number = "-"
		}
		e.influxQueue <- BeaconData{
			HygateMAC: ev.HygateMAC,
			BeaconMAC: ev.BeaconMAC,
			Name:      name,
			Number:    number,
			Type:      e.beaconType[ev.BeaconMAC],
			RSSI:      ev.RSSI,
			Timestamp: ev.At,
			RemoteIP:  ev.RemoteIP,
			Direction: ev.Direction,
		}
	}
	e.hygateBuffers[ev.HygateMAC] = append(e.hygateBuffers[ev.HygateMAC], BeaconData{
		HygateMAC: ev.HygateMAC, BeaconMAC: ev.BeaconMAC, RSSI: ev.RSSI,
		Timestamp: ev.At, RemoteIP: ev.RemoteIP, Direction: ev.Direction,
	})
}

func (e *Engine) isGateScanner(order int) bool {
	if e.exitGateScannerMode == "all" {
		return true
	}
	_, ok := e.exitGateDurations[order]
	return ok
}

func (e *Engine) exitConfirmWaitForOrder(order int) time.Duration {
	if duration, ok := e.exitGateDurations[order]; ok {
		return duration
	}
	return e.exitDefaultDuration
}

func (e *Engine) onMonitorTick(now time.Time) {
	// 1) 나감 확정(게이트 후보 + order별 무감지 대기시간)
	for mac, candidate := range e.beaconExitCandidateAt {
		// 케이스 A: 기존 후보 타임아웃
		if h := e.lastOwnerMap[mac]; h != "" {
			if ord := e.scannerNumberMap[h]; !e.isGateScanner(ord) {
				// 비게이트에서 다시 보였다 = 출갱 취소(재진입으로 간주)
				delete(e.beaconExitCandidateAt, mac)
				continue
			}
		}
		if now.Sub(candidate.DetectedAt) >= e.exitConfirmWaitForOrder(candidate.GateOrder) {
			e.exitFinalize(mac, now)
			continue
		}
	}

	// 케이스 B: 후보가 없어도 lastGateSeenAt 기준으로 확정
	for mac, candidate := range e.lastGateSeenAt {
		// 이미 후보가 살아있다면 A에서 처리되므로 스킵
		if _, has := e.beaconExitCandidateAt[mac]; has {
			continue
		}

		// gate 시각 이후 재감지되었으면 출갱 보류
		if last, ok := e.lastSeenMap[mac]; ok && last.After(candidate.DetectedAt) {
			continue
		}
		if now.Sub(candidate.DetectedAt) >= e.exitConfirmWaitForOrder(candidate.GateOrder) {
			e.exitFinalize(mac, now)
			delete(e.lastGateSeenAt, mac)
		}
	}

	// 2) 스캐너 경고 판단
	missingKA := map[string]bool{}
	missingHB := map[string]bool{}
	for hmac := range e.VALID_HYGATE_MACS {
		if last, ok := e.keepaliveLastSeen[hmac]; !ok || now.Sub(last) > MISSING_KEEPALIVE_THRESHOLD {
			missingKA[hmac] = true
		}
	}
	for sc := range e.scannerToHeartbitMAC {
		if last, ok := e.heartbitLastSeen[sc]; !ok || now.Sub(last) > MISSING_HEARTBIT_THRESHOLD {
			missingHB[sc] = true
			e.warnHeartbitList[sc] = true
		}
	}
	// 최종 비정상 = CONNECT 안됨 ∧ keepalive 결손 ∧ heartbit 결손
	for h := range e.VALID_HYGATE_MACS {
		e.warnScannerList[h] = !e.activeConnections[h] && missingKA[h] && missingHB[h]
	}

	// 3) warnBeacon(사람만, Inside이고, 설정 시간 동안 미수신)
	if e.warnEnabled {
		for mac := range e.VALID_BEACON_MACS {
			if e.isHeartbitMAC(mac) {
				continue
			}
			if e.beaconType[mac] == "vehicle" {
				continue
			}
			if e.beaconTunnelState[mac] != TunnelInside {
				continue
			}
			last, ok := e.lastSeenMap[mac]
			if !ok || now.Sub(last) > e.warnDuration {
				e.warnBeaconList[mac] = true
				// activeBeacon 동기 해제
				delete(e.activeBeaconSet, mac)
				e.col("activeBeacon").DeleteOne(context.Background(), bson.M{"mac": mac})
			}
		}
	}

	// 4) 경고 전이 로그 & DB 싱크  (전이 기반으로만 DB 변경)
	detectedAt := now.Format("2006-01-02 15:04:05")

	// ---------------------------
	// warnScanner: enter → upsert(setOnInsert), recover → delete
	// ---------------------------
	for h := range unionKeys(e.warnScannerList, e.prevWarnScannerState) {
		cur := e.warnScannerList[h]
		prev := e.prevWarnScannerState[h]

		switch {
		case cur && !prev:
			// 최초 warn 진입
			e.logScannerEvent("warn", h)

			setOnInsert := bson.M{"mac": h, "detected_at": detectedAt}
			for k, v := range e.mergeScannerInfo(h) {
				if k == "mac" || k == "detected_at" {
					continue
				}
				setOnInsert[k] = v
			}
			_, _ = e.col("warnScanner").UpdateOne(
				context.Background(),
				bson.M{"mac": h},
				bson.M{"$setOnInsert": setOnInsert},
				options.Update().SetUpsert(true),
			)
		case !cur && prev:
			// warn 해제
			e.logScannerEvent("recover", h)
			_, _ = e.col("warnScanner").DeleteOne(context.Background(), bson.M{"mac": h})
		}
		e.prevWarnScannerState[h] = cur
	}

	// ---------------------------
	// warnHeartbit: enter → upsert(setOnInsert), recover → delete
	// ---------------------------
	for h := range unionKeys(e.warnHeartbitList, e.prevWarnHeartbitState) {
		cur := e.warnHeartbitList[h]
		prev := e.prevWarnHeartbitState[h]

		switch {
		case cur && !prev:
			setOnInsert := bson.M{"mac": h, "detected_at": detectedAt}

			// 스캐너/하트비트 메타는 최초 진입시에만 setOnInsert로 기록
			payload := e.mergeScannerInfo(h)
			if hb, ok := e.scannerToHeartbitMAC[h]; ok {
				if info, ok2 := e.heartbitInfo[hb]; ok2 {
					for k, v := range info {
						if k == "mac" || k == "detected_at" {
							continue
						}
						payload[k] = v
					}
				}
			}
			for k, v := range payload {
				if k == "mac" || k == "detected_at" {
					continue
				}
				setOnInsert[k] = v
			}

			_, _ = e.col("warnHeartbit").UpdateOne(
				context.Background(),
				bson.M{"mac": h},
				bson.M{"$setOnInsert": setOnInsert},
				options.Update().SetUpsert(true),
			)

		case !cur && prev:
			_, _ = e.col("warnHeartbit").DeleteOne(context.Background(), bson.M{"mac": h})
		}

		e.prevWarnHeartbitState[h] = cur
	}

	// ---------------------------
	// warnBeacon: enter → upsert(setOnInsert), recover → delete
	// ---------------------------
	for b := range unionKeys(e.warnBeaconList, e.prevWarnBeaconState) {
		cur := e.warnBeaconList[b]
		prev := e.prevWarnBeaconState[b]

		switch {
		case cur && !prev:
			e.logBeaconEvent("warn", b, e.lastOwnerMap[b])

			setOnInsert := bson.M{"mac": b, "detected_at": detectedAt}
			payload := e.mergeBeaconInfo(b)
			payload["durationMinutes"] = int64(e.warnDuration / time.Minute)
			// 최초 진입 시점의 소유 스캐너 스냅샷만 기록
			payload["detected_scanner"] = e.mergeScannerInfo(e.lastOwnerMap[b])

			for k, v := range payload {
				if k == "mac" || k == "detected_at" {
					continue
				}
				setOnInsert[k] = v
			}

			_, _ = e.col("warnBeacon").UpdateOne(
				context.Background(),
				bson.M{"mac": b},
				bson.M{"$setOnInsert": setOnInsert},
				options.Update().SetUpsert(true),
			)

		case !cur && prev:
			e.logBeaconEvent("recover", b, e.lastOwnerMap[b])
			_, _ = e.col("warnBeacon").DeleteOne(context.Background(), bson.M{"mac": b})
		}

		e.prevWarnBeaconState[b] = cur
	}

	// overstayBeacon: 최초 체류시간 초과 전이에만 현재 상태와 이력을 저장한다.
	if e.overstayEnabled {
		for mac, enteredAt := range e.workerEnteredAt {
			if e.beaconType[mac] != "worker" || e.beaconTunnelState[mac] != TunnelInside {
				continue
			}
			if now.Sub(enteredAt) >= e.overstayDuration {
				e.overstayBeaconList[mac] = true
			}
		}

		for b := range unionKeys(e.overstayBeaconList, e.prevOverstayState) {
			cur := e.overstayBeaconList[b]
			prev := e.prevOverstayState[b]
			if cur && !prev {
				enteredAt := e.workerEnteredAt[b]
				e.logOverstayEvent(b, e.lastOwnerMap[b], enteredAt)
				_, _ = e.col("overstayBeacon").UpdateOne(
					context.Background(),
					bson.M{"mac": b},
					bson.M{"$setOnInsert": e.overstayPayload(b, e.lastOwnerMap[b], enteredAt, now)},
					options.Update().SetUpsert(true),
				)
			}
			e.prevOverstayState[b] = cur
		}
	}

	// 퇴실 확정 후 설정 시간 동안 어느 스캐너에서도 재인식되지 않은 작업자 알람
	if e.absenceEnabled {
		for mac, exitedAt := range e.workerExitedAt {
			if e.beaconType[mac] != "worker" || e.beaconTunnelState[mac] != TunnelOutside {
				continue
			}
			if now.Sub(exitedAt) < e.absenceDuration || e.absenceBeaconList[mac] {
				continue
			}

			e.absenceBeaconList[mac] = true
			payload := e.absencePayload(mac, e.lastOwnerMap[mac], exitedAt, now)
			_, _ = e.col("absenceBeacon").UpdateOne(
				context.Background(),
				bson.M{"mac": mac},
				bson.M{"$setOnInsert": payload},
				options.Update().SetUpsert(true),
			)
			e.logAbsenceEvent("absence", mac, e.lastOwnerMap[mac], exitedAt)
		}
	}

	// 5) stopPersist (주기 저장)
	for bmac, fix := range e.lastFixMap {
		// 사람만 warn 스킵 적용
		if e.beaconType[bmac] == "worker" && e.warnBeaconList[bmac] {
			continue
		}
		// Inside 아니면 스킵
		if e.beaconTunnelState[bmac] != TunnelInside {
			continue
		}
		// 마지막 감지시각
		last, ok := e.lastSeenMap[bmac]
		if !ok {
			continue
		}
		silent := now.Sub(last)
		if silent < STOP_THRESHOLD {
			continue
		}
		if e.warnEnabled && e.beaconType[bmac] == "worker" && silent >= e.warnDuration {
			continue
		}
		// 출갱 확정 직전이면 기록 생략
		if _, ok := e.beaconExitCandidateAt[bmac]; ok {
			continue
		}
		if candidate, ok := e.lastGateSeenAt[bmac]; ok &&
			now.Sub(candidate.DetectedAt) < e.exitConfirmWaitForOrder(candidate.GateOrder) {
			continue
		}
		// 쓰로틀(3분)
		if lastAt, ok := e.lastStopPersistAt[bmac]; ok && now.Sub(lastAt) < STOP_THRESHOLD {
			continue
		}
		// 저장
		point := BeaconData{
			HygateMAC: fix.HygateMAC,
			BeaconMAC: bmac,
			RSSI:      fix.RSSI,
			Timestamp: now,
			RemoteIP:  "-",
			Direction: DirectionStop,
		}

		e.influxQueue <- point
		e.hygateBuffers[fix.HygateMAC] = append(e.hygateBuffers[fix.HygateMAC], point)
		e.lastStopPersistAt[bmac] = now
	}
}

func (e *Engine) onSummaryTick(now time.Time) {
	for mac, buf := range e.hygateBuffers {
		if len(buf) == 0 {
			continue
		}
		last := buf[len(buf)-1]
		p := influxdb2.NewPointWithMeasurement("mem").
			AddTag("data_type", "beacon").
			AddTag("hygate_mac", mac).
			AddTag("ip", last.RemoteIP).
			AddTag("mac", last.BeaconMAC).
			AddField("rssi", last.RSSI).
			SetTime(now)
		_ = e.influxWriteSummary.WritePoint(context.Background(), p)
		e.hygateBuffers[mac] = nil
	}
}

/* ===================== Ownership & Tunnel ===================== */

func (e *Engine) confirmOwnerCandidate(beaconMAC, hygateMAC string, now time.Time) bool {
	cand := e.beaconOwnerCandidateMap[beaconMAC]
	if cand.HygateMAC != hygateMAC || now.Sub(cand.FirstSeen) > OWNER_CANDIDATE_WINDOW_SEC {
		e.beaconOwnerCandidateMap[beaconMAC] = OwnerCandidate{
			HygateMAC: hygateMAC,
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
		return false
	}

	cand.Count++
	cand.LastSeen = now
	e.beaconOwnerCandidateMap[beaconMAC] = cand
	return cand.Count >= OWNER_SWITCH_CONFIRM_COUNT
}

func (e *Engine) isOwner(ev *EBeacon) bool {
	ex, ok := e.beaconOwnerMap[ev.BeaconMAC]
	now := ev.At
	curOrder := e.scannerNumberMap[ev.HygateMAC]
	var dir Direction
	var prevOrder, prevRSSI int
	var prevDir Direction
	var prevHMAC string
	var lastMove time.Time
	if ok {
		prevOrder = ex.Order
		prevRSSI = ex.RSSI
		prevDir = ex.Direction
		prevHMAC = ex.HygateMAC
		lastMove = ex.LastMoveTimestamp
	}

	// 1) 같은 스캐너에서 읽힌 경우
	if ok && ev.HygateMAC == prevHMAC {
		// STOP_THRESHOLD 이상 동안 같은 스캐너에서만 읽히면 정지로 판정
		if now.Sub(lastMove) >= STOP_THRESHOLD {
			dir = DirectionStop
		} else {
			// 그대로 진행 방향 유지
			dir = prevDir
		}
		goto UPDATE
	}

	// 2) 다른 스캐너 + RSSI 우위 → 즉시 전환
	if ok && ev.HygateMAC != prevHMAC && ev.RSSI > prevRSSI {
		dir = calcDirection(curOrder, prevOrder)
		goto UPDATE
	}

	// 3) 최초 인식
	if !ok {
		dir = DirectionStop
		goto UPDATE
	}

	// 4) 동시 스캔 윈도(NEARBY_SCAN_WINDOW_SEC) 안에서는
	//    스캐너 간 "위치 관계"를 RSSI 보다 우선해서 사용
	if now.Sub(ex.Timestamp) < NEARBY_SCAN_WINDOW_SEC {
		distCur := abs(curOrder - prevOrder)

		switch distCur {
		case 0:
			// 같은 스캐너에서 RSSI만 더 세면 값만 갱신
			if ev.RSSI > prevRSSI {
				dir = prevDir
				goto UPDATE
			}
			return false

		case 1:
			// 인접 스캐너 이동도 일시적인 튐을 줄이기 위해 연속 확인 후 전환한다.
			if !e.confirmOwnerCandidate(ev.BeaconMAC, ev.HygateMAC, now) {
				return false
			}
			dir = calcDirection(curOrder, prevOrder)
			goto UPDATE

		default:
			// 2칸 이상 떨어진 스캐너가 아주 짧은 시간 안에 튀는 것은
			// 반사/잡음 가능성이 높으니 무시
			return false
		}
	}

	// 5) NEARBY_SCAN_WINDOW_SEC ~ OWNER_EXPIRE_SEC 사이에는
	//    같은 새 스캐너가 3초 안에 연속으로 확인된 경우에만 owner 전환 허용
	if now.Sub(ex.Timestamp) >= NEARBY_SCAN_WINDOW_SEC && now.Sub(ex.Timestamp) < OWNER_EXPIRE_SEC {
		if !e.confirmOwnerCandidate(ev.BeaconMAC, ev.HygateMAC, now) {
			return false
		}

		dir = calcDirection(curOrder, prevOrder)
		goto UPDATE
	}

	// 5) OWNER_EXPIRE_SEC 이후에는 이전 owner 를 "만료"로 보고
	//    RSSI 가 이전보다 약하더라도 새 스캐너로 전환을 허용한다.
	if now.Sub(ex.Timestamp) >= OWNER_EXPIRE_SEC {
		dir = calcDirection(curOrder, prevOrder)
		goto UPDATE
	}

	// 6) 그 외 구간에서는 RSSI 가 더 강한 스캐너만 owner 를 가져간다.
	if ev.RSSI > prevRSSI {
		dir = calcDirection(curOrder, prevOrder)
		goto UPDATE
	}

	return false

UPDATE:
	moveTs := ex.LastMoveTimestamp
	if !ok || dir != prevDir {
		moveTs = now
	}
	ev.Direction = dir
	e.beaconOwnerMap[ev.BeaconMAC] = OwnerInfo{
		HygateMAC: ev.HygateMAC, RSSI: ev.RSSI, Timestamp: now,
		Order: curOrder, Direction: dir, LastMoveTimestamp: moveTs,
	}
	delete(e.beaconOwnerCandidateMap, ev.BeaconMAC)
	e.lastOwnerMap[ev.BeaconMAC] = ev.HygateMAC
	e.transitionPresentSession(ev.BeaconMAC, ev.HygateMAC, now)

	// 출입 상태
	prevState := e.beaconTunnelState[ev.BeaconMAC]
	e.beaconTunnelState[ev.BeaconMAC] = TunnelInside
	alreadyActive := e.activeBeaconSet[ev.BeaconMAC]
	if e.beaconType[ev.BeaconMAC] == "worker" && prevState != TunnelInside {
		e.workerEnteredAt[ev.BeaconMAC] = now
	}

	// 게이트에서 보이면 나감 후보
	if e.isGateScanner(curOrder) {
		candidate := ExitCandidate{DetectedAt: now, GateOrder: curOrder}
		e.beaconExitCandidateAt[ev.BeaconMAC] = candidate
		e.lastGateSeenAt[ev.BeaconMAC] = candidate // 보강용
	}

	// Inside 확정 시 active upsert
	if prevState != TunnelInside || !alreadyActive {
		payload := e.mergeBeaconInfo(ev.BeaconMAC)
		payload["mac"] = ev.BeaconMAC
		payload["detected_at"] = now.Format("2006-01-02 15:04:05")
		payload["detected_scanner"] = e.mergeScannerInfo(ev.HygateMAC)

		e.col("activeBeacon").UpdateOne(context.Background(),
			bson.M{"mac": ev.BeaconMAC},
			bson.M{"$set": payload},
			options.Update().SetUpsert(true),
		)
		e.activeBeaconSet[ev.BeaconMAC] = true
		e.logDailyEvent("entered", ev.BeaconMAC, ev.HygateMAC)
	}
	// 마지막 확정
	e.lastFixMap[ev.BeaconMAC] = LastFix{
		HygateMAC: ev.HygateMAC, RSSI: ev.RSSI, RemoteIP: ev.RemoteIP, Timestamp: now,
	}
	return true
}

/* ===================== Workers ===================== */

func (e *Engine) influxWorker() {
	batch := []BeaconData{}
	t := time.NewTicker(BATCH_FLUSH_TIME)
	for {
		select {
		case d := <-e.influxQueue:
			batch = append(batch, d)
			if len(batch) >= BATCH_FLUSH_COUNT {
				e.flushBeacon(batch)
				batch = batch[:0]
			}
		case <-t.C:
			if len(batch) > 0 {
				e.flushBeacon(batch)
				batch = batch[:0]
			}
		}
	}
}

/* ===================== Network ===================== */

func handleConn(conn net.Conn, eng *Engine) {
	ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	defer conn.Close()

	fmt.Printf("[%s] [CONNECT] %s\n", time.Now().In(eng.kstLoc).Format("2006-01-02 15:04:05"), ip)
	eng.evCh <- ETCPConnect{RemoteIP: ip}

	reader := bufio.NewReader(conn)
	firstByte, err := reader.ReadByte()
	if err != nil {
		return
	}
	if firstByte == BINARY_FRAME_START {
		if err := handleBinaryScannerConn(reader, eng, ip); err != nil && err != io.EOF {
			fmt.Printf("[%s] [BINARY_ERR] %s | %v\n", time.Now().In(eng.kstLoc).Format("2006-01-02 15:04:05"), ip, err)
		}
		return
	}
	if err := reader.UnreadByte(); err != nil {
		return
	}

	sc := bufio.NewScanner(reader)
	for sc.Scan() {
		line := sc.Text()

		// BC-01 진단: 파싱 전에 원문을 출력해 장비 데이터 형식을 확인한다.
		// if ip == "192.168.0.205" {
		// 	fmt.Printf("[%s] [RAW] %s | %q\n", time.Now().In(eng.kstLoc).Format("2006-01-02 15:04:05"), ip, line)
		// }

		// PROXY protocol
		if strings.HasPrefix(line, "PROXY ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 3 {
				ip = parts[2]
				eng.evCh <- ETCPConnect{RemoteIP: ip}
			}
			continue
		}
		// keepalive hex
		if ok, macHex := isKeepAliveHexLine(line); ok {
			if h, err := formatMAC(macHex); err == nil && eng.VALID_HYGATE_MACS[h] {
				eng.evCh <- EKeepalive{HygateMAC: h, At: time.Now(), RemoteIP: ip}
			}
			continue
		}
		// CSV: time,bmac,rssi,?,hmac (len=5)
		parts := strings.Split(line, ",")
		if len(parts) != 5 {
			continue
		}
		bmac, e1 := formatMAC(parts[1])
		rssi := parseRSSI(parts[2])
		hmac, e2 := formatMAC(parts[4])
		if e1 != nil || e2 != nil {
			continue
		}
		if !eng.hasValidMACPrefix(bmac) {
			continue
		}

		// heartbit vs 일반
		if eng.isHeartbitMAC(bmac) {
			eng.evCh <- EHeartbit{BeaconMAC: bmac, HygateMAC: hmac, RSSI: rssi, At: time.Now()}
		} else {
			fmt.Printf("[%s] [RECV] %s | %s | %s | %d\n", time.Now().In(eng.kstLoc).Format("2006-01-02 15:04:05"), ip, hmac, bmac, rssi)
			eng.evCh <- EBeacon{BeaconMAC: bmac, HygateMAC: hmac, RSSI: rssi, At: time.Now(), RemoteIP: ip}
		}
	}
	if ip == "192.168.0.205" {
		if err := sc.Err(); err != nil {
			fmt.Printf("[%s] [SCAN_ERR] %s | %v\n", time.Now().In(eng.kstLoc).Format("2006-01-02 15:04:05"), ip, err)
		} else {
			fmt.Printf("[%s] [DISCONNECT] %s\n", time.Now().In(eng.kstLoc).Format("2006-01-02 15:04:05"), ip)
		}
	}
}

type binaryScannerReading struct {
	BeaconMAC string
	RSSI      int
}

func handleBinaryScannerConn(reader *bufio.Reader, eng *Engine, ip string) error {
	for {
		frame, err := readBinaryScannerFrame(reader)
		if err != nil {
			return err
		}
		hygateMAC, readings, err := parseBinaryScannerFrame(frame)
		if err != nil {
			fmt.Printf("[%s] [BINARY_FRAME_ERR] %s | %v\n", time.Now().In(eng.kstLoc).Format("2006-01-02 15:04:05"), ip, err)
			continue
		}

		now := time.Now()
		if eng.VALID_HYGATE_MACS[hygateMAC] {
			eng.evCh <- EKeepalive{HygateMAC: hygateMAC, At: now, RemoteIP: ip}
		}
		for _, reading := range readings {
			if !eng.hasValidMACPrefix(reading.BeaconMAC) {
				continue
			}
			if eng.isHeartbitMAC(reading.BeaconMAC) {
				eng.evCh <- EHeartbit{BeaconMAC: reading.BeaconMAC, HygateMAC: hygateMAC, RSSI: reading.RSSI, At: now}
				continue
			}
			fmt.Printf("[%s] [RECV] %s | %s | %s | %d\n", now.In(eng.kstLoc).Format("2006-01-02 15:04:05"), ip, hygateMAC, reading.BeaconMAC, reading.RSSI)
			eng.evCh <- EBeacon{BeaconMAC: reading.BeaconMAC, HygateMAC: hygateMAC, RSSI: reading.RSSI, At: now, RemoteIP: ip}
		}

		nextByte, err := reader.ReadByte()
		if err != nil {
			return err
		}
		if nextByte != BINARY_FRAME_START {
			return fmt.Errorf("invalid binary frame start: 0x%02X", nextByte)
		}
	}
}

func readBinaryScannerFrame(reader io.Reader) ([]byte, error) {
	header := []byte{BINARY_FRAME_START, 0, 0, 0, 0, 0}
	if _, err := io.ReadFull(reader, header[1:]); err != nil {
		return nil, err
	}
	frameLength := int(binary.BigEndian.Uint32(header[2:6]))
	if frameLength < BINARY_FRAME_MIN || frameLength > BINARY_FRAME_MAX {
		return nil, fmt.Errorf("invalid binary frame length: %d", frameLength)
	}

	frame := make([]byte, frameLength)
	copy(frame, header)
	if _, err := io.ReadFull(reader, frame[len(header):]); err != nil {
		return nil, err
	}
	return frame, nil
}

func parseBinaryScannerFrame(frame []byte) (string, []binaryScannerReading, error) {
	if len(frame) < BINARY_FRAME_MIN || frame[0] != BINARY_FRAME_START || frame[len(frame)-1] != BINARY_FRAME_END {
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
	readings := make([]binaryScannerReading, 0)

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
				offset += advertisementLength
				readings = append(readings, binaryScannerReading{
					BeaconMAC: beaconMAC,
					RSSI:      int(int8(frame[offset+1])),
				})
				offset += 2
			}
			continue
		}
		if rssiCount < 1 || offset+rssiCount > len(frame)-1 {
			return "", nil, fmt.Errorf("invalid binary RSSI count: %d", rssiCount)
		}
		for _, value := range frame[offset : offset+rssiCount] {
			readings = append(readings, binaryScannerReading{
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

/* ===================== Bootstrapping ===================== */

func main() {
	// Mongo
	mcli, err := mongo.Connect(context.Background(), options.Client().ApplyURI(mongoURL))
	must(err)
	fmt.Println("✅ MongoDB Connected")

	// Influx
	icli := influxdb2.NewClient(influxURL, token)
	defer icli.Close()
	fmt.Println("✅ InfluxDB Connected")

	eng := NewEngine(mcli, icli)
	eng.ensureIndexes()
	eng.loadProductConfig() // 시작 시 1회만 로드; 변경 사항은 프로세스 재시작 후 반영
	eng.loadDictionaries()
	eng.hydrateActiveFromDB() // 재시작시 activeBeacon 및 stopPersist 상태 복구
	eng.hydratePresentSessions()
	eng.hydrateWorkerEntriesFromDB()
	eng.hydrateWarnFromDB() // 재시작시 warn 상태 복구 (prev=cur로 맞춤)
	eng.hydrateOverstayFromDB()
	eng.hydrateAbsenceFromDB()

	// ticks
	go func() {
		mt := time.NewTicker(MONITOR_INTERVAL)
		st := time.NewTicker(SUMMARY_INTERVAL)
		for {
			select {
			case <-mt.C:
				eng.evCh <- ETick{Now: time.Now()}
			case <-st.C:
				eng.evCh <- ESummarize{Now: time.Now()}
			}
		}
	}()

	// engine
	go eng.Run()

	// TCP
	ln, err := net.Listen("tcp", TCP_PORT)
	must(err)
	fmt.Println("✅ TCP Server listening on", TCP_PORT)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(c, eng)
	}
}

/* ===================== Engine helpers ===================== */

func (e *Engine) ensureIndexes() {
	// TTL 인덱스: scannerLogs/beaconLogs(14d), tunnelDaily(7d), tunnelEvents(90d)
	twoWeeks := int32(14 * 24 * 60 * 60)
	e.ensureTTL("scannerLogs", "ttl", twoWeeks)
	e.ensureTTL("beaconLogs", "ttl", twoWeeks)
	sevenDays := int32(7 * 24 * 60 * 60)
	e.ensureTTL("tunnelDaily", "ttl", sevenDays)
	ninetyDays := int32(90 * 24 * 60 * 60)
	e.ensureTTL("tunnelEvents", "ttl", ninetyDays)

	// tunnelDaily.date unique
	e.col("tunnelDaily").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "date", Value: 1}}, Options: options.Index().SetUnique(true),
	})
	e.col("tunnelEvents").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "date", Value: -1}, {Key: "detected_at", Value: -1}},
	})
	e.col("overstayBeacon").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "mac", Value: 1}}, Options: options.Index().SetUnique(true),
	})
	e.col("absenceBeacon").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "mac", Value: 1}}, Options: options.Index().SetUnique(true),
	})
	e.col("beaconLogs").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "event_key", Value: 1}},
		Options: options.Index().SetUnique(true).SetPartialFilterExpression(
			bson.M{"action": "overstay", "event_key": bson.M{"$exists": true}},
		),
	})
	e.col("tunnelEvents").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "mac", Value: 1}, {Key: "detected_at", Value: -1}},
	})
	e.col("tunnelEvents").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "event", Value: 1}, {Key: "detected_at", Value: -1}},
	})
	e.col("presentSessions").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "beacon_mac", Value: 1}},
		Options: options.Index().SetUnique(true).SetPartialFilterExpression(
			bson.M{"status": "active"},
		),
	})
	e.col("presentSessions").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "scanner_mac", Value: 1}, {Key: "entered_at", Value: -1}},
	})
	e.col("presentSessions").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "status", Value: 1}, {Key: "entered_at", Value: -1}},
	})
	for _, col := range []string{"workerHistory", "vehicleHistory"} {
		e.col(col).Indexes().CreateOne(context.Background(), mongo.IndexModel{
			Keys: bson.D{{Key: "number", Value: 1}}, Options: options.Index().SetUnique(true),
		})
		e.col(col).Indexes().CreateOne(context.Background(), mongo.IndexModel{
			Keys: bson.D{{Key: "history.mac", Value: 1}},
		})
		e.col(col).Indexes().CreateOne(context.Background(), mongo.IndexModel{
			Keys: bson.D{{Key: "history.name", Value: 1}},
		})
	}
}

func (e *Engine) ensureTTL(col, field string, seconds int32) {
	_, _ = e.col(col).Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys:    bson.D{{Key: field, Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(seconds),
	})
}

func (e *Engine) loadDictionaries() {
	// heartbit
	cur, _ := e.col("heartbit").Find(context.Background(), bson.M{})
	for cur.Next(context.Background()) {
		var raw bson.M
		_ = cur.Decode(&raw)
		mac, _ := raw["mac"].(string)
		if mac == "" {
			continue
		}
		delete(raw, "_id")
		e.heartbitInfo[mac] = raw
		e.VALID_BEACON_MACS[mac] = true
		if sc, _ := raw["scanner"].(string); sc != "" {
			e.scannerToHeartbitMAC[sc] = mac
		}
	}
	cur.Close(context.Background())

	// scanner
	cur, _ = e.col("scanner").Find(context.Background(), bson.M{})
	for cur.Next(context.Background()) {
		var raw bson.M
		_ = cur.Decode(&raw)
		mac, _ := raw["mac"].(string)
		if mac == "" {
			continue
		}
		if id, ok := raw["_id"]; ok {
			s := fmt.Sprintf("%v", id)
			if num, err := strconv.ParseInt(s, 10, 64); err == nil {
				raw["tag"] = int(num)
			}
		}
		delete(raw, "_id")
		e.scannerInfo[mac] = raw
		e.VALID_HYGATE_MACS[mac] = true
		switch v := raw["order"].(type) {
		case int32:
			e.scannerNumberMap[mac] = int(v)
		case int:
			e.scannerNumberMap[mac] = v
		}

		// 역매핑
		if ord, ok := e.scannerNumberMap[mac]; ok {
			e.orderToScannerMac[ord] = mac
		}
		if ip, _ := raw["ip"].(string); ip != "" {
			e.ipToScannerMac[ip] = mac
		}

		// 초기엔 경고 보수적으로 true (tick에서 정리)
		e.warnScannerList[mac] = true
		e.warnHeartbitList[mac] = true
	}
	cur.Close(context.Background())

	// vehicle
	cur, _ = e.col("vehicle").Find(context.Background(), bson.M{})
	for cur.Next(context.Background()) {
		var raw bson.M
		_ = cur.Decode(&raw)
		mac, _ := raw["mac"].(string)
		if mac == "" {
			continue
		}
		if id, ok := raw["_id"]; ok {
			s := fmt.Sprintf("%v", id)
			if num, err := strconv.ParseInt(s, 10, 64); err == nil {
				raw["tag"] = int(num)
			}
		}
		delete(raw, "_id")
		e.vehicleInfo[mac] = raw
		e.VALID_BEACON_MACS[mac] = true
		e.beaconType[mac] = "vehicle"
		e.beaconTunnelState[mac] = TunnelOutside
	}
	cur.Close(context.Background())

	// worker
	cur, _ = e.col("worker").Find(context.Background(), bson.M{})
	for cur.Next(context.Background()) {
		var raw bson.M
		_ = cur.Decode(&raw)
		mac, _ := raw["mac"].(string)
		if mac == "" {
			continue
		}
		if id, ok := raw["_id"]; ok {
			s := fmt.Sprintf("%v", id)
			if num, err := strconv.ParseInt(s, 10, 64); err == nil {
				raw["tag"] = int(num)
			}
		}
		delete(raw, "_id")
		e.workerInfo[mac] = raw
		e.VALID_BEACON_MACS[mac] = true
		e.beaconType[mac] = "worker"
		e.beaconTunnelState[mac] = TunnelOutside
	}
	cur.Close(context.Background())

	// unregistered cache
	cur, _ = e.col("unregisteredDevice").Find(context.Background(), bson.M{})
	for cur.Next(context.Background()) {
		var doc struct {
			MAC string `bson:"mac"`
		}
		_ = cur.Decode(&doc)
		if doc.MAC != "" {
			e.UNREGISTERED_MACS[doc.MAC] = true
		}
	}
	cur.Close(context.Background())

	// warn snapshots
	cur, _ = e.col("warnScanner").Find(context.Background(), bson.M{})
	for cur.Next(context.Background()) {
		var raw bson.M
		_ = cur.Decode(&raw)
		mac, _ := raw["mac"].(string)
		if mac != "" {
			e.warnScannerList[mac] = true
		}
	}
	cur.Close(context.Background())

	cur, _ = e.col("warnHeartbit").Find(context.Background(), bson.M{})
	for cur.Next(context.Background()) {
		var raw bson.M
		_ = cur.Decode(&raw)
		mac, _ := raw["mac"].(string)
		if mac != "" {
			e.warnHeartbitList[mac] = true
		}
	}
	cur.Close(context.Background())

	cur, _ = e.col("warnBeacon").Find(context.Background(), bson.M{})
	for cur.Next(context.Background()) {
		var raw bson.M
		_ = cur.Decode(&raw)
		mac, _ := raw["mac"].(string)
		if mac != "" {
			e.warnBeaconList[mac] = true
		}
	}
	cur.Close(context.Background())
}

func (e *Engine) hydrateActiveFromDB() {
	cur, err := e.col("activeBeacon").Find(context.Background(), bson.M{})
	if err != nil {
		fmt.Printf("[BOOT][ERR] hydrateActiveFromDB Find: %v\n", err)
		return
	}
	defer cur.Close(context.Background())

	restored := 0
	for cur.Next(context.Background()) {
		var doc bson.M
		if err := cur.Decode(&doc); err != nil {
			continue
		}

		bmac, _ := doc["mac"].(string)
		if bmac == "" {
			continue
		}

		// 1) lastSeen: detected_at (string "2006-01-02 15:04:05")
		var lastSeen time.Time
		if s, _ := doc["detected_at"].(string); s != "" {
			if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
				lastSeen = t.In(e.kstLoc)
			}
		}
		if lastSeen.IsZero() {
			// 안전장치: 부팅 직후 즉시 warn 방지
			lastSeen = time.Now()
		}

		// 2) 마지막 소유 스캐너 MAC 복구
		var lastOwnerH string
		if ds, _ := doc["detected_scanner"].(bson.M); ds != nil {
			// 2-1) order로 찾기(우선)
			if ordAny, ok := ds["order"]; ok {
				ord := -1
				switch v := ordAny.(type) {
				case int:
					ord = v
				case int32:
					ord = int(v)
				case int64:
					ord = int(v)
				case float64:
					ord = int(v)
				}
				if ord >= 0 {
					if mac, ok := e.orderToScannerMac[ord]; ok {
						lastOwnerH = mac
					}
				}
			}
			// 2-2) ip로 찾기(보조)
			if lastOwnerH == "" {
				if ip, _ := ds["ip"].(string); ip != "" {
					if mac, ok := e.ipToScannerMac[ip]; ok {
						lastOwnerH = mac
					}
				}
			}
		}

		// 3) RSSI는 문서에 없으므로 보수치 (-90)
		lastRSSI := -90

		// ---- 메모리 상태 복구 (DB 수정 없음) ----
		e.beaconTunnelState[bmac] = TunnelInside
		e.activeBeaconSet[bmac] = true
		if t, _ := doc["type"].(string); t != "" {
			e.beaconType[bmac] = t
		}
		if lastOwnerH != "" {
			e.lastOwnerMap[bmac] = lastOwnerH
		}
		e.lastFixMap[bmac] = LastFix{
			HygateMAC: lastOwnerH,
			RSSI:      lastRSSI,
			RemoteIP:  "-",
			Timestamp: lastSeen,
		}
		e.lastSeenMap[bmac] = lastSeen
		if lastOwnerH != "" {
			e.beaconOwnerMap[bmac] = OwnerInfo{
				HygateMAC:         lastOwnerH,
				RSSI:              lastRSSI,
				Timestamp:         lastSeen,
				Order:             e.scannerNumberMap[lastOwnerH],
				Direction:         DirectionStop,
				LastMoveTimestamp: lastSeen,
			}
		}

		// ✅ 4) 게이트 스캐너였다면 출갱 후보로 복구
		if lastOwnerH != "" {
			ord, ok := e.scannerNumberMap[lastOwnerH]
			if !ok || ord == 0 {
				// 캐시 없으면 scannerInfo에서 추출
				if info, ok2 := e.scannerInfo[lastOwnerH]; ok2 {
					switch v := info["order"].(type) {
					case int:
						ord = v
					case int32:
						ord = int(v)
					case int64:
						ord = int(v)
					case float64:
						ord = int(v)
					case string:
						if n, err := strconv.Atoi(v); err == nil {
							ord = n
						}
					}
					if ord != 0 {
						e.scannerNumberMap[lastOwnerH] = ord // 캐시 보강
					}
				}
			}

			// 게이트 스캐너 판정
			if e.isGateScanner(ord) {
				candidate := ExitCandidate{DetectedAt: lastSeen, GateOrder: ord}
				e.beaconExitCandidateAt[bmac] = candidate
				e.lastGateSeenAt[bmac] = candidate
			}
		}

		restored++
	}
	fmt.Printf("[BOOT] hydrateActiveFromDB restored %d active beacons\n", restored)
}

func (e *Engine) hydratePresentSessions() {
	// 재실/퇴실 세션은 사람 태그만 관리한다. 이전 버전에서 생성된 차량
	// 세션과 현재 사람 목록에서 빠진 활성 세션은 제거한다.
	workerMACs := bson.A{}
	for mac := range e.workerInfo {
		workerMACs = append(workerMACs, mac)
	}
	_, _ = e.col("presentSessions").DeleteMany(context.Background(), bson.M{
		"$or": bson.A{
			bson.M{"beacon.type": "vehicle"},
			bson.M{"status": "active", "beacon_mac": bson.M{"$nin": workerMACs}},
		},
	})
	cur, err := e.col("presentSessions").Find(context.Background(), bson.M{
		"status":      "active",
		"beacon.type": "worker",
		"beacon_mac":  bson.M{"$in": workerMACs},
	})
	if err != nil {
		fmt.Printf("[BOOT][ERR] hydratePresentSessions Find: %v\n", err)
		return
	}
	defer cur.Close(context.Background())

	restored := 0
	for cur.Next(context.Background()) {
		var doc struct {
			BeaconMAC  string    `bson:"beacon_mac"`
			ScannerMAC string    `bson:"scanner_mac"`
			EnteredAt  time.Time `bson:"entered_at"`
			LastSeenAt time.Time `bson:"last_seen_at"`
		}
		if err := cur.Decode(&doc); err != nil {
			continue
		}
		if doc.BeaconMAC == "" || doc.ScannerMAC == "" || doc.EnteredAt.IsZero() {
			continue
		}
		if doc.LastSeenAt.IsZero() {
			doc.LastSeenAt = doc.EnteredAt
		}
		e.presentSessions[doc.BeaconMAC] = PresentSession{
			ScannerMAC: doc.ScannerMAC,
			EnteredAt:  doc.EnteredAt,
			LastSeenAt: doc.LastSeenAt,
		}
		restored++
	}
	fmt.Printf("[BOOT] hydratePresentSessions restored %d active sessions\n", restored)
}

func (e *Engine) latestOpenEntry(mac string) (time.Time, bool) {
	var event bson.M
	err := e.col("tunnelEvents").FindOne(
		context.Background(),
		bson.M{"mac": mac},
		options.FindOne().SetSort(bson.D{{Key: "detected_at", Value: -1}}),
	).Decode(&event)
	if err != nil || event["event"] != "entered" {
		return time.Time{}, false
	}
	enteredAt, ok := event["detected_at"].(time.Time)
	return enteredAt, ok
}

func (e *Engine) hydrateWorkerEntriesFromDB() {
	restored := 0
	for mac := range e.workerInfo {
		enteredAt, ok := e.latestOpenEntry(mac)
		if !ok {
			continue
		}
		e.workerEnteredAt[mac] = enteredAt
		e.beaconTunnelState[mac] = TunnelInside
		restored++
	}
	fmt.Printf("[BOOT] hydrateWorkerEntriesFromDB restored %d open worker entries\n", restored)
}

func (e *Engine) hydrateOverstayFromDB() {
	ctx := context.Background()
	if !e.overstayEnabled {
		_, _ = e.col("overstayBeacon").DeleteMany(ctx, bson.M{})
		return
	}

	cur, err := e.col("overstayBeacon").Find(ctx, bson.M{})
	if err != nil {
		fmt.Printf("[BOOT][ERR] hydrateOverstayFromDB Find: %v\n", err)
		return
	}
	defer cur.Close(ctx)

	restored := 0
	for cur.Next(ctx) {
		var doc bson.M
		if cur.Decode(&doc) != nil {
			continue
		}
		mac, _ := doc["mac"].(string)
		_, hasEntry := e.workerEnteredAt[mac]
		if mac == "" || e.beaconType[mac] != "worker" || e.beaconTunnelState[mac] != TunnelInside || !hasEntry {
			if mac != "" {
				_, _ = e.col("overstayBeacon").DeleteOne(ctx, bson.M{"mac": mac})
			}
			continue
		}
		e.overstayBeaconList[mac] = true
		e.prevOverstayState[mac] = true
		restored++
	}
	fmt.Printf("[BOOT] hydrateOverstayFromDB restored %d overstay beacons\n", restored)
}

func (e *Engine) latestTunnelEvent(mac string) (string, time.Time, bool) {
	var event bson.M
	err := e.col("tunnelEvents").FindOne(
		context.Background(),
		bson.M{"mac": mac, "event": bson.M{"$in": []string{"entered", "exited"}}},
		options.FindOne().SetSort(bson.D{{Key: "detected_at", Value: -1}}),
	).Decode(&event)
	if err != nil {
		return "", time.Time{}, false
	}
	action, _ := event["event"].(string)
	detectedAt, ok := event["detected_at"].(time.Time)
	return action, detectedAt, ok
}

func (e *Engine) hydrateAbsenceFromDB() {
	ctx := context.Background()
	if !e.absenceEnabled {
		_, _ = e.col("absenceBeacon").DeleteMany(ctx, bson.M{})
		return
	}

	currentAlerts := map[string]bool{}
	if cur, err := e.col("absenceBeacon").Find(ctx, bson.M{}); err == nil {
		defer cur.Close(ctx)
		for cur.Next(ctx) {
			var doc bson.M
			if cur.Decode(&doc) != nil {
				continue
			}
			if mac, _ := doc["mac"].(string); mac != "" {
				currentAlerts[mac] = true
			}
		}
	}

	restored := 0
	for mac := range e.workerInfo {
		action, detectedAt, ok := e.latestTunnelEvent(mac)
		if !ok || action != "exited" {
			if currentAlerts[mac] {
				_, _ = e.col("absenceBeacon").DeleteOne(ctx, bson.M{"mac": mac})
			}
			continue
		}
		e.beaconTunnelState[mac] = TunnelOutside
		e.workerExitedAt[mac] = detectedAt
		if currentAlerts[mac] {
			e.absenceBeaconList[mac] = true
		}
		restored++
	}
	fmt.Printf("[BOOT] hydrateAbsenceFromDB restored %d exited workers\n", restored)
}

func (e *Engine) hydrateWarnFromDB() {
	ctx := context.Background()

	// 1) warnScanner
	if cur, err := e.col("warnScanner").Find(ctx, bson.M{}); err == nil {
		defer cur.Close(ctx)
		for cur.Next(ctx) {
			var doc bson.M
			if err := cur.Decode(&doc); err != nil {
				continue
			}
			mac, _ := doc["mac"].(string)
			if mac == "" {
				continue
			}
			// 현재/이전 상태를 모두 true로
			e.warnScannerList[mac] = true
			e.prevWarnScannerState[mac] = true
		}
	}

	// 2) warnHeartbit
	if cur, err := e.col("warnHeartbit").Find(ctx, bson.M{}); err == nil {
		defer cur.Close(ctx)
		for cur.Next(ctx) {
			var doc bson.M
			if err := cur.Decode(&doc); err != nil {
				continue
			}
			mac, _ := doc["mac"].(string)
			if mac == "" {
				continue
			}
			e.warnHeartbitList[mac] = true
			e.prevWarnHeartbitState[mac] = true
		}
	}

	// 3) warnBeacon
	if !e.warnEnabled {
		e.warnBeaconList = map[string]bool{}
		e.prevWarnBeaconState = map[string]bool{}
		_, _ = e.col("warnBeacon").DeleteMany(ctx, bson.M{})
	} else if cur, err := e.col("warnBeacon").Find(ctx, bson.M{}); err == nil {
		defer cur.Close(ctx)
		for cur.Next(ctx) {
			var doc bson.M
			if err := cur.Decode(&doc); err != nil {
				continue
			}
			mac, _ := doc["mac"].(string)
			if mac == "" {
				continue
			}
			e.warnBeaconList[mac] = true
			e.prevWarnBeaconState[mac] = true
		}
	}

	fmt.Printf("[BOOT] hydrateWarnFromDB: scanner=%d, heartbit=%d, beacon=%d\n",
		countTrue(e.warnScannerList),
		countTrue(e.warnHeartbitList),
		countTrue(e.warnBeaconList),
	)
}

func (e *Engine) exitFinalize(mac string, exitedAt time.Time) {
	e.beaconTunnelState[mac] = TunnelOutside
	delete(e.beaconExitCandidateAt, mac)
	delete(e.lastGateSeenAt, mac)
	delete(e.activeBeaconSet, mac)
	delete(e.workerEnteredAt, mac)
	delete(e.overstayBeaconList, mac)
	delete(e.prevOverstayState, mac)
	_, _ = e.col("activeBeacon").DeleteOne(context.Background(), bson.M{"mac": mac})
	_, _ = e.col("overstayBeacon").DeleteOne(context.Background(), bson.M{"mac": mac})
	e.closePresentSession(mac, exitedAt, "site_exit", "")
	e.logDailyEvent("exited", mac, e.lastOwnerMap[mac])
	if e.absenceEnabled && e.beaconType[mac] == "worker" {
		e.workerExitedAt[mac] = exitedAt
	}
}

func (e *Engine) transitionPresentSession(bmac, currentScanner string, at time.Time) {
	// 차량은 실시간 위치 데이터만 처리하고 재실/퇴실/체류 세션은 만들지 않는다.
	if currentScanner == "" || e.beaconType[bmac] != "worker" {
		return
	}

	if session, ok := e.presentSessions[bmac]; ok {
		if session.ScannerMAC == currentScanner {
			session.LastSeenAt = at
			e.presentSessions[bmac] = session
			_, _ = e.col("presentSessions").UpdateOne(
				context.Background(),
				bson.M{"beacon_mac": bmac, "status": "active"},
				bson.M{"$set": bson.M{"last_seen_at": at.UTC(), "updated_at": at.UTC()}},
			)
			return
		}
		e.closePresentSession(bmac, at, "scanner_changed", currentScanner)
	}

	payload := bson.M{
		"beacon_mac":   bmac,
		"scanner_mac":  currentScanner,
		"beacon":       e.mergeBeaconInfo(bmac),
		"scanner":      e.mergeScannerInfo(currentScanner),
		"entered_at":   at.UTC(),
		"last_seen_at": at.UTC(),
		"exited_at":    nil,
		"status":       "active",
		"exit_reason":  nil,
		"created_at":   at.UTC(),
		"updated_at":   at.UTC(),
	}
	if _, err := e.col("presentSessions").InsertOne(context.Background(), payload); err != nil {
		fmt.Printf("[PRESENT][ERR] open beacon=%s scanner=%s: %v\n", bmac, currentScanner, err)
		return
	}
	e.presentSessions[bmac] = PresentSession{
		ScannerMAC: currentScanner,
		EnteredAt:  at,
		LastSeenAt: at,
	}
}

func (e *Engine) closePresentSession(bmac string, exitedAt time.Time, reason, nextScanner string) {
	session, ok := e.presentSessions[bmac]
	if !ok {
		return
	}

	duration := exitedAt.Sub(session.EnteredAt)
	if duration < 0 {
		duration = 0
	}
	update := bson.M{
		"last_seen_at":     session.LastSeenAt.UTC(),
		"exited_at":        exitedAt.UTC(),
		"duration_seconds": int64(duration / time.Second),
		"status":           "exited",
		"exit_reason":      reason,
		"updated_at":       exitedAt.UTC(),
	}
	if nextScanner != "" {
		update["next_scanner_mac"] = nextScanner
	}
	_, _ = e.col("presentSessions").UpdateOne(
		context.Background(),
		bson.M{"beacon_mac": bmac, "status": "active"},
		bson.M{"$set": update},
	)
	delete(e.presentSessions, bmac)
}

/* ===================== DB & Logging ===================== */

func (e *Engine) col(name string) *mongo.Collection {
	return e.mongo.Database("LOCATION_MONITOR").Collection(name)
}

func nestedDocument(doc bson.M, key string) bson.M {
	if value, ok := doc[key].(bson.M); ok {
		return value
	}
	if value, ok := doc[key].(map[string]interface{}); ok {
		return bson.M(value)
	}
	return bson.M{}
}

func intValue(value interface{}) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), v == float64(int64(v))
	default:
		return 0, false
	}
}

func firstDocumentValue(doc bson.M, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := doc[key]; ok {
			return value
		}
	}
	return nil
}

func isMACRule(value string, segments int) bool {
	parts := strings.Split(value, ":")
	if len(parts) != segments {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
		if _, err := hex.DecodeString(part); err != nil {
			return false
		}
	}
	return true
}

func stringSliceValue(value interface{}, segments int) []string {
	var raw []interface{}
	switch values := value.(type) {
	case bson.A:
		raw = []interface{}(values)
	case []interface{}:
		raw = values
	case []string:
		raw = make([]interface{}, len(values))
		for i, item := range values {
			raw[i] = item
		}
	default:
		return nil
	}

	result := []string{}
	seen := map[string]bool{}
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			continue
		}
		text = strings.ToUpper(strings.TrimSpace(text))
		if !isMACRule(text, segments) || seen[text] {
			continue
		}
		seen[text] = true
		result = append(result, text)
	}
	return result
}

func containsAnyPattern(mac string, patterns []string) bool {
	mac = strings.ToUpper(strings.TrimSpace(mac))
	for _, pattern := range patterns {
		if strings.Contains(mac, pattern) {
			return true
		}
	}
	return false
}

func (e *Engine) isHygateMAC(mac string) bool {
	return containsAnyPattern(mac, e.hygateMACPatterns)
}

func (e *Engine) isHeartbitMAC(mac string) bool {
	return containsAnyPattern(mac, e.heartbitMACPatterns)
}

func (e *Engine) hasValidMACPrefix(mac string) bool {
	normalizedMAC := strings.ToUpper(strings.TrimSpace(mac))
	for _, prefix := range e.macPrefixes {
		if strings.HasPrefix(normalizedMAC, prefix) {
			return true
		}
	}
	return false
}

func (e *Engine) loadProductConfig() {
	var config bson.M
	err := e.col("productConfig").FindOne(context.Background(), bson.M{"_id": "default"}).Decode(&config)
	if err != nil {
		fmt.Printf("[BOOT] productConfig unavailable; using alert defaults: %v\n", err)
		return
	}

	modules := nestedDocument(config, "modules")
	location := nestedDocument(modules, "location")
	deviceInfo := nestedDocument(location, "device_info")
	if value, ok := deviceInfo["prefix"].(string); ok {
		prefixes := make([]string, 0)
		seen := make(map[string]bool)
		for _, item := range strings.Split(value, ",") {
			prefix := strings.ToUpper(strings.TrimSpace(item))
			if isMACRule(prefix, 3) && !seen[prefix] {
				seen[prefix] = true
				prefixes = append(prefixes, prefix)
			}
		}
		if len(prefixes) > 0 {
			e.macPrefixes = prefixes
		}
	}
	if values := stringSliceValue(deviceInfo["hygate_mac_pattern"], 2); len(values) > 0 {
		e.hygateMACPatterns = values
	}
	if values := stringSliceValue(deviceInfo["heartbit_mac_pattern"], 2); len(values) > 0 {
		e.heartbitMACPatterns = values
	}
	fmt.Printf(
		"[BOOT] device info prefixes=%v hygate_patterns=%v heartbit_patterns=%v\n",
		e.macPrefixes,
		e.hygateMACPatterns,
		e.heartbitMACPatterns,
	)

	warn := nestedDocument(location, "warn")
	if len(warn) > 0 {
		if enabled, ok := warn["enabled"].(bool); ok {
			e.warnEnabled = enabled
		}
		if minutes, valid := intValue(firstDocumentValue(warn, "duration_minutes", "durationMinutes")); valid && minutes >= 0 {
			e.warnDuration = time.Duration(minutes) * time.Minute
		}
	}
	if e.warnEnabled {
		fmt.Printf("[BOOT] warn enabled: %d minutes\n", int64(e.warnDuration/time.Minute))
	} else {
		fmt.Println("[BOOT] warn disabled")
	}

	overstay := nestedDocument(location, "overstay")
	enabled, _ := overstay["enabled"].(bool)
	minutes, valid := intValue(firstDocumentValue(overstay, "duration_minutes", "durationMinutes"))
	if !enabled || !valid || minutes < 0 {
		fmt.Println("[BOOT] overstay disabled")
	} else {
		e.overstayEnabled = true
		e.overstayDuration = time.Duration(minutes) * time.Minute
		fmt.Printf("[BOOT] overstay enabled: %d minutes\n", minutes)
	}

	absence := nestedDocument(location, "absence")
	enabled, _ = absence["enabled"].(bool)
	minutes, valid = intValue(firstDocumentValue(absence, "duration_minutes", "durationMinutes"))
	if !enabled || !valid || minutes < 0 {
		fmt.Println("[BOOT] absence disabled")
	} else {
		e.absenceEnabled = true
		e.absenceDuration = time.Duration(minutes) * time.Minute
		fmt.Printf("[BOOT] absence enabled: %d minutes\n", minutes)
	}

	exitConfig := nestedDocument(location, "exit")
	if len(exitConfig) > 0 {
		mode, _ := firstDocumentValue(exitConfig, "gate_scanner_mode", "gateScannerMode").(string)
		if mode == "all" || mode == "selected" {
			e.exitGateScannerMode = mode
		}
		if value, ok := intValue(firstDocumentValue(exitConfig, "default_duration_minutes", "defaultDurationMinutes")); ok && value >= 0 {
			e.exitDefaultDuration = time.Duration(value) * time.Minute
		}

		var gates []interface{}
		switch value := firstDocumentValue(exitConfig, "gate_scanners", "gateScanners").(type) {
		case bson.A:
			gates = []interface{}(value)
		case []interface{}:
			gates = value
		}
		if gates != nil {
			durations := map[int]time.Duration{}
			for _, raw := range gates {
				var gate bson.M
				switch value := raw.(type) {
				case bson.M:
					gate = value
				case map[string]interface{}:
					gate = bson.M(value)
				default:
					continue
				}
				order, validOrder := intValue(gate["order"])
				if !validOrder || order < 1 {
					continue
				}
				duration := e.exitDefaultDuration
				if value, ok := intValue(firstDocumentValue(gate, "duration_minutes", "durationMinutes")); ok && value >= 0 {
					duration = time.Duration(value) * time.Minute
				}
				durations[int(order)] = duration
			}
			if e.exitGateScannerMode == "all" || len(durations) > 0 {
				e.exitGateDurations = durations
			}
		}
	}
	fmt.Printf(
		"[BOOT] exit gate mode=%s default=%d minutes configured_orders=%d\n",
		e.exitGateScannerMode,
		int64(e.exitDefaultDuration/time.Minute),
		len(e.exitGateDurations),
	)
}

func (e *Engine) overstayPayload(bmac, hmac string, enteredAt, detectedAt time.Time) bson.M {
	payload := e.mergeBeaconInfo(bmac)
	payload["action"] = "overstay"
	payload["mac"] = bmac
	payload["type"] = "worker"
	payload["entered_at"] = enteredAt.UTC()
	payload["detected_at"] = detectedAt.Format("2006-01-02 15:04:05")
	payload["durationMinutes"] = int64(e.overstayDuration / time.Minute)
	if hmac != "" {
		payload["detected_scanner"] = e.mergeScannerInfo(hmac)
	}
	return payload
}

func (e *Engine) logOverstayEvent(bmac, hmac string, enteredAt time.Time) {
	now := time.Now()
	payload := e.overstayPayload(bmac, hmac, enteredAt, now)
	payload["event_key"] = "overstay:" + bmac + ":" + enteredAt.UTC().Format(time.RFC3339Nano)
	payload["ttl"] = now
	_, _ = e.col("beaconLogs").UpdateOne(
		context.Background(),
		bson.M{"action": "overstay", "event_key": payload["event_key"]},
		bson.M{"$setOnInsert": payload},
		options.Update().SetUpsert(true),
	)
}

func (e *Engine) absencePayload(bmac, hmac string, exitedAt, detectedAt time.Time) bson.M {
	payload := e.mergeBeaconInfo(bmac)
	payload["action"] = "absence"
	payload["mac"] = bmac
	payload["type"] = "worker"
	payload["exited_at"] = exitedAt.UTC()
	payload["detected_at"] = detectedAt.Format("2006-01-02 15:04:05")
	payload["durationMinutes"] = int64(e.absenceDuration / time.Minute)
	if hmac != "" {
		payload["detected_scanner"] = e.mergeScannerInfo(hmac)
	}
	return payload
}

func (e *Engine) logAbsenceEvent(action, bmac, hmac string, exitedAt time.Time) {
	now := time.Now()
	payload := e.absencePayload(bmac, hmac, exitedAt, now)
	payload["action"] = action
	payload["ttl"] = now
	_, _ = e.col("beaconLogs").InsertOne(context.Background(), payload)
}

func (e *Engine) cancelAbsence(bmac string) {
	exitedAt, pending := e.workerExitedAt[bmac]
	alerted := e.absenceBeaconList[bmac]
	if !pending && !alerted {
		return
	}

	delete(e.workerExitedAt, bmac)
	delete(e.absenceBeaconList, bmac)
	_, _ = e.col("absenceBeacon").DeleteOne(context.Background(), bson.M{"mac": bmac})
	if alerted {
		e.logAbsenceEvent("absence_recover", bmac, e.lastOwnerMap[bmac], exitedAt)
	}
}

func (e *Engine) updateActiveBeaconTouch(bmac, hmac string, at time.Time) {
	ctx := context.Background()

	// UTC 문자열로 저장 (DB 일관성 유지)
	utcStr := at.UTC().Format("2006-01-02 15:04:05")

	payload := bson.M{
		"detected_at":      utcStr,
		"detected_scanner": e.mergeScannerInfo(hmac),
	}
	insertPart := e.mergeBeaconInfo(bmac)

	// upsert: true (문서가 없을 수도 있으니 안전하게)
	_, _ = e.col("activeBeacon").UpdateOne(
		ctx,
		bson.M{"mac": bmac},
		bson.M{"$set": payload, "$setOnInsert": insertPart},
		options.Update().SetUpsert(true),
	)
}

func (e *Engine) logConnection(action, hmac, ip string) {
	p := e.mergeScannerInfo(hmac)
	p["action"] = action
	p["mac"] = hmac
	p["ip"] = ip
	e.insertLog(p, "scannerLogs")
}

func (e *Engine) logScannerEvent(action, hmac string) {
	p := e.mergeScannerInfo(hmac)
	p["action"] = action
	p["mac"] = hmac
	e.insertLog(p, "scannerLogs")
}

func (e *Engine) logBeaconEvent(action, bmac, hmac string) {
	p := e.mergeBeaconInfo(bmac)
	p["action"] = action
	p["mac"] = bmac
	if action == "warn" {
		p["durationMinutes"] = int64(e.warnDuration / time.Minute)
	}
	if hmac != "" {
		p["detected_scanner"] = e.mergeScannerInfo(hmac)
	}
	e.insertLog(p, "beaconLogs")
}

func (e *Engine) insertLog(doc bson.M, col string) {
	if _, ok := doc["detected_at"]; !ok {
		doc["detected_at"] = time.Now().Format("2006-01-02 15:04:05")
	}
	if _, ok := doc["ttl"]; !ok {
		doc["ttl"] = time.Now()
	}
	_, _ = e.col(col).InsertOne(context.Background(), doc)
}

func (e *Engine) logDailyEvent(ev string, bmac, hmac string) {
	if ev != "entered" && ev != "exited" {
		return
	}
	if e.beaconType[bmac] == "vehicle" {
		return
	}
	now := time.Now()
	kstNow := now.In(e.kstLoc)
	dateStr := kstNow.Format("2006-01-02")
	detectedAt := kstNow.Format("2006-01-02 15:04:05")

	payload := e.mergeBeaconInfo(bmac)
	payload["mac"] = bmac
	if _, ok := payload["name"]; !ok {
		payload["name"] = "-"
	}
	if _, ok := payload["number"]; !ok {
		payload["number"] = "-"
	}
	payload["detected_at"] = detectedAt
	if hmac != "" {
		payload["detected_scanner"] = e.mergeScannerInfo(hmac)
	}

	eventPayload := bson.M{}
	for k, v := range payload {
		eventPayload[k] = v
	}
	eventPayload["event"] = ev
	if ev == "entered" {
		eventPayload["event_label"] = "입"
	} else {
		eventPayload["event_label"] = "출"
	}
	eventPayload["date"] = dateStr
	eventPayload["detected_at"] = now.UTC()
	eventPayload["detected_at_kst"] = detectedAt
	eventPayload["scanner_mac"] = hmac
	eventPayload["source"] = "beacon"
	eventPayload["created_at"] = now.UTC()
	eventPayload["ttl"] = now.UTC()
	_, _ = e.col("tunnelEvents").InsertOne(context.Background(), eventPayload)

	macsField := ev + "_macs"
	detailsField := ev + "_details." + bmac
	_, _ = e.col("tunnelDaily").UpdateOne(
		context.Background(),
		bson.M{"date": dateStr},
		bson.M{
			"$setOnInsert": bson.M{"date": dateStr, "ttl": time.Now()},
			"$addToSet":    bson.M{macsField: bmac},
			"$set":         bson.M{detailsField: payload},
		},
		options.Update().SetUpsert(true),
	)
}

func (e *Engine) mergeBeaconInfo(mac string) bson.M {
	t := e.beaconType[mac]
	if t == "" {
		t = "-"
	}
	base := bson.M{"type": t}
	var src bson.M
	if t == "worker" {
		src = e.workerInfo[mac]
	}
	if t == "vehicle" {
		src = e.vehicleInfo[mac]
	}
	for k, v := range src {
		if k == "mac" || k == "detected_at" {
			continue
		}
		base[k] = v
	}
	return base
}

func (e *Engine) mergeScannerInfo(mac string) bson.M {
	base := bson.M{}
	if info, ok := e.scannerInfo[mac]; ok {
		for k, v := range info {
			if k == "mac" || k == "detected_at" {
				continue
			}
			base[k] = v
		}
	}
	return base
}

func (e *Engine) markUnregistered(mac, ip string) {
	if e.UNREGISTERED_MACS[mac] {
		return
	}
	e.UNREGISTERED_MACS[mac] = true
	name := e.generateInitialName(mac, ip)
	safeIP := ip
	if e.isHeartbitMAC(mac) || e.isHygateMAC(mac) {
		// ok
	} else {
		safeIP = "-"
	}
	_, _ = e.col("unregisteredDevice").InsertOne(context.Background(), bson.M{
		"mac": mac, "ip": safeIP, "name": name, "created_at": time.Now().Format("2006-01-02"),
	})
}

/* ===================== Influx ===================== */

func (e *Engine) flushBeacon(batch []BeaconData) {
	for _, d := range batch {
		t := d.Type
		if t == "" {
			t = "-"
		}
		name := d.Name
		if name == "" {
			name = "-"
		}
		number := d.Number
		if number == "" {
			number = "-"
		}
		p := influxdb2.NewPointWithMeasurement("mem").
			AddTag("hygate_mac", d.HygateMAC).
			AddTag("ip", d.RemoteIP).
			AddTag("mac", d.BeaconMAC).
			AddTag("name", name).
			AddTag("number", number).
			AddTag("type", t).
			AddField("rssi", d.RSSI).
			AddField("direction", int(d.Direction)).
			SetTime(d.Timestamp)
		_ = e.influxWriteBeacon.WritePoint(context.Background(), p)
	}
}

/* ===================== Utilities ===================== */

func calcDirection(cur, prev int) Direction {
	if cur < prev {
		return DirectionUp
	}
	if cur > prev {
		return DirectionDown
	}
	return DirectionStop
}
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func isKeepAliveHexLine(s string) (bool, string) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "0x") {
		return false, ""
	}
	hexBody := s[2:]
	if len(hexBody) < 12 {
		return false, ""
	}
	macHex := strings.ToUpper(hexBody[:12])
	payload := hexBody[12:]
	if len(payload) == 0 {
		return false, ""
	}
	for i := 0; i < len(payload); i++ {
		if payload[i] != '0' {
			return false, ""
		}
	}
	if _, err := hex.DecodeString(macHex); err != nil {
		return false, ""
	}
	return true, macHex
}

func formatMAC(raw string) (string, error) {
	if strings.HasPrefix(raw, "0x") {
		raw = raw[2:]
	}
	if len(raw) != 12 {
		return "", fmt.Errorf("invalid mac")
	}
	parts := []string{}
	for i := 0; i < 12; i += 2 {
		parts = append(parts, raw[i:i+2])
	}
	return strings.Join(parts, ":"), nil
}

func parseRSSI(s string) int { var v int; fmt.Sscanf(s, "%d", &v); return v }

func (e *Engine) generateInitialName(mac, ip string) string {
	if ip == "-" {
		return "-"
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "-"
	}
	lastInt, err := strconv.Atoi(parts[3])
	if err != nil {
		return "-"
	}
	last := fmt.Sprintf("%03d", lastInt)
	switch {
	case e.isHygateMAC(mac):
		return "스캐너 " + last
	case e.isHeartbitMAC(mac):
		return "측정 " + last
	default:
		return "-"
	}
}

func unionKeys(a, b map[string]bool) map[string]struct{} {
	out := map[string]struct{}{}
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func countTrue(m map[string]bool) int {
	n := 0
	for _, v := range m {
		if v {
			n++
		}
	}
	return n
}
