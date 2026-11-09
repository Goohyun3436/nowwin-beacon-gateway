# nowwin-beacon-gateway

현승코리아 G-1 비콘 수신 테스트 서버 · Go

<br />

## 실행 환경

- OS: Ubuntu 22.04.5 LTS (x86_64)
- Docker: 29.9.3
- docker-compose: v2.9.0 (`docker-compose`)
- Go: 1.23.12 (`golang:1.23-alpine` 빌드 이미지)

<br />

## 실행

```bash
cd scanner-test
docker-compose up -d --build
```

- 대시보드: `http://서버IP:8080`
- TCP 수신: `서버IP:7001`
- 중지: `docker-compose down`

<br />

## 비콘원문파서

- BINARY-LONG:

    `bb01000000aaac233fc2...`

- BINARY-CSV: 

    `time,beacon_mac,rssi,unused,scanner_mac`

<br />

## 게이트웨이 설정

| 항목 | 설정 |
| --- | --- |
| Protocol | TCP |
| URL | `서버IP:7001` |
| Upload Interval | 1초 |
| Data format | BINARY-LONG |
| Compression | none |
| MAC filter | `^C30000.*\|^00C0B1.*` |
| MCV3 advertising packets only | 체크 해제 |

<br />

## 주요 기능

- TCP 바이너리 및 CSV 기반 텍스트 프레임 자동 판별, 독립된 파서 패키지
- WebSocket 기반 실시간 대시보드, 모바일 화면 지원
- 비콘 목록 및 MAC 선택 필터
- 최초 수신 순서 유지 · 수신 경과 시간 표시 · 30초 미수신 항목 제외
- 패킷별 요약표·원문 hex · 로그 스크롤 시 자동 일시정지
- 최근 이벤트 200건 메모리 보관 · 재시작 시 초기화

<br />

## 개발 및 테스트

필수: Go 1.22+ · Python 3

```bash
cd scanner-test
make dev                         # 코드 저장 시 자동 재빌드·재시작
make test                        # Go 테스트 및 race 검사
python3 scripts/send_sample.py   # 합성 데이터 전송
```

<br />

## 구조

- 파서: `scanner-test/parser/`
- 서버·대시보드: `scanner-test/cmd/server/`
