# nowwin-beacon-gateway

현승코리아 G-1 게이트웨이의 비콘 수신을 확인하는 Go 테스트 서버입니다. 기존 운영 코드(`main.go`)와 분리해 실행합니다.

## 실행

```bash
cd scanner-test
docker-compose up -d --build
```

- 대시보드: `http://서버IP:8080`
- TCP 수신: `서버IP:7001`
- 중지: `docker-compose down`
- 코드 수정 후 같은 실행 명령으로 다시 빌드합니다.

## 비콘원문파서

- BINARY-LONG
- CSV 기반 텍스트 프레임 (time,beacon_mac,rssi,unused,scanner_mac)

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

## 주요 기능

- TCP 바이너리 및 CSV 기반 텍스트 프레임 자동 판별, 독립된 파서 패키지
- WebSocket 기반 실시간 대시보드, 모바일 화면 지원
- 비콘 목록 및 MAC 선택 필터
- 최초 수신 순서 유지, 마지막 수신 후 경과 시간 표시, 30초 미수신 시 목록에서 제외
- 패킷별 요약표와 원문 hex 표시, 아래로 스크롤하면 자동 일시정지
- 최근 이벤트 200건을 메모리에만 보관하며 서버 재시작 시 초기화

## 개발 및 테스트

Go 1.22 이상과 Python 3이 필요합니다.

```bash
cd scanner-test
make dev                         # 코드 저장 시 자동 재빌드·재시작
make test                        # Go 테스트 및 race 검사
python3 scripts/send_sample.py   # 합성 데이터 전송
```

파서는 `scanner-test/parser/`, 서버와 대시보드는 `scanner-test/cmd/server/`에 있습니다.
