# 비콘 스캐너 테스트 서버

운영용 `main.go`는 변경하지 않았습니다. 별도 Go 모듈인 `scanner-test/`에서 실행하며 MongoDB/InfluxDB 없이 테스트합니다.

## 실행

Go 1.22 이상과 Python 3이 있으면:

```sh
cd scanner-test
make dev
```

`.go`/`.html` 저장 시 다시 빌드하고 재시작합니다. 컴파일 오류 시 기존 서버가 계속 실행됩니다. 재시작하면 메모리 통계는 초기화되며 수신 원문도 메모리에만 유지되므로 재시작 시 초기화됩니다. TCP 연결은 장비가 재연결해야 합니다.

단순 실행: `make run`, 검증: `make test` (race 검사 포함).

통합 검증: `go build -o .scanner ./cmd/server && python3 scripts/smoke_test.py` (임시 포트/로그로 실행 후 종료).

Go 없이 Docker로 실행:

```sh
cd scanner-test
docker compose up --build
```

코드 변경 후 같은 명령으로 다시 빌드합니다. 원본은 파일로 저장하지 않으며, 최근 200건만 메모리에 유지합니다. 중지는 `docker compose down`.

- 대시보드: http://localhost:8080 (동일 LAN의 다른 PC에서는 서버 IP:8080)
- 장비 TCP 목적지: `192.168.0.200:7001` (서버의 실제 IP가 다르면 수정)
- 장비: TCP / BINARY-LONG / compression none / 업로드 1초
- 기존 서버가 같은 7001 포트를 사용하면 먼저 중지하거나 테스트 포트와 장비 목적지를 함께 변경하세요.
- 네이티브 옵션 예: `go run ./cmd/server -tcp :7002 -web :8081 -format binary-long`
- `-format auto` 기본값은 BB 시작 바이너리와 줄 단위 CSV를 판별합니다. binary-long / csv로 고정할 수도 있습니다.

## 수신 확인

장비 MAC 필터는 사진의 `^C30000.*|^00C0B1.*`로 두고 서버에서 다음 값만 관측 목록에 반영합니다.

- `C3:00:00:*` 전체
- `00:C0:B1:*` 전체

대시보드는 마지막 수신 5초 이내를 활성으로 표시합니다. 관측 목록에서 두 접두사와 `00:C0:B1:C1:6B:AD`의 실제 수신을 확인하세요. 지정 MAC은 표시 제한이 아니라 실제 TCP 수신 여부 확인 대상입니다. **사진의 MCV3 advertising packets only가 체크되어 있습니다.** 다른 종류가 보이지 않으면 이 옵션을 해제하고 다시 확인하세요. 서버 필터는 장비가 전송하지 않은 광고를 복구할 수 없습니다.

실장비가 연결되기 전에는 실제 수신 여부를 확인할 수 없습니다. 아래는 합성 데이터로 동작만 검증합니다.

```sh
cd scanner-test
python3 scripts/send_sample.py
python3 scripts/send_sample.py --csv
```

세 MAC(C3 한 개, 00:C0:B1 두 개)은 표시되고 다른 접두사의 MAC은 필터 제외 수에만 반영됩니다. 합성 데이터도 같은 로그/통계에 기록되므로 실장비 검증 때 서버를 재시작하고 실수신 데이터로 다시 확인하세요.

## 파서와 프로토콜 검증

- `scanner-test/parser/binary.go`: 기존 `main.go`의 바이너리 파서를 추출했습니다. v1 광고 원본도 보존합니다.
- `scanner-test/parser/stream.go`: TCP 스트림 프레이밍, 기존 CSV/keepalive 파서, MAC 필터를 분리했습니다.
- `scanner-test/cmd/server/main.go`: TCP 수신, 메모리 원문 관리, 통계와 HTTP 대시보드만 담당합니다.
- `GET /ws`: WebSocket 연결 시 초기 상태를 보내고 수신/연결 상태 변경 시 즉시 갱신합니다. 대시보드는 폴링 없이 갱신하며 연결이 끊기면 자동 재연결합니다.
- `GET /api/state`: 최근 수신 이벤트 200건과 관측값/통계를 JSON으로 제공합니다.

사진은 설정만 보여주므로 BINARY-LONG의 바이트 규격을 확정할 수 없습니다. 현재 기준은 기존 코드의 `BB | version(u8) | 전체길이(u32 BE) | scanner MAC(6) | beacon count(u16 BE) | entries | DD`입니다. 각 entry는 MAC(6), sample count(u16 BE), samples입니다. v0은 RSSI(i8) 배열, v1은 광고 길이(u8), 광고, metadata(u8), RSSI(i8)입니다. 이 구조를 새 장비의 공식 규격으로 간주하지 마세요.

TCP의 분할/합쳐진 수신은 길이로 처리합니다. 잘못된 헤더/길이는 연결을 종료하고, 길이가 유효한 프레임의 파싱 오류는 기록 후 다음 프레임을 처리합니다. 최대 프레임/CSV 줄 크기는 1 MiB입니다. partial 수신과 미지원 형식도 읽은 원본은 보존합니다.

대시보드 로그는 수신 패킷 1건마다 요약표(스캐너 MAC, 비콘 MAC, RSSI, 처리 결과)와 실제 원문 hex를 하나의 블록으로 묶어 최신순으로 표시합니다. 수신 시각, 형식, 송신 주소도 함께 표시합니다. 내부 스크롤 없이 페이지에 세로로 펼칩니다.

로그 제목이 화면 위로 지나가면 자동 일시정지하여 읽는 위치를 유지합니다. WebSocket 수신은 계속되며 우측 상단 고정 버튼에 새 패킷 수를 표시합니다. 버튼을 누르면 최신 데이터로 갱신하고 로그 시작 위치로 이동하며 갱신을 재개합니다. 위로 돌아오면 자동 일시정지가 해제되지만 수동 일시정지는 유지됩니다.

`raw-chunk`는 TCP 읽기 조각이며 하나의 장비 패킷과 동일하지 않습니다. `packet`은 프레이밍과 파싱 결과입니다. 파일에는 누적 저장하지 않으며 최근 이벤트 200건만 메모리에 유지합니다. `-log` 옵션은 기존 실행 명령 호환을 위해 받아들이지만 무시합니다. 이전에 생성된 captures.jsonl 파일은 자동 삭제하지 않습니다.

HTTP / JSON-PREPARSED 수신은 아직 구현하지 않았습니다. 현재 HTTP는 대시보드/API 전용입니다. 실제 JSON 예시와 바이너리 로그를 확보한 다음 형식별 디코더를 추가하고 동일한 Reading 구조로 변환하면 됩니다.

운영 적용 시 검증된 `parser` 패키지를 운영 모듈에 복사하고 기존 네트워크 수신부에서 호출하세요. 반환된 scanner MAC/Reading을 기존 EKeepalive/EBeacon/EHeartbit 이벤트로 연결하면 DB/위치 판정 로직을 유지할 수 있습니다. 테스트용 Allowed 필터는 운영 대상 정책에 맞춰 따로 적용하세요. PROXY protocol 처리는 이 테스트 서버에 포함하지 않았습니다.

이 서버와 대시보드는 인증 없는 LAN 진단 도구입니다. 외부 공개 없이 장비와 연결 가능한 테스트 네트워크에서 실행하세요.
