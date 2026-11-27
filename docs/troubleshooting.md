# vm-queue 트러블슈팅 가이드

이 문서는 Tailscale 격리 환경과 일회성 AI VM 연동 과정에서 실제 발생한 7가지 시행착오와 해결·예방 방법을 정리한 기록입니다.

---

## 1. Tailscale `grants` 저장 후에도 `0.0.0.0/0` 전체 허용 규칙이 남는 현상

- **증상**: 관리 콘솔에 `"grants"` 규칙만 작성해 저장해도 서버의 `sudo tailscale debug netmap` `PacketFilter[0]`에 `0.0.0.0/0` 포트 `0~65535` 허용 규칙이 함께 내려옵니다.
- **원인**: Tailscale 정책 JSON에서 `"acls"` 키 자체를 생략하면 레거시 기본 전체 허용 정책이 활성화됩니다.
- **해결 및 예방**:
  - 정책 상단에 `"acls": []`를 명시적으로 넣어야 기본 거부가 적용됩니다([docs/tailscale-acl.json](tailscale-acl.json)).
  - 기동 직후 `scripts/check-tailscale-isolation.sh --auto-down`으로 와일드카드 소스가 0건인지 자동 확인합니다.

---

## 2. 상시 서버에서 Tailscale 기동 시 기존 DNS·터널 충돌 위험

- **증상**: 서버에 기본 옵션으로 `tailscale up`을 실행하면 `/etc/resolv.conf`가 MagicDNS로 덮이거나 서브넷 라우팅이 겹쳐 기존 Docker 컨테이너·터널 서비스가 영향을 받을 수 있습니다.
- **해결 및 예방**:
  - 상시 서버 합류 시 반드시 `--accept-routes=false --accept-dns=false` 플래그를 함께 사용합니다.
  - 큐 서비스는 `127.0.0.1:8790`에만 바인딩하고 `tailscale serve --tcp=8790`으로만 Tailnet에 노출합니다.

---

## 3. `awk -F= '{print $2}'` 명령의 `$2` 셸 확장 함정

- **증상**: `ssh host "awk -F= '/^VM_QUEUE_WORKER_TOKEN=/{print $2}' .env"`를 PowerShell이나 이스케이프가 풀리는 셸에서 실행하면 `$2`가 빈 문자열로 치환돼 `print`만 실행되고 결과적으로 `VM_QUEUE_WORKER_TOKEN=<토큰>` 77자 전체 줄이 출력됩니다.
- **원인**: 큰따옴표 안의 `$2`를 로컬 셸이 먼저 변수로 해석하기 때문입니다.
- **해결 및 예방**:
  - `$` 변수를 쓰지 않는 `sed -n 's/^VM_QUEUE_WORKER_TOKEN=//p'` 또는 [scripts/print-worker-token.sh](../scripts/print-worker-token.sh)를 사용합니다.

---

## 4. 워커 토큰 형식 오염과 원인 파악이 어려운 `HTTP 401`

- **증상**: 워커가 `HTTP 401`만 받고 실패할 때 토큰 앞뒤 공백, `Bearer ` 중복, `VM_QUEUE_WORKER_TOKEN=` 접두사, `<...>` 꺾쇠 중 어느 문제인지 서버 로그만으로 구별하기 어렵습니다.
- **해결 및 예방**:
  - 서버(`server.ts`)의 `classifyAuthHeader`가 시크릿 원문을 절대 남기지 않고 사유(`missing_auth_header`, `malformed_auth_header`, `token_mismatch`, `role_mismatch`)와 플래그(`double_bearer`, `env_key_prefix`, `angle_brackets`, `quoted`, `contains_whitespace`)만 `journald`에 기록합니다.
  - 워커(`worker/vm_worker.py`)의 `validate_worker_token`이 요청 전송 전에 잘못된 토큰 형식을 선제 차단합니다.

---

## 5. AI 에이전트가 새 요청을 보내지 않고 직전 401만 반복 설명하는 착시

- **증상**: 사용자가 AI 채팅창에 "토큰을 수정했다"고 답했을 때 에이전트가 실제 네트워크 호출 없이 직전 턴의 `401` 실패만 다시 설명하는 경우가 있습니다.
- **진단 방법**:
  - 서버에서 `journalctl --user -u vm-queue`와 `sudo journalctl -u tailscaled`를 확인하면 최근 시각에 실제 패킷·HTTP 요청이 들어왔는지 즉시 판별할 수 있습니다.
- **예방**:
  - 재실행을 지시할 때 구체적인 엔드포인트 호출과 `vm_worker.py` 실행 명령을 함께 전달합니다.

---

## 6. 60초 리스 중첩으로 인한 `{"job": null}` 반환

- **증상**: 직전 시도가 작업을 선점(`leased`)한 상태에서 60초 리스 만료 전에 다시 `POST /jobs/claim`을 보내면 서버가 중복 배정을 막으려고 `{"job": null}`을 돌려줍니다.
- **해결 및 예방**:
  - 수동 호출 대신 `vm_worker.py`가 백그라운드 하트비트로 리스를 자동 연장하고 실패 시 즉시 `POST /jobs/:id/fail`을 호출해 리스 고착을 막습니다.
  - 수동 개입이 필요할 때는 `cli/vm-queue-cli.ts requeue <job_id>`로 즉시 `queued` 상태로 되돌립니다.

---

## 7. `GET /jobs/:id/input` 본문에 `kind`가 없어 워커가 멈추는 문제

- **증상**: AI 워커가 `/jobs/:id/input` 응답 JSON에서 `kind`나 `input.kind`를 찾다가 작업을 실행하지 못하고 멈췄습니다.
- **원인**: `kind`는 `POST /jobs/claim` 응답의 `job.kind`에 포함되고 `/input` 본문은 작업 입력 데이터만 담도록 설계됐기 때문입니다.
- **해결 및 예방**:
  - 서버의 `GET /jobs/:id/input` 응답 헤더에 `X-Job-Id`와 `X-Job-Kind`를 추가해 어느 단계에서도 작업 종류를 교차 확인할 수 있게 했습니다.
  - 프롬프트로 HTTP 순서를 매번 설명하지 않고 계약이 내장된 `worker/vm_worker.py` 한 줄 실행으로 대체했습니다.
