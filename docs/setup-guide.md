# vm-queue 구축 및 운영 가이드

이 문서는 상시 리눅스 서버(`tag:oci`)에 `vm-queue`를 설치하고 Tailscale 격리 정책을 적용한 뒤 일회성 AI VM(`tag:worker`)에서 안전하게 `repo_check` 작업을 처리하는 전 과정을 다룹니다.

## 0. 준비 사항

- 상시 서버: Bun 런타임, Python 3, SQLite 내장(`bun:sqlite`), systemd 사용자 서비스 환경
- 워커 VM: Python 3.9 이상, `git`, 필요 시 각 프리셋 런타임(`bun`, `pytest`, `go`, `cargo`)
- Tailscale 계정 및 관리 콘솔 접근 권한

---

## 1. Tailscale ACL 선행 고정 (Phase 0)

서버에 Tailscale을 올리기 전에 관리 콘솔의 **Access Controls** 정책을 먼저 저장해야 민감 포트가 일시 개방되는 사고를 막습니다.

1. [docs/tailscale-acl.json](tailscale-acl.json) 전체를 복사해 Tailscale 관리 콘솔 정책 편집기에 붙여넣고 저장합니다.
2. 핵심 규칙은 `"acls": []`를 명시하는 것입니다. 이 줄이 없으면 Tailscale 기본 전체 허용 규칙(`0.0.0.0/0` 포트 `0~65535`)이 남을 수 있습니다.
3. 정책 저장 후 **Settings → Keys**에서 워커용 Auth Key를 발급합니다.
   - Description: `vm-queue-worker`
   - Reusable: 끔(1회용 권장)
   - Ephemeral: 켬(VM 종료 시 자동 정리)
   - Pre-approved: 켬
   - Tags: `tag:worker`

---

## 2. 상시 서버 Tailscale 합류 및 격리 검증 (Phase 1)

기존 서비스의 DNS 해석이나 라우팅이 흔들리지 않도록 상시 서버에서는 반드시 `--accept-routes=false`와 `--accept-dns=false`를 지정합니다.

```bash
sudo tailscale up \
  --advertise-tags=tag:oci \
  --accept-routes=false \
  --accept-dns=false
```

로그인 승인 뒤 아래 스크립트로 `PacketFilter`에 `0.0.0.0/0` 전체 허용 규칙이 없는지 점검합니다.

```bash
bash scripts/check-tailscale-isolation.sh --port 8790 --auto-down
```

`PASS: PacketFilter_count=...`가 출력되면 다음 단계로 넘어갑니다.

---

## 3. vm-queue 설치 및 서비스 등록 (Phase 2)

### 3.1 환경변수 설정

```bash
mkdir -p ~/services/vm-queue/data
cp .env.example ~/services/vm-queue/.env
chmod 600 ~/services/vm-queue/.env
```

서로 다른 24자 이상의 랜덤 토큰 2개를 생성해 `.env`의 `VM_QUEUE_ADMIN_TOKEN`과 `VM_QUEUE_WORKER_TOKEN`에 채웁니다.

```bash
openssl rand -hex 24
openssl rand -hex 24
```

토큰 형식에 `VM_QUEUE_` 접두사·`Bearer `·꺾쇠·공백이 섞이지 않았는지 확인합니다.

```bash
bash scripts/print-worker-token.sh --check-only ~/services/vm-queue/.env
```

### 3.2 systemd 사용자 서비스 및 Tailscale TCP 노출

[deploy/vm-queue.service.example](../deploy/vm-queue.service.example)을 `~/.config/systemd/user/vm-queue.service`로 복사하고 기동합니다.

```bash
mkdir -p ~/.config/systemd/user
cp deploy/vm-queue.service.example ~/.config/systemd/user/vm-queue.service
systemctl --user daemon-reload
systemctl --user enable --now vm-queue.service
systemctl --user is-active vm-queue.service
```

이어서 Tailnet 내부 전용 TCP 포트로 `8790`을 엽니다.

```bash
sudo tailscale serve --bg --yes --tcp=8790 tcp://127.0.0.1:8790
tailscale serve status
```

노출을 끄려면 `sudo tailscale serve --tcp=8790 off`를 실행합니다.

---

## 4. 워커 토큰 전달과 `repo_check` 실전 운용 (Phase 3)

### 4.1 안전한 워커 토큰 추출

셸 변수 확장(`$2`) 오류를 피하려고 항상 `scripts/print-worker-token.sh` 또는 `sed` 명령을 사용합니다.

```bash
ssh your-server "sed -n 's/^VM_QUEUE_WORKER_TOKEN=//p' ~/services/vm-queue/.env"
```

### 4.2 상시 서버에서 작업 투입 및 자동 오프로드

```bash
# 워커 생존 여부(최근 90초)를 먼저 확인한 뒤 자동 오프로드
bun run cli/vm-queue-cli.ts workers --window 90
bun run cli/vm-queue-cli.ts offload \
  --repo https://github.com/example-org/sample-repo \
  --ref main

# 직접 등록할 때도 --preset 을 생략하면 auto 로 동작합니다
bun run cli/vm-queue-cli.ts submit-repo-check \
  --job-id check-demo-1 \
  --repo https://github.com/example-org/sample-repo
```

허용 프리셋 목록은 다음과 같습니다.

| 프리셋 | 실행 내용 | 비고 |
|---|---|---|
| `auto` (기본값) | 저장소 매니페스트(`package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`)와 설치된 도구를 보고 자동 선택 | 해당 런타임이 없으면 `git_info`로 안전 폴백 |
| `git_info` | 추적 파일 수, 확장자 분포, 매니페스트 존재 여부 수집 | 저장소 코드를 실행하지 않음 |
| `bun_test` | `bun install --ignore-scripts` 후 `bun test` | `bun` 필요 |
| `bun_check` | `bun install --ignore-scripts` 후 `bun run check` | `bun` 필요 |
| `pytest` | `pytest -q` | `pytest` 필요 |
| `go_test` | `go test ./...` | `go` 필요 |
| `cargo_test` | `cargo test` | `cargo` 필요 |

### 4.3 일회성 AI VM에서 작업 비우기 (유한 세션 폴링)

워커 VM에 `VM_QUEUE_WORKER_TOKEN` 환경변수를 넣은 뒤 원라인 명령을 실행합니다. 기본 `--mode drain`은 대기 작업을 처리하고 바로 종료하며 작업 시간 동안 자동으로 새 작업을 받으려면 `--mode poll --max-idle-sec 1800`(30분 유휴 시 자동 종료, 최대 허용치 3600초)을 사용합니다.

> 무료 AI VM 계정 정지 위험을 피하려고 24시간 휴면 방지나 클릭 유지 루프는 의도적으로 제외했습니다.

```bash
curl -fsSL https://raw.githubusercontent.com/gimso2x/vm-queue/main/worker/vm_worker.py -o /tmp/vm_worker.py && python3 /tmp/vm_worker.py --url http://100.64.0.10:8790 --mode poll --max-idle-sec 1800
```

실패하거나 리스가 꼬인 작업은 상시 서버에서 다시 큐로 돌릴 수 있습니다.

```bash
bun run cli/vm-queue-cli.ts requeue check-demo-1 --ttl 3600
bun run cli/vm-queue-cli.ts status check-demo-1
```
