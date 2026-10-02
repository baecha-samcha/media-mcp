# Raspberry Pi deployment (manual opt-in)

## OAuth activation (existing production)

현재 Pi의 `media-mcp.service`는 이미 실행 중입니다. **OAuth 추가에는 아래 절차만
사용하세요.** 아래의 초기 설치/Tunnel 생성 절차는 새 호스트용 과거 안내입니다.
기존 unit, cloudflared, DNS, firewall은 변경할 필요가 없습니다.

구현 작업에서는 실제 환경파일을 읽거나 수정하지 않았으며 서비스를 재시작하지
않았습니다. OAuth 설정은 기존 `MEDIA_MCP_API_KEY`를 유지한 상태로 추가해야 합니다.
다음은 **운영자가 직접 실행할 명령**입니다.

```bash
cd /home/baecha/media-mcp
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q media_mcp tests scripts

# 현재 실행 여부만 확인; 별도 서버 프로세스를 시작하지 않습니다.
systemctl is-active media-mcp.service
curl --fail --silent --show-error http://127.0.0.1:8765/health

# 비밀번호를 숨김 입력. 기존 env 값 유지 + 같은 폴더에 mode-600 백업.
# 기존 OAuth 설정이 있으면 덮어쓰지 않고 거절합니다.
.venv/bin/python scripts/configure_oauth.py

# 기존 PUBLIC_BASE_URL이 https://media.baecha.xyz인지 편집기에서 확인합니다.
# cat/로그/채팅으로 env 내용을 출력하지 마세요.
nano /home/baecha/.config/media-mcp/server.env

# 아래 시점부터 실제 운영 반영. 사용자가 직접 실행합니다.
sudo systemctl restart media-mcp.service
systemctl is-active media-mcp.service
curl --fail --silent --show-error http://127.0.0.1:8765/health

# 외부 HTTPS discovery: 모두 JSON/HTTP 200이어야 합니다.
curl --fail --silent --show-error https://media.baecha.xyz/health
curl --fail --silent --show-error https://media.baecha.xyz/.well-known/oauth-authorization-server
curl --fail --silent --show-error https://media.baecha.xyz/.well-known/oauth-protected-resource/mcp
curl --fail --silent --show-error https://media.baecha.xyz/.well-known/oauth-protected-resource

# 401 + WWW-Authenticate resource_metadata 및 scope="media:read"가 정상입니다.
curl --silent --show-error --include --request POST \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json, text/event-stream' \
  --data '{}' https://media.baecha.xyz/mcp
```

`configure_oauth.py`가 생성/추가하는 변수:

- `MEDIA_MCP_OWNER_PASSWORD_HASH`: 숨김 입력 비밀번호의 salted scrypt hash.
  원래 비밀번호는 저장하지 않습니다. 비밀번호 관리자에 따로 보관하세요.
- `MEDIA_MCP_OAUTH_STORAGE_KEY`: CSPRNG Fernet key. 외부 env에만 저장됩니다.
- `MEDIA_MCP_OAUTH_REDIRECT_URIS`: 기본 ChatGPT 고정 callback.
- `MEDIA_MCP_OAUTH_ACCESS_TTL=900`, `MEDIA_MCP_OAUTH_REFRESH_TTL=2592000`,
  `MEDIA_MCP_OAUTH_CODE_TTL=120`.

Issuer는 기존 `MEDIA_MCP_PUBLIC_BASE_URL`을 사용합니다. 별도 issuer proxy나
OpenAI API key는 필요 없습니다. `MEDIA_MCP_OAUTH_STORE_DIR`는 선택 사항이며
기본 `MEDIA_MCP_TEMP_DIR/oauth-v1`을 권장합니다. 기존 unit은
`/home/baecha/.cache/media-mcp`만 쓰기 허용하므로 그 안에 유지하세요.
이 기본값에서는 unit 재설치/daemon-reload가 필요 없습니다.

ChatGPT **Create app** 입력:

| 항목 | 값 |
|---|---|
| Name | `media-mcp` |
| MCP Server URL | `https://media.baecha.xyz/mcp` |
| Authentication | `OAuth` |
| Registration 선택이 있는 경우 | `Dynamic Client Registration` |
| Client ID / Client Secret | 직접 입력하지 않음(DCR 발급) |
| Scope 입력이 있는 경우 | `media:read offline_access` |

owner 승인 화면에서 본인이 시작한 연결의 client/callback/scopes를 확인하고
비밀번호로 승인합니다. API key를 owner password로 쓰거나 입력하지 마세요.
도구 목록 `extract_media`, `prepare_media`를 확인합니다. ChatGPT UI의 정확한
callback이 기본값과 다르면 해당 HTTPS URL만 allowlist에 추가한 뒤 재시작합니다.
CIMD-only client/localhost callback은 이 개인 서버의 기본 정책에서 지원하지 않습니다.

Refresh token은 `offline_access`를 승인한 경우에만 발급합니다. 만료/회전/재사용
폐기/재연결 절차와 제한 사항은 [README OAuth 설명](../README.md#승인과-token-lifecycle)을
참고하세요. 정상 재시작은 OAuth grants를 보존하고 기존 미디어 capability URL은
무효화합니다. Owner hash/issuer 변경은 전체 OAuth 등록·승인을 폐기하므로 주의하세요.
Encryption key만 변경하면 기존 DB를 복호화할 수 없어 startup이 실패합니다.

문제 발생 시 `systemctl is-active media-mcp.service`로 확인하고 로컬에서
`journalctl -u media-mcp.service -n 50 --no-pager`를 검토하세요. env/token/query를
붙여넣지 마세요. 최초 OAuth 활성화 롤백은 설정 스크립트가 출력한 private backup을
환경파일로 복구한 다음 사용자가 서비스를 재시작하는 방식입니다. DB/미디어/Tunnel을
삭제할 필요가 없습니다. 암호화 DB의 복원은 현재 key와 일치해야 합니다.

## Initial deployment reference (new hosts only)

Code/tests are implemented. These commands have **not** been executed: service
installation/enabling, tunnel creation, DNS changes, firewall changes. The existing
production services and existing cloudflared service must remain untouched.

Verified host: user `baecha`, project `/home/baecha/media-mcp`, venv Python 3.13,
`/usr/bin/cloudflared` 2026.7.3 already installed. Port 8765 was free during the
implementation. Check it again before starting. No package installation is needed
on this checkout after implementation; `requirements.lock` records the tested venv.

## 1. Local configuration and foreground verification

```bash
cd /home/baecha/media-mcp
ss -ltnp 'sport = :8765'
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q media_mcp tests scripts

install -d -m 700 /home/baecha/.config/media-mcp /home/baecha/.cache/media-mcp
# Do not overwrite an existing environment file.
test -e /home/baecha/.config/media-mcp/server.env || \
  install -m 600 .env.example /home/baecha/.config/media-mcp/server.env
```

Generate the key **locally**, without displaying it or entering it in shell history.
The following only fills the empty placeholder and refuses to replace an existing key:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
import secrets
p = Path('/home/baecha/.config/media-mcp/server.env')
s = p.read_text()
if '\nMEDIA_MCP_API_KEY=\n' not in s:
    raise SystemExit('Empty key placeholder not found; existing key left untouched')
p.write_text(s.replace('\nMEDIA_MCP_API_KEY=\n', '\nMEDIA_MCP_API_KEY=' + secrets.token_urlsafe(48) + '\n', 1))
p.chmod(0o600)
PY

# Source only your trusted, locally maintained shell-compatible file.
set -a
. /home/baecha/.config/media-mcp/server.env
set +a
.venv/bin/python -m media_mcp.server
```

In a second terminal, `curl http://127.0.0.1:8765/health`. Stop this foreground
instance with Ctrl-C before installing/starting the systemd instance. Prepared
URLs use `MEDIA_MCP_PUBLIC_BASE_URL`; before the tunnel exists, override it to
`http://127.0.0.1:8765` for local fetch tests. The environment file is not loaded
automatically by Python; systemd's `EnvironmentFile` or the shell supplies it.

## 2. Apply the application service — only when ready

```bash
cd /home/baecha/media-mcp
sudo install -m 644 deployment/media-mcp.service /etc/systemd/system/media-mcp.service
sudo systemctl daemon-reload
sudo systemctl enable --now media-mcp.service
systemctl status media-mcp.service --no-pager
journalctl -u media-mcp.service -n 100 --no-pager
curl --fail http://127.0.0.1:8765/health
```

The app runs as `baecha`, uses its virtualenv and separate mode-600 environment
file, and logs to journal. It does not run as root. The service can write only
its cache directory (and private `/tmp`). Cookie copies must be under that cache
path. If changing `MEDIA_MCP_TEMP_DIR`, also update `ReadWritePaths`. Use exactly
one Uvicorn worker: a store ownership lock prevents unsafe multi-worker cleanup.
The memory/CPU systemd caps complement per-job limits; adjust both if raising
application concurrency.

## 3. Dedicated Cloudflare Tunnel — only when ready

Use a **separate tunnel and unit** so existing tunnels/services are unaffected.
Credentials remain in `~/.cloudflared`, never in this repository.

```bash
cloudflared --version
# Only if this account has not authenticated this machine already:
cloudflared tunnel login
cloudflared tunnel create media-mcp
```

Record the new UUID, then prepare the dedicated configuration:

```bash
cd /home/baecha/media-mcp
install -d -m 700 /home/baecha/.cloudflared
test -e /home/baecha/.cloudflared/media-mcp.yml || \
  install -m 600 deployment/cloudflared.example.yml /home/baecha/.cloudflared/media-mcp.yml
# Replace BOTH REPLACE_WITH_TUNNEL_UUID placeholders with the created UUID.
nano /home/baecha/.cloudflared/media-mcp.yml
cloudflared --config /home/baecha/.cloudflared/media-mcp.yml tunnel ingress validate
cloudflared --config /home/baecha/.cloudflared/media-mcp.yml tunnel ingress rule https://media.baecha.xyz/health

# Creates the DNS record; stop if that hostname already serves something else.
cloudflared tunnel route dns media-mcp media.baecha.xyz
sudo install -m 644 deployment/cloudflared-media.service /etc/systemd/system/cloudflared-media.service
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflared-media.service
journalctl -u cloudflared-media.service -n 100 --no-pager
curl --fail https://media.baecha.xyz/health
```

No inbound firewall port needs to be opened: the app listens on loopback and the
tunnel connects outbound. Do not run `cloudflared service install` over an existing
installation. For a dashboard-managed tunnel, add a published application route
`media.baecha.xyz → http://127.0.0.1:8765` to the chosen tunnel instead of the local
management commands above; do not mix the two methods for the same tunnel.

If cloudflared is missing on a different machine, use Cloudflare's official Debian
repository (commands below are documentation only):

```bash
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update
sudo apt-get install cloudflared
```

Keep Cloudflare caching disabled for `/media/*`; the application returns
`Cache-Control: no-store` for all responses. URL tokens are access credentials:
do not enable path/query access logging for them at the origin or export them to
analytics. Existing Cloudflare Access policies or browser challenges may prevent
AI fetchers from retrieving media; configure this dedicated hostname deliberately.
The application Bearer key protects extraction/preparation; media uses short-lived
unguessable URLs so clients unable to attach a custom header can read bytes.

## MCP connection

Endpoint: `https://media.baecha.xyz/mcp`, transport: **Streamable HTTP**, header:
`Authorization: Bearer <your configured key>`. Supports `extract_media` and
`prepare_media`; initialization and tool schemas use the official MCP SDK 2.2.0.
The transport is stateless with JSON POST responses, so it needs no sticky sessions
or long-lived SSE connection. Prepared media sessions are separate from MCP sessions.

Clients may use the existing custom Bearer header or the optional owner-approved
OAuth flow described above. Supplying URLs enables byte access; whether a host
actually analyzes video/audio depends on that client's capabilities.

## Maintenance

- `journalctl -u media-mcp.service -f` for safe operation/error-code logs.
- TTL cleanup runs every 30s, with expiry checked on every fetch. An already opened
  transfer may finish after TTL within its 120s stream deadline.
- Shutdown deletes cached sessions; restart sweeps only app-owned `job-<64 hex>`
  directories under `MEDIA_MCP_TEMP_DIR/sessions-v1`. Old links return 404.
- Four 128MiB reservations bound cached/preparing media to 512MiB by default.
  Expired files with an open transfer can retain up to another 128MiB (4 x 32MiB)
  until completion or the stream deadline. Large downloads exceeding limits fail.
- No MP4 remuxing/HLS/DASH assembly, subtitle/frame extraction, persistent cache,
  byte-range requests or multi-user isolation in this version. HEAD is supported.
- HTTP base URLs are accepted only for loopback development. Public deployment
  requires HTTPS; incoming Host/Origin are checked, forwarded headers are not trusted.
- Pinned Python transports are tested with the locked yt-dlp version. Updating
  yt-dlp requires rerunning both security and live tests before deployment.

References: [MCP mounting](https://py.sdk.modelcontextprotocol.io/run/asgi/),
[MCP transport options](https://py.sdk.modelcontextprotocol.io/run/),
[Cloudflare tunnel config](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/),
[cloudflared packages](https://pkg.cloudflare.com/).

### Persistent OAuth connections

Set `MEDIA_MCP_OAUTH_PERSISTENT_GRANTS=1` to issue new grants and client
registrations without automatic expiration. Requires an authorized service restart
and a newly registered/approved ChatGPT connection. Existing credentials retain
their original expiry; expired credentials are not restored. Access token responses
omit `expires_in`. Revocation and owner-change invalidation remain effective.
Default `0` retains the bounded TTL policy. This cannot control ChatGPT-side login
or connection policies. Reverting to `0` affects new grants only; explicitly revoke
existing persistent grants if they must be terminated.
