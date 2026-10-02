# media-mcp

Instagram / YouTube extractor + authenticated HTTP API + MCP Streamable HTTP.
Raspberry Pi에서 `127.0.0.1:8765`로 실행하고 Cloudflare Tunnel을 통해 공개합니다.
운영 서비스·DNS·Tunnel 설정은 자동 변경하지 않습니다.

## Architecture

```text
HTTP POST /extract ───┐
MCP extract_media ────┴─ MediaService ─ killable worker ─ existing extractor
HTTP POST /prepare ──┐                                      │
MCP prepare_media ───┴─ MediaService ─ extract + download_media
                            │
                        TTL store ─ GET/HEAD /media/{session}/{token}
```

- `core.py`, `instagram.py`, `extractor.py`: 기존 정상 동작 구현을 유지했습니다.
  Reel/YouTube는 yt-dlp, Post/carousel은 공개 HTML JSON 파서를 사용합니다.
- `download.py`: 기존 streaming/cleanup context에 항목별 크기·개수·시간 제한 추가.
- `config.py`: 환경변수와 startup validation. API 키 없이 서버가 실행되지 않습니다.
- `network.py`: **작업 프로세스에만** 허용 host/HTTPS와 공인 IP 검사를 적용합니다.
  DNS 결과의 숫자 IP로 실제 연결하며 SNI/인증서 검증의 원래 호스트명은 유지합니다.
  redirect의 URL/호스트/IP도 검사합니다. proxy, native curl 전송, 외부 JS 실행은
  작업 프로세스에서 비활성화해 보안 경계를 우회하지 못하게 합니다.
- `worker.py`, `service.py`: HTTP/MCP 공유 작업 계층, timeout 시 프로세스 종료,
  메모리 제한, 저장 공간 예약, 무작위 토큰, TTL/재시작 cleanup.
- `api.py`, `server.py`: FastAPI, 공식 MCP SDK, 인증, 안전한 오류와 미디어 streaming.

## Dependencies and tests

추가한 직접 dependency는 **FastAPI 0.141.1**, **Uvicorn 0.53.0**,
**공식 MCP SDK 2.2.0**입니다. 기존 yt-dlp 2026.08.19를 유지합니다.
`requirements.txt`는 직접 dependency, `requirements.lock`는 검증한 전체 버전입니다.
OAuth는 기존 venv/lock에 있던 `cryptography==50.0.1`,
`python-multipart==0.0.32`를 직접 dependency로 명시합니다. OAuth 작업에서는
패키지를 설치하거나 기존 SDK 버전을 변경하지 않았습니다.

```bash
cd /home/baecha/media-mcp
# 새 환경에서만: .venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q media_mcp tests scripts
# Instagram 원래 live tests (기본 suite에서는 skip)
MEDIA_MCP_LIVE=1 .venv/bin/python -m unittest discover -s tests -v
# 실제 임시 localhost 서버 + YouTube metadata + Instagram 준비/GET/HEAD + MCP SDK
.venv/bin/python scripts/smoke_live.py
```

기존 17개 테스트를 그대로 유지했습니다. 새 테스트는 auth, health, OpenAPI,
extract/prepare/fetch/HEAD, 만료·미존재·경로조작·symlink, 다운로드 크기·개수,
세션 한도, SSRF/IP/redirect/DNS rebinding, 취소·실제 프로세스 timeout, cleanup,
MCP 초기화·도구 스키마·호출·오류를 검증합니다. 기본 suite는 외부 네트워크를 쓰지 않습니다.

OAuth 보완 후 2026-09-16 로컬 검증: **67 tests, 65 passed, 2 opt-in live skipped**.
공식 SDK OAuth client로 discovery → DCR → owner approval → PKCE 교환 → MCP
initialize/tools/list/tools/call → refresh 회전을 자동 검증했습니다(ASGI transport,
미디어 runner는 fixture). 기존 parser/SSRF/resource-limit/TTL/API-key 테스트도 통과했습니다.
`compileall`, `pip check`, `systemd-analyze verify deployment/media-mcp.service` 통과.
이번 OAuth 작업에서는 Instagram/YouTube live 추출과 ChatGPT UI 연결을 재실행하지
않았습니다. 외부 `/health`는 기존 운영 버전 `0.2.0`으로 확인했고 운영 재시작은 하지 않았습니다.

이전 HTTP 구현 당시 실환경 확인 기록(OAuth 작업의 재검증 결과 아님):
carousel `DdEZgWTlGfB`의 18개 이미지 **9,209,423 bytes**를 서버가
준비하고 임시 HTTP URL로 모두 내려받았습니다. Reel `DdQ90KiyERI` 영상/오디오
2개 **730,654 bytes**도 GET/HEAD 성공했습니다. 짧은 YouTube `jNQXAC9IVRw`는
metadata 추출에 성공했습니다(YouTube 영상 다운로드는 수행하지 않았음).

## Configuration and start

설정 전체는 [.env.example](.env.example), 정확한 systemd/Cloudflare 적용 절차는
[deployment/README.md](deployment/README.md)를 참고하세요.
실제 API 키는 `.env.example`에 쓰지 말고 `~/.config/media-mcp/server.env`에 mode 600으로
보관합니다. 최소 32자의 공백 없는 ASCII 키가 필요합니다. Python이 `.env`를 자동
읽지는 않습니다. systemd `EnvironmentFile` 또는 셸 환경변수로 전달합니다.

| 변수 (`MEDIA_MCP_` 접두사) | 기본값 |
|---|---|
| `API_KEY` | 필수, 기본값 없음 |
| `HOST`, `PORT` | `127.0.0.1`, `8765` |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8765` (port 설정 반영) |
| `TEMP_DIR` | `~/.cache/media-mcp`의 절대 경로 |
| `MEDIA_TTL`, `CLEANUP_INTERVAL` | 900초, 30초 |
| `MAX_ITEMS` | 20 |
| `MAX_ITEM_BYTES`, `MAX_TOTAL_BYTES` | 32MiB, 128MiB |
| `INLINE_MAX_ITEMS` | 3 (`prepare_media` inline 이미지 최대 개수) |
| `INLINE_MAX_BYTES` | 5MiB (MCP inline 이미지 원본 합계, base64 이전) |
| `INLINE_FRAME_MAX_BYTES` | 2MiB (Reel 프레임 1장 원본 상한, 합계 제한과 함께 적용) |
| `CONCURRENCY`, `MAX_SESSIONS` | 1개 작업, 4개 보관/준비 세션 |
| `EXTRACT_TIMEOUT`, `PREPARE_TIMEOUT` | 45초, 90초 (작업 전체) |
| `WORKER_MEMORY_MB` | 프로세스 주소 공간 512MiB |
| `MAX_STREAMS`, `STREAM_TIMEOUT` | 4개, 120초 |

캐시·준비 중인 미디어는 기본값에서 **512MiB**로 제한합니다. 만료 시 이미 전송 중인
파일은 열린 descriptor 때문에 최대 128MiB(4 × 32MiB)를 추가로 유지할 수 있으며
전송 종료/timeout에 해제됩니다. 준비 중인 세션도 포함해 용량을 예약합니다. JSON body는 16KiB, URL은 2048자, body 수신은 10초,
Uvicorn 동시 연결/작업은 32로 제한합니다. HTTP와 MCP의 작업 한도는 공유합니다.
서버/스토어는 한 프로세스만 사용해야 하며 파일 잠금으로 중복 소유를 막습니다.

```bash
# 설정 파일을 먼저 만들고 API 키를 설정: deployment/README.md 참고
set -a
. /home/baecha/.config/media-mcp/server.env
set +a
cd /home/baecha/media-mcp
.venv/bin/python -m media_mcp.server
```

운영에서는 `MEDIA_MCP_PUBLIC_BASE_URL=https://media.baecha.xyz`로 설정하세요.
Host 헤더나 forwarded header로 미디어 URL을 생성하지 않습니다.

## HTTP API

| Endpoint | 인증 | 결과 |
|---|---|---|
| `GET /health` | 없음 | status/version |
| `POST /extract` | Bearer API key | 기존 normalized metadata |
| `POST /prepare` | Bearer API key | source metadata + 임시 미디어 URL |
| `GET /media/{session_id}/{token}` | URL 자체가 capability | media bytes |
| `HEAD /media/{session_id}/{token}` | URL 자체가 capability | Content-Type/Length |
| `GET /docs`, `/openapi.json` | 없음 | Swagger/OpenAPI |
| `/mcp` | OAuth access token 또는 기존 Bearer API key | Streamable HTTP MCP |

```bash
# 키 값은 직접 명령에 입력하지 않고 위의 환경파일에서 불러옵니다.
curl --fail https://media.baecha.xyz/health
curl --fail-with-body \
  -H "Authorization: Bearer $MEDIA_MCP_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.instagram.com/reel/DdQ90KiyERI/"}' \
  https://media.baecha.xyz/extract

curl --fail-with-body \
  -H "Authorization: Bearer $MEDIA_MCP_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.instagram.com/p/DdEZgWTlGfB/"}' \
  https://media.baecha.xyz/prepare
```

`/prepare` response:

```json
{
  "session_id": "<64 random hex characters>",
  "source": {"platform": "instagram", "id": "DdEZgWTlGfB", "url": "https://www.instagram.com/p/DdEZgWTlGfB/", "...": "existing normalized metadata"},
  "media": [{"index": 0, "type": "image", "url": "https://media.baecha.xyz/media/<session>/<token>", "content_type": "image/jpeg", "bytes": 123456}],
  "expires_at": 1800000000,
  "access": "temporary_bearer_url"
}
```

`source.media`의 CDN URL은 원본 metadata입니다. 실제 AI 분석에는 최상위 `media[].url`을
사용하세요. URL은 추측 불가능한 session/token 조합이며 파일시스템 경로를 노출하지
않습니다. 토큰 URL을 가진 누구나 TTL 내 읽을 수 있으므로 비밀처럼 취급하세요.
AI fetcher에 API 키를 넘길 필요가 없습니다. 모든 응답은 `Cache-Control: no-store`입니다.
TTL 이후 새 요청은 404; 이미 열린 전송은 스트림 timeout까지 완료할 수 있습니다.
서버 재시작 시 기존 URL은 무효화됩니다. 원본 URL/id로 다시 prepare하세요.

## MCP

공식 SDK 2.2.0의 **Streamable HTTP**, endpoint `/mcp`를 사용합니다.
`extract_media(url: str)` 출력과 HTTP `/prepare`는 유지됩니다.
`prepare_media(url: str, indices: list[int] | None = None, frame_timestamps: list[float] | None = None,
frame_indices: list[int] | None = None)`는 첫 text block 및
`structuredContent`에 기존 URL/session/expiry/source metadata를 유지하고, 뒤에 SDK
`ImageContent`를 직접 추가합니다. `indices=[2,1]`은 1-based 게시물 순서이며 이미지도
요청 순서로 반환합니다. 기존 metadata `index`는 0-based입니다. 기본은 첫 이미지 최대
3개, `INLINE_MAX_ITEMS`로 조정합니다. 선택하지 않은 이미지도 임시 URL을 유지합니다.
원본 합계 `INLINE_MAX_BYTES`(기본 5MiB) 제한으로 base64 크기는 약 6.67MiB입니다.
이미지는 리사이즈하지 않고 파일 시그니처로 MIME을 판별합니다. download 실패는 item
`error`, inline 크기/MIME/base64 실패는 `inline_error`로 보고하며 다른 이미지를 유지합니다.
Instagram 릴스는 기본적으로 첫 번째 영상에서 길이의 10%·50%·90% 프레임을
native `ImageContent`로 반환합니다(게시물 이미지와 같은 블록 형식·읽기 경로).
같은 프레임 번호는 `skipped: "duplicate_frame"`, 기본 선택에서 직전 프레임과 8×8 회색
축소본이 거의 같으면 `skipped: "near_duplicate"`로 건너뜁니다(`duplicate_of`=기준 ordinal).
릴스에 한해 `frame_timestamps`(초) 또는 `frame_indices`(0-based 영상 프레임 번호) 중 하나로
특정 프레임을 지정할 수 있습니다(고유한 0 이상 값, 최대 `INLINE_MAX_ITEMS`개, 지정 시 근접 중복
제거 없음). 둘을 같이 쓰거나 게시물에 쓰는 등 잘못된 값은 `invalid_frames`(400)이고, 영상
길이를 넘는 값은 해당 프레임만 `error: "out_of_range"`입니다. HTTP `/prepare`는 변경 없습니다.
각 프레임은 종횡비를 유지한 최대 1280px JPEG이며 기존 inline 개수·원본 합계 제한과
프레임당 `INLINE_FRAME_MAX_BYTES`를 적용합니다. `indices`는 계속 1-based media 항목 선택입니다.
`structuredContent.frames`에는 0-based 원본 `index`, `frame_index`, 요청 `timestamp_seconds`,
`selection`(`default`/`timestamps`/`frame_indices`), `width`·`height`, `content_type`, `bytes`,
`extracted`(ffmpeg 추출 성공 여부), `source: "instagram_reel"`, `inline_status`, text block을 포함한
0-based `content_block_index`가 기록됩니다.
실패한 프레임은 `error` 또는 `inline_error`를 기록하고 성공한 프레임과 영상 URL은 유지합니다.
설치된 `ffmpeg`·`ffprobe`를 제한된 worker에서 사용하며 로컬 MP4/WebM만 읽습니다.
그 외 비이미지는 URL로 전달하고, 명시적으로 inline 선택하면 `unsupported_media`를 보고합니다.
빈/중복/범위 밖 indices 또는 개수 제한 초과는 `invalid_indices`입니다.
모든 항목은 기존 다운로드 제한 내에서 준비되므로 indices는 inline 선택만 제어합니다.
`view_media(url: str)`는 ChatGPT 호환성 검증용으로, 단일 이미지 Instagram 게시물의 이미지를
`TextContent`(최소 metadata) + `ImageContent`(base64, worker `content_type()` MIME)로 직접 반환합니다.
임시 URL/세션을 만들지 않고 응답 전에 job 디렉터리를 삭제합니다. carousel/Reel/영상/YouTube와
`INLINE_MAX_BYTES` 초과는 리사이즈 없이 `unsupported_media`/`limit_exceeded` 오류입니다.
stateless transport + JSON 응답을 사용하며 FastAPI lifespan에서 SDK session manager를
시작·종료합니다. 예상 가능한 실패는 MCP `isError=true`와 안전한 JSON 오류로 반환합니다.

SDK 연결 예제:

```python
import asyncio, os
import httpx2  # official MCP SDK dependency
from mcp.client.streamable_http import streamable_http_client
from mcp.client.session import ClientSession

async def main():
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + os.environ["MEDIA_MCP_API_KEY"]},
        timeout=100,
    ) as http:
        async with streamable_http_client("https://media.baecha.xyz/mcp", http_client=http) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                result = await client.call_tool("prepare_media", {
                    "url": "https://www.instagram.com/p/DdEZgWTlGfB/"
                })
                # result contains temporary URLs: pass them to the AI consumer.

asyncio.run(main())
```

API 키 헤더를 지원하는 MCP client는 위 예제를 계속 사용할 수 있습니다.
ChatGPT custom app에는 아래 OAuth를 활성화하세요. AI API 호출은 추가하지 않습니다.
각 AI client의 영상/오디오 지원 여부는 별개입니다.

## OAuth architecture and ChatGPT connection

단일 owner authorization server를 FastAPI에 함께 제공합니다. 공식 MCP SDK 2.2.0의
`OAuthAuthorizationServerProvider`, discovery 생성기, authorization/token/registration/
revocation handler와 MCP bearer/resource/scope 검증 middleware를 사용합니다.
프로젝트 코드는 owner 승인, 보관/만료, 정확한 callback 허용목록과 SDK의 기본 정책에
없는 입력 검증을 담당합니다. Instagram/YouTube extractor와 capability 미디어 경로는
OAuth와 분리되어 기존 동작을 유지합니다.

```text
ChatGPT → /mcp → 401 + resource_metadata + scope
        → protected resource metadata → authorization server metadata
        → /register (허용된 정확한 callback만 등록)
        → /authorize (state + S256 PKCE + resource)
Browser → /oauth/consent (owner 비밀번호 + cookie/CSRF + 승인)
        → 등록된 callback (code + state + iss)
ChatGPT → /token (code + verifier + resource) → access/refresh tokens
        → /mcp (Bearer access token) → 기존 tools/service
```

**표준 선택:** MCP 2026-07-28 authorization 규격의 OAuth 2.1 draft 기반 code flow,
RFC 8414 AS metadata, RFC 9728 protected resource metadata, RFC 7636 PKCE S256,
RFC 8707 resource binding, RFC 9207 issuer identification, RFC 7591 DCR,
RFC 7009 revocation을 사용합니다. OAuth 2.1은 아직 draft이며 OIDC 로그인 서버는
아닙니다. `openid/email/profile`과 ID token은 제공하지 않습니다.

현재 MCP는 CIMD를 권장하고 DCR은 호환성 목적으로 유지합니다. 이 개인 서버는
**공식 SDK가 제공하는 DCR**을 선택합니다. 등록 입력 URL을 외부에서 fetch하지 않고
운영자가 신뢰하는 callback만 허용하므로 임의 client metadata URL에 대한 SSRF 경로를
추가하지 않습니다. CIMD 지원을 광고하지 않습니다. OpenAI 공식 문서도 DCR을 지원하며,
이 구현은 `authorization_response_iss_parameter_supported=true`와 성공/오류 redirect의
`iss`를 통해 고정 callback `https://chatgpt.com/connector_platform_oauth_redirect`를
지원합니다. 화면에 다른 callback이 표시되면 **그 정확한 URL을 확인하여** allowlist에
추가하세요. wildcard로 완화하지 마세요. Claude 등 다른 OAuth 클라이언트는 DCR,
resource parameter 및 정확한 HTTPS callback이 필요합니다. 기본값은 ChatGPT만
허용하며, 다른 vendor의 실제 UI 연결은 검증하지 않았습니다.

OAuth 활성화 후 공개 endpoint(아래 경로 앞에 `https://media.baecha.xyz`):

| Method | 경로 | 역할 |
|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | issuer/auth/token/register/revoke/PKCE/scopes metadata |
| GET | `/.well-known/oauth-protected-resource/mcp` | canonical resource `/mcp`, AS URL |
| GET | `/.well-known/oauth-protected-resource` | 동일 protected resource metadata 별칭 |
| GET, POST | `/authorize` | 검증 후 owner 승인 화면으로 이동 |
| GET, POST | `/oauth/consent` | owner 인증/승인/거절 |
| POST | `/register` | 제한된 DCR, JSON 요청 |
| POST | `/token` | code 교환 또는 refresh, form-urlencoded |
| POST | `/revoke` | 해당 client의 token family 폐기, form-urlencoded |

Token endpoint 인증은 `none`, `client_secret_post`, `client_secret_basic`을 지원합니다.
`resource`는 authorization/code 교환/refresh에서 정확히
`https://media.baecha.xyz/mcp`여야 합니다. 잘못된 resource는 `invalid_target`,
잘못된 code/verifier/만료 token은 `invalid_grant`, client 인증 실패는
HTTP 401 `invalid_client`로 응답합니다. credential 중복과 혼합은 거절합니다.

### 필요한 환경변수

기존 설정/API key를 유지한 채 아래 값을 외부 `~/.config/media-mcp/server.env`에
추가합니다. [안전한 설정 스크립트](scripts/configure_oauth.py)는 새 owner 비밀번호를
숨김 입력받고 hash와 암호화 key를 로컬에서 생성해 추가합니다. 기존 OAuth 값이 있으면
덮어쓰지 않고 종료하며, 기존 환경파일 전체의 mode-600 백업을 같은 폴더에 만듭니다.
이 백업에도 기존 API key가 있으므로 환경파일과 동일하게 보호하세요.

| 변수 (`MEDIA_MCP_` 접두사) | 의미/기본값 |
|---|---|
| `OWNER_PASSWORD_HASH` | 필수: salted scrypt hash, 스크립트에서 생성; raw password는 저장하지 않음 |
| `OAUTH_STORAGE_KEY` | 필수: Fernet 암호화 key, 스크립트에서 CSPRNG로 생성 |
| `PUBLIC_BASE_URL` | 기존 값 유지: `https://media.baecha.xyz`; issuer와 resource 생성에 사용 |
| `OAUTH_REDIRECT_URIS` | 쉼표로 구분한 정확한 HTTPS callback, 기본 ChatGPT 고정 callback |
| `OAUTH_PERSISTENT_GRANTS` | 0; 1이면 새 승인 및 클라이언트에 자동 만료 없음 |
| `OAUTH_ACCESS_TTL` | 900초, 최대 3600초 |
| `OAUTH_REFRESH_TTL` | 2592000초(30일), 최대 90일; refresh로 연장되지 않음 |
| `OAUTH_CODE_TTL` | 120초, 최대 300초; single-use |
| `OAUTH_STORE_DIR` | 기본 `TEMP_DIR/oauth-v1`; 기존 unit writable 경로 안에 유지 |

두 secret 설정이 없으면 기존 API-key 전용 모드입니다. 하나만 설정하거나 유효하지
않은 값을 넣으면 startup이 실패합니다. owner password는 16–1024자로 설정하고
비밀번호 관리자에 보관하세요. 서버에는 `MEDIA_MCP_OWNER_PASSWORD` 평문 변수를
추가하지 않습니다. owner hash와 encryption key도 비밀로 보호합니다.

### ChatGPT에서 연결

1. 아래 deployment 절차로 설정 후 직접 서비스를 재시작하고 discovery를 확인합니다.
2. ChatGPT의 developer mode/custom app 생성 화면에서 **Create app**을 엽니다.
   화면 명칭과 접근 권한은 계정/workspace에 따라 다를 수 있습니다.
3. Name: `media-mcp`, MCP Server URL: **`https://media.baecha.xyz/mcp`**,
   Authentication: **OAuth**, 등록 방식 선택이 보이면 **Dynamic Client Registration**.
   Client ID/Secret은 DCR이 생성하므로 수동 값을 넣지 않습니다.
4. Scope 입력란이 있다면 `media:read offline_access`를 사용합니다. `offline_access`는
   AS metadata에도 광고합니다. 이를 요청하지 않은 client에는 refresh를 발급하지 않습니다.
5. 연결을 시작하면 `media.baecha.xyz`의 승인 화면에서 client ID/callback/scopes를
   확인하고 owner 비밀번호로 승인합니다. 방금 본인이 시작한 연결만 승인하세요.
6. 연결 후 tool scan에서 `extract_media`, `prepare_media`를 확인합니다.
   access token은 `/mcp` 요청마다 검증됩니다. OAuth token으로 HTTP `/extract`나
   `/prepare`를 호출할 수는 없습니다. 이 두 경로는 기존 API key 전용입니다.

### 승인과 token lifecycle

- 로그인 세션/계정 DB를 만들지 않습니다. 등록만으로 code나 token을 얻을 수 없습니다.
  매 authorization마다 비밀번호와 명시적 승인이 필요합니다. DCR client 이름은
  누구나 선택할 수 있어 UI에서 신뢰되지 않은 이름임을 표시하고 HTML을 escape합니다.
- 승인 요청은 5분 TTL, cookie/CSRF nonce는 무작위입니다. HTTPS cookie는
  `__Host-`, Secure, HttpOnly, SameSite=Lax이며 POST Origin과 hidden CSRF를 검사합니다.
  state는 필수이고 제한된 ASCII/길이를 검증해 성공/오류 callback으로 돌려보냅니다.
  client는 본인이 생성한 state와 `iss`를 검증해야 합니다. code 발급 자체도 single-use입니다.
- Code/access/refresh는 256-bit 무작위 opaque 값이며 DB lookup에는 SHA-256 digest만
  저장합니다. Client secret과 승인 metadata는 Fernet으로 암호화한 SQLite에 저장합니다.
  디렉터리 700/DB 600, symlink 거절, 프로세스 lock, transaction을 적용합니다.
- Access token은 기본 15분, refresh family는 최초 승인부터 최대 30일입니다.
  Refresh는 회전하며 이전 access token도 폐기합니다. 사용한 refresh 재사용 시 family
  전체를 폐기합니다. `/revoke`도 해당 family 전체를 폐기합니다. Code 재사용이 보관기간
  안에 감지되면 해당 family를 폐기합니다. 만료된 code는 항상 거절합니다.
- 정상 재시작 후 OAuth grants는 유지됩니다. **임시 미디어 URL은 기존 설계대로
  재시작 시 무효화**됩니다. owner hash 또는 issuer를 변경하면 다음 startup에서 모든
  OAuth 등록/승인을 폐기합니다. DB와 다른 encryption key는 자동 삭제 없이 startup을
  실패시킵니다. 기존 key를 복구하거나 운영자가 별도 초기화 계획을 세워야 합니다.
- API key의 정확한 값만 constant-time 비교로 기존 MCP credential로 인정합니다.
  OAuth 실패를 API key 성공으로 바꾸는 느슨한 fallback은 없습니다.

### OAuth troubleshooting / security limitations

- Discovery 401/404: 설정 미적용/미재시작 또는 OAuth 비활성 여부를 확인하세요.
  Issuer/resource/실제 callback은 trailing slash까지 일치해야 합니다.
- `invalid_redirect_uri`: ChatGPT 관리 화면의 정확한 callback과 allowlist를 비교하세요.
  UI가 CIMD를 강제하는 경우 이 서버의 DCR 경로를 선택할 수 있어야 합니다.
- `invalid_grant`: code 만료/재사용, verifier 오류, refresh 재사용/만료 가능성입니다.
  폐기된 family는 재연결해 owner 승인을 다시 받아야 합니다.
- 승인 403: cookie 또는 Origin/CSRF 누락, 잘못된 비밀번호를 확인하세요. 승인 화면을
  새로 열면 기존 화면의 nonce는 무효화됩니다. 동시에 여러 승인 탭을 열지 마세요.
- 429: 전역 분당 제한(DCR 10, authorize 60, token 120, revoke 60, consent 30,
  비밀번호 시도 5). 1분 뒤 다시 시도합니다. 전역 제한은 프록시 IP 신뢰를 피하지만
  공격자가 일시적으로 owner 연결을 방해할 수 있습니다. 등록 최대 64개/1년,
  pending 64개, DB record 약 4096개/페이지 최대 약 32MiB로 제한합니다.
  공개 DCR capacity 고갈에 대한 자동 신원 검증/관리 UI는 없습니다.
- 단일 사용자/단일 프로세스용입니다. MFA, 계정 복구, OIDC, Enterprise domain
  restrictions, CIMD/private_key_jwt, localhost callback은 제공하지 않습니다.
  다른 표준 클라이언트는 허용된 HTTPS callback으로 DCR을 지원해야 합니다.
- 암호화 key와 DB를 모두 읽을 수 있는 호스트 침해는 이 암호화로 방어하지 못합니다.
  Client secret은 SDK 호환을 위해 복호화 가능한 형태로 보관합니다.
- Access log는 기존대로 끕니다. Cloudflare/외부 로그 설정은 변경하지 않았습니다.
  OAuth query/body/header와 capability URL을 로그나 지원 요청에 붙여넣지 마세요.
- ChatGPT UI 로그인은 자동 조작하지 않았습니다. 로컬 공식 SDK 전체 OAuth flow 테스트는
  실제 ChatGPT 연결 성공을 보장하는 외부 UI 검증과 구별됩니다.

정확한 Pi 설정/재시작/외부 curl 검증 명령은
[deployment/README.md의 OAuth 활성화 절차](deployment/README.md#oauth-activation-existing-production)를 참고하세요.

공식 근거: [OpenAI authentication](https://developers.openai.com/plugins/build/auth),
[MCP authorization 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

## Security and errors

- 입력은 정해진 Instagram/YouTube URL만 허용합니다. CDN URL 직접 입력은 거절합니다.
- worker 내부 URL도 공식 source host와 명시된 CDN suffix로 제한합니다.
  `network.py`에 목록이 있으며, localhost/private/link-local/metadata IP/내부 IPv6,
  IP literal URL, 비 HTTPS 전송 및 redirect를 차단합니다.
- 공인 DNS 응답을 검증한 숫자 주소로 연결해 재해석 단계의 DNS rebinding을 방지합니다.
  전송 adapter 설정은 별도 worker에 격리되어 기존 CLI/파서를 변경하지 않습니다.
- API/MCP는 constant-time Bearer 비교, Host/Origin 검증을 공유합니다.
- 파일은 서버 소유 mode-700 폴더에만 생성하고 GET은 token table로 조회합니다.
  경로를 사용자에게서 받지 않으며 symlink/open-no-follow 검증을 합니다.
- 파일 byte signature로 MIME을 확인합니다. HTML/SVG를 media로 서빙하지 않습니다.
- journal 로그에는 operation/error code/exception type만 남깁니다. signed URL,
  cookie, API key, token URL을 기록하지 않도록 Uvicorn access log를 비활성화했습니다.

HTTP 오류는 `{"error":{"code":"...","message":"..."}}`입니다.
`unsupported_url` 400, `login_required` 403, `not_found` 404,
`rate_limited`/`busy` 429, `limit_exceeded` 413, `timeout` 504,
`capacity` 507, `extraction_failed`/`download_failed` 502,
미존재/만료 토큰 `media_not_found` 404. JSON validation은 422입니다.
원본 traceback은 API에 노출하지 않습니다.

## Remaining limitations

- Instagram 비공식 HTML/GraphQL은 바뀔 수 있습니다. 공개 HTML이 현재 성공 경로이며
  구형 GraphQL fallback은 환경에 따라 차단됩니다.
- 단일 이미지/혼합 carousel은 fixture 검증, 쿠키 인증은 mock 검증입니다.
- YouTube metadata는 live 검증했지만 영상 bytes 다운로드는 미검증입니다.
  큰 파일/manifest-only 결과는 제한에 따라 실패하며 HLS/DASH 조립은 지원하지 않습니다.
- 쿠키는 `MEDIA_MCP_COOKIE_FILE`로 선택 적용합니다. yt-dlp가 갱신할 수 있으므로
  전용 복사본을 사용하세요. 인증이 없거나 게시물/차단 응답이 모호하면 정확한
  private/deleted 구분이 불가능할 수 있습니다.
- byte-range seeking, 오디오 분리/프레임 생성, 영구 미디어 캐시, 다중 사용자 권한은 미구현입니다.
- 프로세스 SIGKILL 후 잔여 파일은 다음 시작 때 정리됩니다. 프로세스 주소 공간 제한은
  메모리 사용을 제한하지만 OS 수준 전체 자원 한도는 제공한 systemd unit도 적용하세요.

원래 CLI는 그대로 사용할 수 있습니다:

```bash
.venv/bin/python -m media_mcp 'https://www.instagram.com/p/DdEZgWTlGfB/' --download-check
```

공식 문서: [MCP ASGI 연결](https://py.sdk.modelcontextprotocol.io/run/asgi/),
[MCP transport](https://py.sdk.modelcontextprotocol.io/run/).

### 만료 없는 ChatGPT 연결

`MEDIA_MCP_OAUTH_PERSISTENT_GRANTS=1`로 설정하고 승인된 서비스 재시작 후
ChatGPT 연결을 새로 등록·승인하면 access token은 `expires_in` 없이 발급됩니다.
새 client 및 grant도 자동 만료되지 않습니다. 기본값 0은 기존 TTL 정책입니다.
기존 연결의 만료를 소급 연장하거나 만료·폐기된 토큰을 복구하지 않으므로 새 연결이 필요합니다.
이 설정은 ChatGPT 계정 로그인이나 ChatGPT 측 연결 정책을 변경하지 않습니다.
토큰은 폐기할 때까지 유효하므로 노출 시 `/revoke`로 폐기하세요.
소유자 인증 변경, refresh 재사용 탐지, PKCE, 승인 및 기존 API-key 검증은 유지됩니다.
