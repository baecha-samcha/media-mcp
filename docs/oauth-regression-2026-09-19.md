# OAuth regression investigation — 2026-09-19

## 조사 범위와 확인된 운영 상태

운영 SQLite는 `mode=ro`로 열었으며 OAuthStore.start/cleanup을 호출하지 않았다.
실행 중인 media-mcp 프로세스의 환경에서 storage key만 메모리로 가져와 Fernet을
복호화했다. 환경 파일, token/code/secret/state/request_id, lookup digest 및 client ID는
출력하지 않았다. `meta.expires=2**62`는 날짜로 변환하지 않고 무기한 sentinel로 처리했다.
서비스 재시작, 설정 변경, grant 삭제, 운영 token 교환은 수행하지 않았다.

| kind | 개수 | 확인 결과 (KST) |
| --- | ---: | --- |
| client | 1 | 2026-09-16 22:21:45 등록, 2027-09-16 만료, auth method=none, 등록 scope=media:read offline_access, authorization_code/refresh_token 지원 |
| family | 1 | 2026-09-16 23:06:05 기록, 2026-10-16 23:06:05 만료, revoked=false, generation 필드 없음(기존 코드의 유효 값=0) |
| refresh | 0 | used=true/false를 확인할 행 자체가 없음 |
| access | 0 | 만료된 access는 cleanup으로 삭제됨 |
| code | 0 | code는 120초 후 cleanup 대상이므로 현재 행 부재만으로 교환 실패를 판단할 수 없음 |
| pending | 0 | pending은 300초 후 cleanup 대상 |
| meta | 1 | 마지막 암호화 기록 2026-09-16 23:05:30, 무기한 sentinel |

실행 프로세스 설정 TTL은 access=900, refresh=2592000, code=120초였다.
Fernet timestamp는 해당 암호화 payload 작성 시각이며 일반적으로 최초 생성 시각과
같다고 단정할 수 없다. 여기서는 family에 generation 변경이 없어 최초 생성과 일치하는
것으로 해석했다.

## 원인과 확실성

1. **갱신 불가능한 최초 grant: scope discovery 불일치.** 기존 `/mcp` 401 challenge는
   `scope="media:read"`, protected-resource metadata도 `scopes_supported=["media:read"]`였다.
   AS metadata/DCR 등록은 offline_access를 포함하지만 등록 scope와 실제 승인 scope는
   다르다. SDK AuthorizationHandler는 요청된 scope를 AuthorizationParams/code로 전달하고,
   서버 issue()는 승인 scope에 offline_access가 있을 때만 refresh를 만든다.
   따라서 challenge를 따르는 클라이언트는 15분 access만 받는다. 이 flow를 실행하고
   3일 후 cleanup하면 실제 DB와 같은 client/family/meta만 남는 상태를 재현했다.

   family는 code 교환 트랜잭션에서만 생성되므로 **9/16 23:06:05 code 교환 성공**은
   확인된다. 사용된 refresh도 family 만료까지 보관되며, reuse revoke는 행을 삭제하지
   않는다. 현재 family가 유효하고 refresh가 0개인 것은 **현재 코드와 외부 변경이
   없었다는 전제에서 refresh 미발급**을 가리킨다. generation=0/revoked=false는 rotation
   성공이나 reuse revocation 가설을 지지하지 않는다. 당시 scope/발급 로그가 없으므로
   ChatGPT의 실제 authorize 요청 내용이나 과거 수동 DB 변경 가능성까지 증명하지는 못한다.
   “3일 TTL”은 없으며 15분 후 이미 갱신할 수 없던 연결을 3일 뒤 다시 사용했을 가능성이
   증거와 일치한다. 마지막 성공 사용 시각은 확인할 수 없다.

2. **완료된 consent의 중복 POST가 거부로 표시됨.** pending을 삭제하고 code를 만든 뒤
   303을 반환한다. 같은 POST가 다시 오면 pending 조회 실패로 403 access_denied가 된다.
   password 검증의 await 중 두 POST가 겹치면 트랜잭션 재검사에서 기존에는 400도 발생한다.
   두 경우 모두 테스트로 재현했다. 9/19 journal에는 22:44:52 성공→22:44:58 pending 거부,
   22:45:23 성공→22:45:24 pending 거부가 있다. 9/16에도 여러 승인 시도가 있다.
   그러나 기존 로그는 ticket을 구분하지 않으므로 이 쌍이 **동일 ticket이라는 사실이나
   브라우저 더블클릭/재전송/뒤로가기 중 어떤 동작인지** 확정할 수 없다.
   서버에는 consent POST를 자동 재시도하는 코드가 없으며 HTML form이 POST 진입점이다.
   303 생성은 브라우저 수신이나 ChatGPT callback 도착을 증명하지 않는다.
   9/19에 생성된 family가 없으므로 해당 날짜에 지속된 성공 code 교환 증거도 없다.

3. **별도의 잠재 버그: refresh 충돌이 family 전체를 폐기함.** 기존 load/exchange 두 곳에서
   used refresh를 보면 family를 revoke했다. 동시 요청에서 첫 요청의 성공 응답에 포함된
   새 access/refresh까지 두 번째 요청이 무효화할 수 있었다. 재현 테스트로 확인했지만
   운영 DB는 이 경로가 이번 사건의 원인이었다는 증거를 보이지 않는다.

즉 scope discovery, consent 중복 처리, refresh 충돌 처리는 서로 다른 문제다.
journal에서 POST, /token, refresh, invalid_grant, Traceback 키워드는 0건이었다.
서버는 access_log=False이고 이전 token 진단 로그가 없으므로 요청 부재의 증거는 아니다.

## 수정

- `media_mcp/api.py`: 401 challenge에 media:read offline_access를 안내한다. 403은 기존
  media:read 요구를 유지한다. MCP access 검증에 offline_access를 필수로 추가하지 않는다.
- `media_mcp/oauth.py`: PRM도 두 scope를 광고한다. 명시적으로 media:read만 승인한 grant에는
  계속 refresh를 발급하지 않는다. 승인 범위를 몰래 늘리지 않는다.
- consent 완료 시 browser/CSRF digest와 decision만 담은 암호화 receipt를 300초 보관한다.
  같은 binding의 중복 제출에는 200 완료 안내만 반환한다. callback/code/token/state를
  재전달하거나 새로 발급하지 않는다. 원래 pending과 code는 계속 single-use다.
  cookie는 원래의 짧은 TTL 동안 남겨 receipt binding에 사용한다. cookie 단독으로는
  승인할 수 없다. 만료, 다른 cookie/CSRF/decision/origin은 계속 거부한다.
- refresh는 used_at을 기록한다. 최초 사용 후 5초 미만의 중복은 invalid_grant로 거부하되
  성공한 rotation의 family를 폐기하지 않는다. **재사용 성공, successor 재전달, 추가 발급은
  없다.** 5초 이상 또는 legacy used_at 없는 used token은 family를 revoke한다. 재시도는
  이 기간을 연장하지 않는다. 5초는 프로토콜/ChatGPT 보장값이 아닌 명시적인 충돌 정책이다.
  탈취와 정상 충돌은 구별할 수 없으며, 이 기간에는 reuse에 대한 family 폐기만 유예된다.
  성공 응답 자체를 잃어버린 클라이언트를 복구하는 idempotent token 재발급은 구현하지 않는다.
- token endpoint에 grant/stage/outcome/status와 고정된 실패 reason을 기록한다. authorize에는
  offline_access 요청 여부, code 교환에는 refresh 발급 여부, rotation/revoke에는 고정 reason을
  남긴다. 향후 family에는 refresh_issued/generation도 기록한다. 기존 DB에 마이그레이션이나
  기존 grant 수정은 필요 없다. 요청 값이나 예외 본문은 로그에 넣지 않는다.

완료 안내는 중복 제출의 잘못된 access_denied 표시를 해소하지만, 최초 callback이 브라우저에서
차단/취소됐다면 연결 완료를 보장하지 않는다. 그 경우 ChatGPT에서 새 인증을 시작해야 한다.
refresh의 실패 요청을 받은 클라이언트가 스스로 연결을 지우는 동작까지 서버가 통제할 수 없다.

## 호환성 근거

설치된 MCP SDK는 2.2.0이다. `mcp/server/auth/handlers/authorize.py`와
`mcp/shared/auth.py::validate_scope`에서 승인 scope 전달을 확인했다.
`mcp/client/auth/utils.py::get_client_metadata_scopes`는 challenge→PRM→AS 순으로 선택하며,
이 버전은 AS가 offline_access와 refresh grant를 지원하면 scope를 보강한다. 따라서 현재
SDK 통합 테스트가 통과한 사실만으로 ChatGPT가 동일하게 보강한다고 판단할 수 없다.
SDK OAuthClientProvider는 인스턴스별 lock도 사용한다. 이것 역시 ChatGPT의 동시 요청
구현을 증명하지 않는다.

현재 OpenAI 공식 문서를 실제 조회했다:
https://developers.openai.com/plugins/build/auth

문서는 PRM scopes_supported, PKCE, token 교환 및 refresh/rotation을 설명하지만
ChatGPT의 중복 consent POST 원인이나 refresh 동시성/재시도 정책은 보장하지 않는다.
ChatGPT 내부 구현이나 브라우저 네트워크 trace는 이번 조사에서 확보하지 못했다.

## 검증과 명령

- 수정 전 `.venv/bin/python -m unittest discover -s tests -v`: 79개, 실패 0, live 2개 skip.
- 수정 전 소스를 별도 임시 디렉터리에 복사하고 새 핵심 회귀 테스트 4개 실행:
  discovery lifecycle, duplicate consent, concurrent consent, concurrent refresh **모두 실패**.
- 수정 후 동일 전체 명령: 89개, 실패 0, live 2개 skip (10.919초).
- `.venv/bin/python -m compileall -q media_mcp tests`: 통과.
- 최종 systemctl 확인: ActiveState=active, MainPID=276589, 시작 시각 9/16 23:05:27 유지.
- 최종 전체 테스트 출력: `/tmp/media-oauth-final-tests.log`.
- 추가 10개 테스트: discovery 기반 전체 lifecycle + 3일 경과 + 재시작,
  access-only 운영 DB 상태 재현, consent binding/expiry, concurrent consent,
  concurrent refresh, restart 후 collision deadline, credential 없는 로그,
  legacy used refresh, wrong-client replay, restart 후 consent receipt/code single-use.
- 기존 code replay/PKCE/CSRF/resource/client binding/refresh expiry/revocation 및 공식 SDK
  discovery→DCR→consent→PKCE→MCP→refresh 테스트도 함께 실행.
- 읽기 전용 조사: `systemctl show media-mcp --property=MainPID,FragmentPath,EnvironmentFiles`,
  `journalctl -u media-mcp --since 2026-09-16 -o json --no-pager`의 고정 메시지 필터,
  SQLite read-only 복호화 및 whitelist 필드 집계, `rg`/소스·SDK 확인.
- 원본 소스 백업: `/tmp/media-oauth-before-4lpw1ns4/`.

## 적용 및 사용자 조치

Python 프로세스에 변경을 적용하려면 **media-mcp 재시작이 필요**하다. 실행하지 않았다.
재시작은 현재 요청을 잠시 중단할 수 있으나 동일 설정/key/store로 기동하면 DB가 보존된다.
이번 조사 중 다른 운영 서비스는 변경하지 않았다. 패키지 설치도 없다.

현재 DB에 refresh가 없으므로 기존 연결의 token refresh만으로 복구할 수 없다.
배포 후 ChatGPT에서 새 인증/재연결을 통해 offline_access가 포함된 새 grant를 받아야 한다.
연결 삭제나 DB grant 삭제를 먼저 할 필요는 없다. ChatGPT가 기존 scope/연결 정보를 계속
사용해서 새 인증을 진행하지 못할 때만 UI의 제거 후 재연결을 고려한다. UI의 “Refresh”가
도구 목록 갱신인지 재인증인지 확인되지 않았으므로 그 버튼만으로 해결된다고 약속하지 않는다.
배포 후 안전한 새 로그에서 offline_access_requested=True, refresh_issued=True,
authorization_code 성공, access 만료 이후 refresh 성공 순서를 확인해야 한다.
실제 ChatGPT UI 및 운영 refresh 검증은 아직 수행하지 않았다.
