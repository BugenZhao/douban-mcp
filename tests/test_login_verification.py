"""Protocol fixtures from the Doubean 0.13.2 account verification flow."""

import json
import stat
import time
from urllib.parse import parse_qs

import httpx
import pytest

from douban_mcp import __main__ as cli
from douban_mcp.client import FrodoClient, FrodoError
from douban_mcp.config import Settings
from douban_mcp.server import create_server

PASSWORD = "test-password-never-output"
ACCESS = "test-access-never-output"
REFRESH = "test-refresh-never-output"
SMS = "4821"


class PhoneFlow:
    def __init__(self):
        self.requests = []
        self.sms_requests = 0
        self.verifications = 0
        self.send_result = {"status": "success", "payload": {}}
        self.verify_result = {
            "status": "success",
            "payload": {
                "access_token": ACCESS,
                "refresh_token": REFRESH,
                "douban_user_id": "123",
                "expires_in": 3600,
            },
        }
        self.solution = "douban://douban.com/account/login_verify_phone?user_id=123"
        self.redirect = "https://accounts.douban.com/passport/verify_phone?user_id=123&dark_mode=0"
        self.device = None
        self.error_code = 9000

    def __call__(self, request):
        self.requests.append(request)
        path = request.url.path
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        assert "Authorization" not in request.headers
        if path == "/service/auth2/token":
            assert request.url.host == "frodo.douban.com"
            assert form["password"] == PASSWORD
            self.device = form["device_id"]
            return httpx.Response(
                400,
                json={
                    "code": self.error_code,
                    "localized_message": "已开启账号保护，新设备请验证手机号",
                    "extra": {"solution_uri": self.solution},
                },
                headers={
                    "set-cookie": "verification_session=private-cookie; Domain=.douban.com; Path=/; Secure"
                },
            )
        assert request.url.host in {"www.douban.com", "accounts.douban.com"}
        assert "udid/" + self.device in request.headers["user-agent"]
        assert "DoubanApp" in request.headers["user-agent"]
        assert "verification_session=private-cookie" in request.headers["cookie"]
        assert PASSWORD not in str(request.url) + request.content.decode()
        if path == "/accounts/auth2_redir":
            assert request.method == "GET"
            assert request.url.params["url"].startswith(
                "https://accounts.douban.com/passport/verify_phone?"
            )
            return httpx.Response(302, headers={"location": self.redirect})
        if path == "/passport/verify_phone":
            return httpx.Response(
                200,
                text="<html></html>",
                headers={"set-cookie": "verify_page=private-page-cookie; Path=/; Secure"},
            )
        assert request.method == "POST"
        assert request.headers["origin"] == "https://accounts.douban.com"
        assert request.headers["x-requested-with"] == "com.douban.frodo"
        assert "verify_page=private-page-cookie" in request.headers["cookie"]
        assert form["user_id"] == "123"
        assert not request.url.query
        if path == "/j/app/verify_phone/request_phone_code":
            self.sms_requests += 1
            assert form == {"user_id": "123", "apikey": Settings().api_key}
            return httpx.Response(200, json=self.send_result)
        assert path == "/j/app/verify_phone/verify_phone_code"
        self.verifications += 1
        assert form == {"user_id": "123", "client_id": Settings().api_key, "phone_code": SMS}
        return httpx.Response(200, json=self.verify_result)


@pytest.fixture
async def flow_client(tmp_path):
    flow = PhoneFlow()
    client = FrodoClient(
        Settings(state_dir=tmp_path, request_interval=0), transport=httpx.MockTransport(flow)
    )
    yield flow, client
    await client.close()


async def test_two_step_login_keeps_only_token_on_disk(flow_client, tmp_path):
    flow, client = flow_client
    challenge = await client.login("example@example.invalid", PASSWORD)
    assert challenge["verification_required"] and challenge["sms_sent"]
    assert not (tmp_path / "credentials.json").exists()
    assert {p.name for p in tmp_path.iterdir()} == {".lock", "device.json"}
    result = await client.login(challenge_id=challenge["challenge_id"], sms_code=SMS)
    assert result["authenticated"] and result["user_id"] == "123"
    for secret in (PASSWORD, ACCESS, REFRESH, SMS, "private-cookie"):
        assert secret not in json.dumps([challenge, result])
    state = json.loads((tmp_path / "credentials.json").read_text())
    assert state["access_token"] == ACCESS and state["refresh_token"] == REFRESH
    assert stat.S_IMODE((tmp_path / "credentials.json").stat().st_mode) == 0o600
    assert PASSWORD not in (tmp_path / "credentials.json").read_text()
    assert flow.sms_requests == flow.verifications == 1
    assert not client._pending_login and not client._accounts.cookies
    with pytest.raises(FrodoError, match="验证会话已失效"):
        await client.login(challenge_id=challenge["challenge_id"], sms_code=SMS)
    assert flow.verifications == 1


async def test_wrong_code_retries_without_resending_and_preserves_existing_login(flow_client):
    flow, client = flow_client
    client.store.write("credentials.json", {"access_token": "existing"})
    challenge = await client.login("example@example.invalid", PASSWORD)
    good_result = flow.verify_result
    flow.verify_result = {"status": "failed", "message": SMS + PASSWORD + ACCESS}
    with pytest.raises(FrodoError) as error:
        await client.login(challenge_id=challenge["challenge_id"], sms_code=SMS)
    assert error.value.code == "sms_verification_failed"
    assert all(s not in json.dumps(error.value.as_dict()) for s in (SMS, PASSWORD, ACCESS))
    assert client.store.read("credentials.json")["access_token"] == "existing"
    flow.verify_result = good_result
    assert (await client.login(challenge_id=challenge["challenge_id"], sms_code=SMS))[
        "authenticated"
    ]
    assert flow.sms_requests == 1 and flow.verifications == 2


@pytest.mark.parametrize(
    "reason", ["expired", "unknown", "device_changed", "restart", "logout", "new_login"]
)
async def test_stale_challenge_never_submits_sms(flow_client, reason):
    flow, client = flow_client
    challenge = await client.login("example@example.invalid", PASSWORD)
    if reason == "expired":
        client._pending_login["expires_at"] = time.time() - 1
    elif reason == "unknown":
        challenge["challenge_id"] = "bad"
    elif reason == "device_changed":
        client.store.write("device.json", {"device_id": "a" * 40})
    elif reason == "restart":
        client._clear_login_challenge()
    elif reason == "logout":
        await client.logout()
    else:
        await client.login("example@example.invalid", PASSWORD)
    with pytest.raises(FrodoError) as error:
        await client.login(challenge_id=challenge["challenge_id"], sms_code=SMS)
    assert error.value.code == "login_challenge_expired"
    assert flow.verifications == 0


@pytest.mark.parametrize(
    "solution",
    [
        None,
        "https://evil.invalid/?user_id=123",
        "douban://[",
        "douban://douban.com/account/login_verify_phone?user_id=123&user_id=456",
        "douban://douban.com/account/login_verify_phone?user_id=../123",
    ],
)
async def test_missing_or_untrusted_context_cannot_send_sms(flow_client, solution):
    flow, client = flow_client
    flow.solution = solution
    with pytest.raises(FrodoError) as error:
        await client.login("example@example.invalid", PASSWORD)
    assert error.value.code == "verification_context_missing"
    assert len(flow.requests) == 1


@pytest.mark.parametrize(
    "result,code",
    [
        (
            {"status": "failed", "message": "captcha_required", "payload": {"tc_app_id": "123"}},
            "captcha_required",
        ),
        ({"status": "failed", "message": PASSWORD + ACCESS}, "sms_send_failed"),
    ],
)
async def test_sms_failure_does_not_claim_code_was_sent(flow_client, result, code):
    flow, client = flow_client
    flow.send_result = result
    with pytest.raises(FrodoError) as error:
        await client.login("example@example.invalid", PASSWORD)
    assert error.value.code == code
    assert PASSWORD not in str(error.value) and ACCESS not in str(error.value)
    assert client._pending_login is None
    assert flow.sms_requests == 1


async def test_redirect_is_checked_before_request(flow_client):
    flow, client = flow_client
    flow.redirect = "https://evil.invalid/collect?secret=example"
    with pytest.raises(FrodoError) as error:
        await client.login("example@example.invalid", PASSWORD)
    assert error.value.code == "verification_redirect"
    assert len(flow.requests) == 2


async def test_bad_password_does_not_send_sms(flow_client):
    flow, client = flow_client
    flow.error_code = 101
    with pytest.raises(FrodoError) as error:
        await client.login("example@example.invalid", PASSWORD)
    assert error.value.code == "101"
    assert len(flow.requests) == 1


async def test_local_code_validation_and_attempt_limit(flow_client):
    flow, client = flow_client
    challenge = await client.login("example@example.invalid", PASSWORD)
    with pytest.raises(FrodoError) as error:
        await client.login(challenge_id=challenge["challenge_id"], sms_code="xx")
    assert error.value.code == "invalid_sms_code" and flow.verifications == 0
    flow.verify_result = {"status": "failed", "message": "invalid_code"}
    for _ in range(5):
        with pytest.raises(FrodoError):
            await client.login(challenge_id=challenge["challenge_id"], sms_code=SMS)
    assert client._pending_login is None and flow.sms_requests == 1


async def test_mcp_two_step_flow_and_discovery(flow_client):
    _flow, client = flow_client
    server = create_server(client)
    tools = {t.name: t for t in await server.list_tools()}
    schema = tools["douban_login"].inputSchema
    assert "challenge_id" in schema["properties"] and "sms_code" in schema["properties"]
    assert not schema.get("required")
    first = await server.call_tool(
        "douban_login", {"username": "example@example.invalid", "password": PASSWORD}
    )
    challenge = json.loads(first[0].text)
    assert challenge["verification_required"]
    second = await server.call_tool(
        "douban_login", {"challenge_id": challenge["challenge_id"], "sms_code": SMS}
    )
    assert json.loads(second[0].text)["authenticated"]
    assert all(secret not in str(second) for secret in (ACCESS, REFRESH, PASSWORD))


async def test_cli_prompts_and_retries_code_without_repeating_password(
    flow_client, monkeypatch, capsys
):
    flow, client = flow_client
    monkeypatch.setattr(cli, "FrodoClient", lambda settings: client)
    monkeypatch.setattr("builtins.input", lambda prompt: "example@example.invalid")
    prompts = []
    values = iter([PASSWORD, "bad-code", SMS])

    def secret_input(prompt):
        prompts.append(prompt)
        return next(values)

    monkeypatch.setattr(cli.getpass, "getpass", secret_input)
    await cli.auth_command("login")
    captured = capsys.readouterr()
    assert json.loads(captured.out)["authenticated"]
    assert prompts == ["密码: ", "短信验证码: ", "短信验证码: "]
    assert all(
        secret not in captured.out + captured.err for secret in (PASSWORD, ACCESS, REFRESH, SMS)
    )
    assert flow.sms_requests == flow.verifications == 1


@pytest.mark.parametrize("phase", ["send", "verify"])
async def test_timeout_is_redacted_and_never_retried(tmp_path, phase):
    flow = PhoneFlow()
    calls = 0

    def handler(request):
        nonlocal calls
        target = "request_phone_code" if phase == "send" else "verify_phone_code"
        if request.url.path.endswith("/" + target):
            calls += 1
            raise httpx.ReadTimeout(PASSWORD + ACCESS + SMS, request=request)
        return flow(request)

    client = FrodoClient(
        Settings(state_dir=tmp_path, request_interval=0), transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(FrodoError) as error:
            challenge = await client.login("example@example.invalid", PASSWORD)
            await client.login(challenge_id=challenge["challenge_id"], sms_code=SMS)
        assert error.value.code == "verification_network_error"
        assert error.value.outcome_unknown
        assert all(s not in str(error.value) for s in (PASSWORD, ACCESS, SMS))
        assert calls == 1 and not (tmp_path / "credentials.json").exists()
    finally:
        await client.close()


@pytest.mark.parametrize("payload", [{}, {"access_token": ACCESS, "douban_user_id": "456"}])
async def test_invalid_token_response_preserves_credentials(flow_client, payload):
    flow, client = flow_client
    client.store.write("credentials.json", {"access_token": "existing"})
    challenge = await client.login("example@example.invalid", PASSWORD)
    flow.verify_result = {"status": "success", "payload": payload}
    with pytest.raises(FrodoError) as error:
        await client.login(challenge_id=challenge["challenge_id"], sms_code=SMS)
    assert error.value.code == "invalid_token_response"
    assert client.store.read("credentials.json")["access_token"] == "existing"


async def test_cli_server_failure_stops_without_automatic_retry(tmp_path, monkeypatch, capsys):
    flow = PhoneFlow()
    calls = 0

    def handler(request):
        nonlocal calls
        if request.url.path.endswith("/verify_phone_code"):
            calls += 1
            return httpx.Response(500, json={"status": "failed", "message": ACCESS})
        return flow(request)

    client = FrodoClient(
        Settings(state_dir=tmp_path, request_interval=0), transport=httpx.MockTransport(handler)
    )
    monkeypatch.setattr(cli, "FrodoClient", lambda settings: client)
    monkeypatch.setattr("builtins.input", lambda prompt: "example@example.invalid")
    values = iter([PASSWORD, SMS])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(values))
    with pytest.raises(FrodoError) as error:
        await cli.auth_command("login")
    assert error.value.code == "verification_http_error"
    assert error.value.outcome_unknown and calls == 1
    assert ACCESS not in capsys.readouterr().out
