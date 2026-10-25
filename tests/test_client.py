import asyncio
import base64
import hashlib
import hmac
import json
import stat
import time
from urllib.parse import parse_qs

import httpx
import pytest

from douban_mcp.client import FrodoClient, FrodoError, segment, signature
from douban_mcp.config import Settings
from douban_mcp.state import StateError, StateStore


def make_client(tmp_path, handler):
    return FrodoClient(
        Settings(state_dir=tmp_path, request_interval=0), transport=httpx.MockTransport(handler)
    )


def signed_request(request, token=""):
    values = (
        dict(request.url.params)
        if request.method == "GET"
        else {
            k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()
        }
    )
    assert values["apikey"] == Settings().api_key
    assert values["_sig"] == signature(
        request.method, request.url.path, values["_ts"], Settings().api_secret, token
    )
    if token:
        assert request.headers["Authorization"] == "Bearer " + token
    else:
        assert "Authorization" not in request.headers
    return values


@pytest.mark.parametrize("method,token", [("GET", ""), ("GET", "token"), ("POST", "token")])
def test_signature_vectors(method, token):
    parts = [method, "%2Fapi%2Fv2%2Fmovie%2F3541415"] + ([token] if token else []) + ["1700000000"]
    expected = base64.b64encode(
        hmac.new(b"secret", "&".join(parts).encode(), hashlib.sha1).digest()
    ).decode()
    assert signature(method, "/api/v2/movie/3541415", "1700000000", "secret", token) == expected


@pytest.mark.parametrize("value", ["../me", "x?token=y", "a/b", "https://example.com", "", "x#f"])
def test_path_injection_rejected(value):
    with pytest.raises(FrodoError):
        segment(value)


async def test_anonymous_query_and_unicode(tmp_path):
    def handler(request):
        signed_request(request)
        assert request.url.params["q"] == "三体"
        assert "status" not in request.url.params
        return httpx.Response(200, json={"items": []})

    client = make_client(tmp_path, handler)
    try:
        assert await client.get("/api/v2/search/book", params={"q": "三体", "status": None}) == {
            "items": []
        }
    finally:
        await client.close()


async def test_login_refresh_restart_logout(tmp_path):
    calls = []

    def handler(request):
        form = signed_request(request)
        calls.append(form)
        assert request.url.path == "/service/auth2/token"
        assert not request.url.query  # secrets and POST signature are form-only
        assert form["redirect_uri"] == "frodo://app/oauth/callback/"
        assert form["disable_account_create"] == "false"
        if form["grant_type"] == "password":
            assert form["password"] == "private-password"
            return httpx.Response(
                200,
                json={
                    "access_token": "first",
                    "refresh_token": "refresh1",
                    "expires_in": 3600,
                    "douban_user_id": "123",
                },
            )
        assert form["refresh_token"] == "refresh1"
        return httpx.Response(
            200, json={"access_token": "second", "refresh_token": "refresh2", "expires_in": 3600}
        )

    client = make_client(tmp_path, handler)
    try:
        result = await client.login("test@example.com", "private-password")
        assert result["authenticated"] and result["user_id"] == "123"
        assert "first" not in json.dumps(result)
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        assert stat.S_IMODE((tmp_path / "credentials.json").stat().st_mode) == 0o600
        assert "private-password" not in (tmp_path / "credentials.json").read_text()
        await client.refresh()
    finally:
        await client.close()
    restarted = make_client(tmp_path, handler)
    try:
        assert restarted.auth_status()["user_id"] == "123"
        assert restarted.store.read("credentials.json")["access_token"] == "second"
        assert calls[0]["udid"] == calls[1]["udid"]
        await restarted.logout()
        assert not restarted.auth_status()["authenticated"]
        assert (tmp_path / "device.json").exists()
    finally:
        await restarted.close()


async def test_token_import_verifies_before_replacing(tmp_path):
    def handler(request):
        signed_request(request, "candidate")
        return httpx.Response(401, json={"code": 123, "msg": "invalid token candidate"})

    client = make_client(tmp_path, handler)
    client.store.write("credentials.json", {"access_token": "existing"})
    try:
        with pytest.raises(FrodoError) as error:
            await client.import_token("candidate")
        assert "candidate" not in str(error.value)
        assert client.store.read("credentials.json")["access_token"] == "existing"
    finally:
        await client.close()


async def test_import_success(tmp_path):
    client = make_client(tmp_path, lambda _: httpx.Response(200, json={"id": "456"}))
    try:
        result = await client.import_token("new", "refresh", 3600)
        assert result["user_id"] == "456"
        assert "new" not in json.dumps(result)
        assert client.auth_status()["can_refresh"]
    finally:
        await client.close()


async def test_expired_token_refresh_once_under_concurrency(tmp_path):
    refreshes = []

    def handler(request):
        if request.method == "POST":
            refreshes.append(request)
            return httpx.Response(200, json={"access_token": "fresh", "expires_in": 3600})
        signed_request(request, "fresh")
        return httpx.Response(200, json={"id": "123"})

    client = make_client(tmp_path, handler)
    client.store.write(
        "credentials.json",
        {"access_token": "expired", "refresh_token": "refresh", "expires_at": time.time() - 1},
    )
    try:
        await asyncio.gather(*(client.get("/api/v2/user/me") for _ in range(3)))
        assert len(refreshes) == 1
        assert client.store.read("credentials.json")["refresh_token"] == "refresh"
    finally:
        await client.close()


async def test_no_auth_prevents_network_writes(tmp_path):
    calls = []
    client = make_client(tmp_path, lambda request: calls.append(request))
    try:
        with pytest.raises(FrodoError, match="Log in"):
            await client.set_interest("movie", "3541415", "done")
        with pytest.raises(FrodoError):
            await client.delete_interest("movie", "3541415")
        assert calls == []
    finally:
        await client.close()


@pytest.mark.parametrize("explicit", [False, True])
async def test_write_merges_or_clears_and_verifies(tmp_path, explicit):
    old = {
        "status": "mark",
        "rating": {"value": 4},
        "comment": "已有短评",
        "tags": ["科幻"],
        "is_private": True,
    }
    posts = []

    def handler(request):
        values = signed_request(request, "token")
        if request.method == "GET":
            return httpx.Response(200, json={"interest": old})
        assert request.url.path == "/api/v2/movie/3541415/done"
        assert values["share_to_douban"] == "0" and values["is_private"] == "1"
        assert values["rating"] == ("0" if explicit else "4")
        assert values["comment"] == ("" if explicit else "已有短评")
        assert values["tags"] == ("" if explicit else "科幻")
        old.update(
            status="done",
            rating={"value": int(values["rating"])},
            comment=values["comment"],
            tags=values["tags"].split(),
        )
        posts.append(request)
        return httpx.Response(200, json={"interest": old})

    client = make_client(tmp_path, handler)
    client.store.write("credentials.json", {"access_token": "token"})
    try:
        kwargs = {"rating": 0, "comment": "", "tags": []} if explicit else {}
        result = await client.set_interest("movie", "3541415", "done", **kwargs)
        assert result["submitted"] and result["verified"]
        assert len(posts) == 1
    finally:
        await client.close()


async def test_delete_uses_post_unmark_and_verifies(tmp_path):
    calls = []

    def handler(request):
        signed_request(request, "token")
        calls.append((request.method, request.url.path))
        return httpx.Response(200, json={"interest": None})

    client = make_client(tmp_path, handler)
    client.store.write("credentials.json", {"access_token": "token"})
    try:
        result = await client.delete_interest("book", "2567698")
        assert result["verified"]
        assert calls == [("POST", "/api/v2/book/2567698/unmark"), ("GET", "/api/v2/book/2567698")]
    finally:
        await client.close()


async def test_write_timeout_not_retried(tmp_path):
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json={"interest": None})
        raise httpx.ReadTimeout("secret URL and token")

    client = make_client(tmp_path, handler)
    client.store.write("credentials.json", {"access_token": "token"})
    try:
        with pytest.raises(FrodoError) as error:
            await client.set_interest("movie", "1", "done")
        assert error.value.outcome_unknown
        assert "secret URL" not in str(error.value)
        assert calls == ["GET", "POST"]
    finally:
        await client.close()


@pytest.mark.parametrize(
    "status,payload,code",
    [
        (403, {"code": 100, "msg": "need_login"}, "100"),
        (200, {"error": "invalid_grant", "error_description": "bad login"}, "invalid_grant"),
        (429, {"msg": "rate limited"}, "http_error"),
        (302, {}, "http_error"),
    ],
)
async def test_api_errors_and_redirects(tmp_path, status, payload, code):
    client = make_client(tmp_path, lambda _: httpx.Response(status, json=payload))
    try:
        with pytest.raises(FrodoError) as error:
            await client.get("/api/v2/user/me")
        assert error.value.code == code
    finally:
        await client.close()


async def test_error_redacts_password_before_truncation(tmp_path):
    password = "sensitive" * 100
    client = make_client(
        tmp_path, lambda _: httpx.Response(403, json={"msg": password, "code": 120})
    )
    try:
        with pytest.raises(FrodoError) as error:
            await client.login("private@example.com", password)
        assert error.value.message == "[redacted]"
    finally:
        await client.close()


def test_state_corruption_and_symlinks(tmp_path):
    store = StateStore(tmp_path)
    store.write("credentials.json", {})
    (tmp_path / "credentials.json").write_text("bad json")
    with pytest.raises(StateError):
        store.read("credentials.json")
    (tmp_path / "credentials.json").unlink()
    (tmp_path / "credentials.json").symlink_to(tmp_path / "another")
    with pytest.raises(OSError):
        store.read("credentials.json")


def test_state_lock_contention(tmp_path):
    first, second = StateStore(tmp_path), StateStore(tmp_path)
    with first.locked(), pytest.raises(StateError, match="busy"), second.locked():
        pass


@pytest.mark.parametrize("verification_fails", [False, True])
async def test_write_reports_unverified_without_repeating(tmp_path, verification_fails):
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.method == "POST":
            return httpx.Response(200, json={"ok": True})
        if len(calls) == 3 and verification_fails:
            raise httpx.ReadTimeout("readback failed")
        # A 200 response may still ignore a submitted comment/status.
        return httpx.Response(200, json={"interest": None})

    client = make_client(tmp_path, handler)
    client.store.write("credentials.json", {"access_token": "token"})
    try:
        result = await client.set_interest("movie", "1", "done", comment="new")
        assert result["submitted"] and not result["verified"]
        assert calls == ["GET", "POST", "GET"]
    finally:
        await client.close()


async def test_unexpected_subject_schema_aborts_update(tmp_path):
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(200, json={"title": "missing interest"})

    client = make_client(tmp_path, handler)
    client.store.write("credentials.json", {"access_token": "token"})
    try:
        with pytest.raises(FrodoError, match="update stopped"):
            await client.set_interest("movie", "1", "done")
        assert calls == ["GET"]
    finally:
        await client.close()
