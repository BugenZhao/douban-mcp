import json
import os
import sys

import httpx
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp.exceptions import ToolError

from douban_mcp.client import FrodoClient
from douban_mcp.config import Settings
from douban_mcp.server import create_server


async def test_stdio_handshake_discovery_and_safe_calls(tmp_path):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "douban_mcp"],
        env={**os.environ, "DOUBAN_STATE_DIR": str(tmp_path)},
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        listed = await session.list_tools()
        tools = {t.name: t for t in listed.tools}
        assert len(tools) == 19
        assert tools["douban_subject"].annotations.readOnlyHint
        assert not tools["douban_set_interest"].annotations.readOnlyHint
        assert tools["douban_delete_interest"].annotations.destructiveHint
        status = await session.call_tool("douban_auth_status", {})
        assert not status.isError
        assert not json.loads(status.content[0].text)["authenticated"]
        rejected = await session.call_tool(
            "douban_set_interest",
            {
                "subject_type": "movie",
                "subject_id": "3541415",
                "status": "done",
                "rating": 9,
            },
        )
        assert rejected.isError
        unauth = await session.call_tool("douban_me", {})
        assert unauth.isError and "login_required" in unauth.content[0].text


@pytest.mark.parametrize(
    "name,args,path,params",
    [
        (
            "douban_search",
            {"query": "三体", "category": "book"},
            "/api/v2/search/book",
            {"q": "三体"},
        ),
        (
            "douban_search_suggestions",
            {"query": "三体"},
            "/api/v2/search/suggestion",
            {"q": "三体"},
        ),
        (
            "douban_subject",
            {"subject_type": "tv", "subject_id": "26794435"},
            "/api/v2/tv/26794435",
            {},
        ),
        ("douban_collection", {}, "/api/v2/subject_collection/movie_top250/items", {"count": "20"}),
        (
            "douban_user_interests",
            {"user_id": "123", "status": "mark"},
            "/api/v2/user/123/interests",
            {"status": "mark", "type": "movie"},
        ),
        ("douban_user_reviews", {"user_id": "123"}, "/api/v2/user/123/reviews", {"type": "movie"}),
    ],
)
async def test_tool_routes(tmp_path, name, args, path, params):
    requests = []

    def handler(request):
        requests.append(request)
        assert request.url.path == path
        for key, value in params.items():
            assert request.url.params[key] == value
        return httpx.Response(200, json={"items": []})

    client = FrodoClient(
        Settings(state_dir=tmp_path, request_interval=0), transport=httpx.MockTransport(handler)
    )
    try:
        server = create_server(client)
        await server.call_tool(name, args)
        assert len(requests) == 1
        with pytest.raises(ToolError):
            await server.call_tool(
                "douban_subject", {"subject_type": "movie", "subject_id": "../user/me"}
            )
        assert len(requests) == 1
    finally:
        await client.close()


async def test_me_uses_authenticated_identity_instead_of_public_username(tmp_path):
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer current-token"
        if request.url.path == "/api/v2/user/me":
            return httpx.Response(200, json={"id": "999", "uid": "me"})
        assert request.url.path == "/api/v2/~me"
        return httpx.Response(200, json={"id": "456", "uid": "current-account"})

    client = FrodoClient(
        Settings(state_dir=tmp_path, request_interval=0), transport=httpx.MockTransport(handler)
    )
    # Even a stale ID saved by the former token importer must not choose the public profile.
    client.store.write("credentials.json", {"access_token": "current-token", "user_id": "999"})
    try:
        result = await create_server(client).call_tool("douban_me", {})
        profile = json.loads(result[0].text)
        assert profile == {"id": "456", "uid": "current-account"}
        assert len(requests) == 1
    finally:
        await client.close()


async def test_me_rejected_token_is_not_replaced_by_public_profile(tmp_path):
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/api/v2/user/me":
            return httpx.Response(200, json={"id": "999", "uid": "me"})
        assert request.url.path == "/api/v2/~me"
        return httpx.Response(401, json={"code": 123, "msg": "invalid token"})

    client = FrodoClient(
        Settings(state_dir=tmp_path, request_interval=0), transport=httpx.MockTransport(handler)
    )
    client.store.write("credentials.json", {"access_token": "expired-token", "user_id": "456"})
    try:
        with pytest.raises(ToolError, match="invalid token"):
            await create_server(client).call_tool("douban_me", {})
        assert len(requests) == 1
    finally:
        await client.close()
