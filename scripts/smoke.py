"""Read-only live acceptance via a real stdio MCP subprocess and temporary anonymous state."""

import asyncio
import json
import os
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SMOKE_USER = os.getenv("DOUBAN_SMOKE_USER", "1000001")

CALLS = [
    ("douban_search", {"query": "盗梦空间", "count": 2}),
    ("douban_search", {"query": "三体", "category": "book", "count": 2}),
    ("douban_search_suggestions", {"query": "三体"}),
    *[
        ("douban_subject", {"subject_type": kind, "subject_id": sid})
        for kind, sid in [
            ("movie", "3541415"),
            ("tv", "35588177"),
            ("book", "2567698"),
            ("music", "1394539"),
        ]
    ],
    ("douban_rating", {"subject_type": "movie", "subject_id": "3541415"}),
    ("douban_comments", {"subject_type": "movie", "subject_id": "3541415", "count": 2}),
    ("douban_reviews", {"subject_type": "movie", "subject_id": "3541415", "count": 2}),
    *[
        ("douban_collection", {"collection_id": cid, "count": 2})
        for cid in [
            "movie_top250",
            "movie_real_time_hotest",
            "book_top250",
        ]
    ],
    ("douban_user", {"user_id": SMOKE_USER}),
    ("douban_user_interests", {"user_id": SMOKE_USER, "status": "done", "count": 2}),
    ("douban_user_reviews", {"user_id": SMOKE_USER, "count": 2}),
]


async def main():
    failures = 0
    with tempfile.TemporaryDirectory(prefix="douban-smoke-") as state:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "douban_mcp"],
            env={**os.environ, "DOUBAN_STATE_DIR": state},
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(f"Discovered {len(tools.tools)} tools", flush=True)
            for name, args in CALLS:
                result = await session.call_tool(name, args)
                if result.isError:
                    failures += 1
                    summary = {"error": result.content[0].text}
                else:
                    payload = json.loads(result.content[0].text)
                    summary = {"title": payload.get("title"), "keys": list(payload)[:6]}
                print(
                    json.dumps(
                        {"tool": name, "ok": not result.isError, "summary": summary},
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
    print(f"{len(CALLS) - failures}/{len(CALLS)} live reads passed")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
