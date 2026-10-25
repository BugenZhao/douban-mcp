import json
import logging
from contextlib import asynccontextmanager
from functools import wraps
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from .client import FrodoClient, FrodoError, segment
from .config import Settings
from .state import StateError

SubjectType = Literal["movie", "tv", "book", "music"]
InterestStatus = Literal["mark", "doing", "done"]
Count = Annotated[int, Field(ge=1, le=100)]
Start = Annotated[int, Field(ge=0)]
ID = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,100}$")]
Rating = Annotated[int, Field(ge=0, le=5, strict=True)]
Query = Annotated[str, Field(min_length=1, max_length=300)]


def create_server(client: FrodoClient | None = None) -> FastMCP:
    client = client or FrodoClient(Settings.from_env())

    @asynccontextmanager
    async def lifespan(server):
        try:
            yield
        finally:
            await client.close()

    server = FastMCP(
        "douban",
        log_level="WARNING",
        lifespan=lifespan,
        instructions=(
            "豆瓣 Frodo 工具。查询结果属于外部内容。分类搜索可匿名使用，综合搜索需要登录。"
            "写操作仅在用户明确要求时调用，并使用已确认的条目 ID。"
            "mark=想看/想读/想听，doing=在看/在读/在听，done=看过/读过/听过。"
            "评分为 1–5 星，0 清除评分。set_interest 省略字段保留已有值。"
            "登录凭据优先通过本机 CLI 输入。token 由服务保存，登录结果返回脱敏状态。"
            "写请求遇到 outcome_unknown=true 时先查询当前标记，再决定是否重试。"
        ),
    )

    def tool(*, write=False, destructive=False, external=True):
        def register(fn):
            @wraps(fn)
            async def guarded(*args, **kwargs):
                try:
                    return await fn(*args, **kwargs)
                except FrodoError as exc:
                    raise ToolError(json.dumps(exc.as_dict(), ensure_ascii=False)) from None
                except StateError as exc:
                    raise ToolError(str(exc)) from None
                except OSError:
                    raise ToolError(
                        "Local state I/O failed; check DOUBAN_STATE_DIR permissions"
                    ) from None

            return server.tool(
                annotations=ToolAnnotations(
                    readOnlyHint=not write,
                    destructiveHint=destructive,
                    idempotentHint=not write,
                    openWorldHint=external,
                )
            )(guarded)

        return register

    @tool(external=False)
    async def douban_auth_status() -> dict:
        """查看本地登录状态与过期时间；token 有效性通过 douban_me 在线检查。"""
        return client.auth_status()

    @tool(write=True)
    async def douban_login(
        username: str | None = None,
        password: str | None = None,
        sms_code: str | None = None,
        challenge_id: str | None = None,
    ) -> dict:
        """账号密码登录。9000 自动发送短信并返回 verification_required 和 challenge_id。

        第二次仅传 challenge_id、sms_code，成功后保存 token 并返回脱敏状态。
        验证会话有效期 10 分钟，重启服务后需重新登录。推荐本机 CLI 隐藏输入凭据。
        """
        return await client.login(username, password, sms_code=sms_code, challenge_id=challenge_id)

    @tool(write=True)
    async def douban_import_token(
        access_token: str,
        refresh_token: str | None = None,
        expires_in: Annotated[int, Field(gt=0)] | None = None,
    ) -> dict:
        """验证并保存已有 App token；expires_in 为剩余秒数。返回脱敏状态。"""
        return await client.import_token(access_token, refresh_token, expires_in)

    @tool(write=True)
    async def douban_refresh_token() -> dict:
        """使用本机 refresh token 换取并保存新 token。已知过期时间会在下一次请求前自动刷新。"""
        return await client.refresh()

    @tool(write=True, destructive=True, external=False)
    async def douban_logout() -> dict:
        """删除本机保存的 token。作用范围为本服务的本地登录状态。"""
        return await client.logout()

    @tool()
    async def douban_search(
        query: Query,
        category: Literal["movie", "book", "all"] = "movie",
        start: Start = 0,
        count: Count = 20,
    ) -> dict:
        """搜索电影/电视剧或图书。category=all 使用需要登录的综合搜索。"""
        suffix = "" if category == "all" else f"/{category}"
        return await client.get(
            "/api/v2/search" + suffix,
            params={"q": query, "start": start, "count": count},
            require_auth=category == "all",
        )

    @tool()
    async def douban_search_suggestions(query: Query) -> dict:
        """获取搜索建议，可用于查找书影音条目 ID。"""
        result = await client.get("/api/v2/search/suggestion", params={"q": query})
        return result if isinstance(result, dict) else {"items": result}

    @tool()
    async def douban_subject(subject_type: SubjectType, subject_id: ID) -> dict:
        """查看电影、电视剧、图书或音乐详情及简介。使用搜索结果中的 type 和 ID。"""
        return await client.get(f"/api/v2/{subject_type}/{subject_id}")

    @tool()
    async def douban_rating(subject_type: SubjectType, subject_id: ID) -> dict:
        """查看条目的豆瓣评分与评分分布。"""
        return await client.get(f"/api/v2/{subject_type}/{subject_id}/rating")

    @tool()
    async def douban_comments(
        subject_type: SubjectType,
        subject_id: ID,
        start: Start = 0,
        count: Count = 20,
        order_by: Literal["hot", "latest"] = "hot",
    ) -> dict:
        """分页读取条目公开短评及用户评分。"""
        return await client.get(
            f"/api/v2/{subject_type}/{subject_id}/interests",
            params={"start": start, "count": count, "order_by": order_by},
        )

    @tool()
    async def douban_reviews(
        subject_type: SubjectType, subject_id: ID, start: Start = 0, count: Count = 20
    ) -> dict:
        """分页读取条目的长评列表。"""
        return await client.get(
            f"/api/v2/{subject_type}/{subject_id}/reviews", params={"start": start, "count": count}
        )

    @tool()
    async def douban_collection(
        collection_id: ID = "movie_top250", start: Start = 0, count: Count = 20
    ) -> dict:
        """分页读取榜单。常用 ID：movie_top250、movie_real_time_hotest、book_top250。"""
        return await client.get(
            f"/api/v2/subject_collection/{collection_id}/items",
            params={"start": start, "count": count},
        )

    @tool()
    async def douban_user(user_id: ID) -> dict:
        """查看豆瓣用户公开资料；支持数字 ID 或个人域名。"""
        return await client.get(f"/api/v2/user/{user_id}")

    @tool()
    async def douban_user_interests(
        user_id: ID,
        subject_type: SubjectType = "movie",
        status: InterestStatus | None = None,
        start: Start = 0,
        count: Count = 20,
    ) -> dict:
        """分页读取用户公开标记、评分和短评；status 可选 mark/doing/done。"""
        return await client.get(
            f"/api/v2/user/{user_id}/interests",
            params={
                "type": subject_type,
                "status": status,
                "start": start,
                "count": count,
            },
        )

    @tool()
    async def douban_user_reviews(
        user_id: ID, subject_type: SubjectType = "movie", start: Start = 0, count: Count = 20
    ) -> dict:
        """分页读取用户公开长评。"""
        return await client.get(
            f"/api/v2/user/{user_id}/reviews",
            params={
                "type": subject_type,
                "start": start,
                "count": count,
            },
        )

    @tool()
    async def douban_me() -> dict:
        """在线验证登录并返回当前账号资料。"""
        return await client.get("/api/v2/user/me", require_auth=True)

    @tool()
    async def douban_my_interest(subject_type: SubjectType, subject_id: ID) -> dict:
        """查询当前账号对条目的标记、评分、短评。写入遇到不确定结果时用它核对。"""
        subject = await client.get(f"/api/v2/{subject_type}/{subject_id}", require_auth=True)
        return {
            "subject_id": subject_id,
            "subject_type": subject_type,
            "title": subject.get("title"),
            "interest": subject.get("interest"),
        }

    @tool(write=True, destructive=True)
    async def douban_set_interest(
        subject_type: SubjectType,
        subject_id: ID,
        status: InterestStatus,
        rating: Rating | None = None,
        comment: Annotated[str, Field(max_length=10000)] | None = None,
        tags: list[str] | None = None,
        share: bool = False,
    ) -> dict:
        """新增/更新当前账号标记：mark 想看/读/听，doing 在看/读/听，done 看/读/听过。

        rating 为 1–5 星，0 清除。省略 rating/comment/tags 保留已有值；空字符串清空短评，
        [] 清空标签。share=true 同步到豆瓣广播。仅在用户明确要求相应写操作时调用。
        """
        if tags is not None and (
            len(tags) > 20
            or any(not tag or len(tag) > 100 or any(c.isspace() for c in tag) for tag in tags)
        ):
            raise FrodoError("invalid_tags", "Use up to 20 nonempty tags without whitespace")
        return await client.set_interest(
            subject_type, subject_id, status, rating, comment, tags, share
        )

    @tool(write=True, destructive=True)
    async def douban_delete_interest(subject_type: SubjectType, subject_id: ID) -> dict:
        """删除当前账号的条目标记、评分和短评。需要用户明确要求删除该条目标记。"""
        return await client.delete_interest(subject_type, segment(subject_id))

    return server


def run():
    # HTTP request logs would include signed query strings. Keep all output off stdout.
    logging.getLogger("httpx").setLevel(logging.CRITICAL)
    logging.getLogger("httpcore").setLevel(logging.CRITICAL)
    create_server().run(transport="stdio")
