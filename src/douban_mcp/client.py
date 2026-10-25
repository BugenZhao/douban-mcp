"""Frodo transport, token lifecycle and subject mutations. No background traffic."""

import asyncio
import base64
import hashlib
import hmac
import re
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit

import httpx

from .config import Settings
from .state import StateStore

ORIGIN = "https://frodo.douban.com"


class FrodoError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int | None = None,
        outcome_unknown: bool = False,
        verification_user_id: str | None = None,
    ):
        self.verification_user_id = verification_user_id
        self.code = code
        self.message = message
        self.status = status
        self.outcome_unknown = outcome_unknown
        super().__init__(message)

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "http_status": self.status,
            "outcome_unknown": self.outcome_unknown,
        }


def signature(method: str, path: str, timestamp: str, secret: str, token: str = "") -> str:
    parts = [method.upper(), quote(path, safe="")]
    if token:
        parts.append(token)
    parts.append(timestamp)
    digest = hmac.new(secret.encode(), "&".join(parts).encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def segment(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", value):
        raise FrodoError("invalid_id", "Use a Douban ID or collection key, with letters/digits/_/-")
    return value


class FrodoClient:
    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.store = StateStore(settings.state_dir)
        self._http = httpx.AsyncClient(
            timeout=settings.timeout,
            proxy=settings.proxy,
            trust_env=False,
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": settings.user_agent, "Accept": "application/json"},
        )
        self._accounts = httpx.AsyncClient(
            timeout=settings.timeout,
            proxy=settings.proxy,
            trust_env=False,
            follow_redirects=False,
            transport=transport,
        )
        self._pending_login: dict | None = None
        self._pace_lock = asyncio.Lock()
        self._auth_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._last_request = 0.0

    async def close(self):
        self._clear_login_challenge()
        await self._accounts.aclose()
        await self._http.aclose()

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        token: str = "",
    ) -> Any:
        if not (path.startswith("/api/v2/") or path == "/service/auth2/token"):
            raise FrodoError("invalid_path", "Unsupported Frodo path")
        query = {k: v for k, v in (params or {}).items() if v is not None}
        form = {k: v for k, v in (data or {}).items() if v is not None}
        async with self._pace_lock:
            await asyncio.sleep(
                max(0, self.settings.request_interval - (time.monotonic() - self._last_request))
            )
            ts = str(int(time.time()))
            signed = {
                "apikey": self.settings.api_key,
                "os_rom": "android",
                "_ts": ts,
                "_sig": signature(method, path, ts, self.settings.api_secret, token),
            }
            device = self.settings.device_id or self.store.read("device.json").get("device_id")
            if device:
                signed["udid"] = device
            if method == "POST":
                form.update(signed)
            else:
                query.update(signed)
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            self._last_request = time.monotonic()
            try:
                response = await self._http.request(
                    method,
                    ORIGIN + path,
                    params=query,
                    data=form or None,
                    headers=headers,
                )
            except httpx.HTTPError:
                raise FrodoError(
                    "network_error",
                    "Frodo request failed; check connectivity and DOUBAN_PROXY. "
                    "For a write, read the current interest before retrying.",
                    outcome_unknown=method != "GET",
                ) from None
        try:
            payload = response.json()
        except ValueError:
            raise FrodoError(
                "invalid_response",
                "Frodo returned a non-JSON response",
                status=response.status_code,
                outcome_unknown=method != "GET",
            ) from None
        api_error = isinstance(payload, dict) and (
            bool(payload.get("error")) or payload.get("code") not in (None, 0, "0", 200, "200")
        )
        if not response.is_success or api_error:
            raw_code = (
                payload.get("code", payload.get("error", "http_error"))
                if isinstance(payload, dict)
                else "http_error"
            )
            # Pass only a bounded error identifier and message, never the full response or URL.
            code = str(raw_code) if isinstance(raw_code, (str, int)) else "api_error"
            msg = (
                payload.get("localized_message")
                or payload.get("msg")
                or payload.get("error_description")
                or payload.get("error")
                if isinstance(payload, dict)
                else "Frodo request failed"
            )
            message = str(msg or "Frodo request failed")
            for secret in [
                token,
                signed["_sig"],
                self.settings.api_secret,
                *[
                    str(v)
                    for k, v in form.items()
                    if k in {"password", "access_token", "refresh_token", "username"}
                ],
            ]:
                if secret:
                    code, message = (
                        code.replace(secret, "[redacted]"),
                        message.replace(secret, "[redacted]"),
                    )
            verification_user_id = None
            if code == "9000" and path == "/service/auth2/token":
                extra = payload.get("extra")
                uri = extra.get("solution_uri") if isinstance(extra, dict) else None
                if isinstance(uri, str):
                    try:
                        parsed = urlsplit(uri)
                    except ValueError:
                        parsed = urlsplit("")
                    if (
                        parsed.scheme == "douban"
                        and parsed.netloc == "douban.com"
                        and parsed.path == "/account/login_verify_phone"
                    ):
                        values = parse_qs(parsed.query).get("user_id", [])
                        if len(values) == 1 and re.fullmatch(r"[0-9]{1,30}", values[0]):
                            verification_user_id = values[0]
            raise FrodoError(
                code[:80],
                message[:500],
                verification_user_id=verification_user_id,
                status=response.status_code,
                outcome_unknown=method != "GET" and response.status_code >= 500,
            )
        return payload

    def auth_status(self) -> dict:
        state = self.store.read("credentials.json")
        expiry = state.get("expires_at")
        return {
            "authenticated": bool(state.get("access_token")),
            "user_id": state.get("user_id"),
            "expires_at": expiry,
            "expired": bool(expiry and expiry <= time.time()),
            "can_refresh": bool(state.get("refresh_token")),
            "verification": "local_state_only",
        }

    def _save_token(self, payload: dict, previous: dict | None = None):
        access = payload.get("access_token")
        if not isinstance(access, str) or not access or any(c.isspace() for c in access):
            raise FrodoError(
                "invalid_token_response", "Login response did not contain a valid token"
            )
        previous = previous or {}
        try:
            lifetime = float(payload.get("expires_in") or 0)
        except (ValueError, TypeError):
            raise FrodoError("invalid_token_response", "Invalid token expiry") from None
        self.store.write(
            "credentials.json",
            {
                "access_token": access,
                "refresh_token": payload.get("refresh_token") or previous.get("refresh_token"),
                "user_id": payload.get("douban_user_id")
                or payload.get("user_id")
                or previous.get("user_id"),
                "expires_at": time.time() + lifetime if lifetime > 0 else None,
            },
        )

    def _device_params(self) -> dict:
        device = self.store.device(self.settings.device_id)
        return {
            "udid": device,
            "device_id": device,
            "douban_udid": hashlib.sha1(device.encode()).hexdigest(),
        }

    def _clear_login_challenge(self):
        self._pending_login = None
        self._accounts.cookies.clear()
        self._accounts.headers.clear()

    def _challenge_status(self) -> dict:
        pending = self._pending_login
        return {
            "authenticated": False,
            "verification_required": True,
            "sms_sent": True,
            "challenge_id": pending["id"],
            "expires_at": pending["expires_at"],
            "message": "短信已发送至账号绑定的手机号；请提交验证码完成登录。",
        }

    async def _account_request(self, method: str, url: str, *, data=None) -> httpx.Response:
        # Callers supply only fixed Douban endpoints or checked bootstrap redirects.
        async with self._pace_lock:
            await asyncio.sleep(
                max(0, self.settings.request_interval - (time.monotonic() - self._last_request))
            )
            self._last_request = time.monotonic()
            try:
                return await self._accounts.request(method, url, data=data)
            except httpx.HTTPError:
                raise FrodoError(
                    "verification_network_error",
                    "手机号验证请求失败；请检查网络。短信发送和校验均只尝试一次。",
                    outcome_unknown=method == "POST",
                ) from None

    async def _phone_api(self, action: str, user_id: str, sms_code: str | None = None) -> dict:
        form = {"user_id": user_id}
        if action == "request_phone_code":
            form["apikey"] = self.settings.api_key
        else:
            form.update(client_id=self.settings.api_key, phone_code=sms_code)
        response = await self._account_request(
            "POST", "https://accounts.douban.com/j/app/verify_phone/" + action, data=form
        )
        try:
            result = response.json()
        except ValueError:
            result = None
        if not isinstance(result, dict):
            raise FrodoError(
                "verification_invalid_response",
                "手机号验证返回了异常响应。",
                status=response.status_code,
                outcome_unknown=True,
            )
        if response.is_success and result.get("status") == "success":
            payload = result.get("payload")
            return payload if isinstance(payload, dict) else {}
        # Account responses may echo credentials or contain captcha URLs. Return fixed messages.
        reason = result.get("message")
        payload = result.get("payload")
        captcha = isinstance(payload, dict) and any(
            payload.get(k)
            for k in ("captcha_id", "tc_app_id", "touch_cap_url", "captcha_image_url")
        )
        if captcha or (isinstance(reason, str) and "captcha" in reason):
            code, message = (
                "captcha_required",
                "豆瓣要求图形验证，请在官方 App 完成验证后重新登录。",
            )
        elif not response.is_success:
            code, message = "verification_http_error", "手机号验证服务请求失败，请稍后重新登录。"
        elif action == "verify_phone_code":
            code, message = "sms_verification_failed", "短信校验失败；请检查验证码及有效期。"
        else:
            code, message = (
                "sms_send_failed",
                "短信发送失败；请稍后重新登录，或在官方 App 检查账号保护。",
            )
        raise FrodoError(
            code, message, status=response.status_code, outcome_unknown=response.status_code >= 500
        )

    async def _begin_phone_verification(self, user_id: str, device: str) -> dict:
        self._accounts.cookies.update(self._http.cookies)
        self._accounts.headers.update(
            {
                "User-Agent": f"Mozilla/5.0 (Linux; Android 6.0) AppleWebKit/537.36 "
                f"Chrome/130.0.0.0 Mobile Safari/537.36 udid/{device} "
                "com.douban.frodo/7.22.0 DoubanApp",
                "X-Requested-With": "com.douban.frodo",
            }
        )
        page = "https://accounts.douban.com/passport/verify_phone?" + urlencode(
            {"user_id": user_id, "dark_mode": "0"}
        )
        url = "https://www.douban.com/accounts/auth2_redir?" + urlencode({"url": page})
        allowed = {
            ("www.douban.com", "/accounts/auth2_redir"),
            ("accounts.douban.com", "/passport/verify_phone"),
            ("accounts.douban.com", "/login"),
            ("accounts.douban.com", "/passport/login"),
        }
        for _ in range(5):
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.netloc not in {"www.douban.com", "accounts.douban.com"}
                or (parsed.netloc, parsed.path) not in allowed
            ):
                raise FrodoError("verification_redirect", "手机号验证会话返回了意外跳转。")
            response = await self._account_request("GET", url)
            if response.is_redirect and response.headers.get("location"):
                url = urljoin(url, response.headers["location"])
                continue
            if not response.is_success:
                raise FrodoError(
                    "verification_session_failed",
                    "手机号验证会话初始化失败。",
                    status=response.status_code,
                )
            break
        else:
            raise FrodoError("verification_redirect", "手机号验证会话跳转次数过多。")
        self._accounts.headers.update(
            {
                "Origin": "https://accounts.douban.com",
                "Referer": page,
                "X-CSRF-TOKEN": "undefined",
                "Accept": "application/json, text/plain, */*",
            }
        )
        await self._phone_api("request_phone_code", user_id)
        self._pending_login = {
            "id": secrets.token_hex(16),
            "user_id": user_id,
            "device": device,
            "expires_at": time.time() + 600,
            "attempts": 0,
        }
        return self._challenge_status()

    async def login(
        self,
        username: str | None = None,
        password: str | None = None,
        *,
        sms_code: str | None = None,
        challenge_id: str | None = None,
    ) -> dict:
        async with self._auth_lock:
            if sms_code is not None or challenge_id is not None:
                if username is not None or password is not None:
                    raise FrodoError(
                        "invalid_login_step", "验证步骤仅需 challenge_id 和 sms_code。"
                    )
                pending = self._pending_login
                if pending and pending["expires_at"] <= time.time():
                    self._clear_login_challenge()
                    pending = None
                if (
                    not pending
                    or not isinstance(challenge_id, str)
                    or not re.fullmatch(r"[0-9a-f]{32}", challenge_id)
                    or not secrets.compare_digest(challenge_id, pending["id"])
                ):
                    raise FrodoError(
                        "login_challenge_expired", "验证会话已失效，请重新输入账号密码登录。"
                    )
                if not isinstance(sms_code, str) or not re.fullmatch(r"[0-9]{4,8}", sms_code):
                    raise FrodoError("invalid_sms_code", "请输入 4–8 位数字短信验证码。")
                with self.store.locked():
                    device = self.settings.device_id or self.store.read("device.json").get(
                        "device_id"
                    )
                    if device != pending["device"]:
                        self._clear_login_challenge()
                        raise FrodoError("login_challenge_expired", "设备信息已变化，请重新登录。")
                    pending["attempts"] += 1
                    try:
                        payload = await self._phone_api(
                            "verify_phone_code", pending["user_id"], sms_code
                        )
                        if str(payload.get("douban_user_id")) != pending["user_id"]:
                            raise FrodoError(
                                "invalid_token_response", "验证响应中的账号信息不匹配。"
                            )
                        self._save_token(payload)
                    except FrodoError:
                        if pending["attempts"] >= 5:
                            self._clear_login_challenge()
                        raise
                    self._clear_login_challenge()
                return self.auth_status()
            if not username or not username.strip() or not password:
                raise FrodoError("credentials_required", "Username and password are required")
            self._clear_login_challenge()
            # The login cookie jar is scoped to this attempt; credentials stay in the form only.
            self._http.cookies.clear()
            device = self._device_params()
            with self.store.locked():
                try:
                    payload = await self._send(
                        "POST",
                        "/service/auth2/token",
                        data={
                            "client_id": self.settings.api_key,
                            "client_secret": self.settings.api_secret,
                            "grant_type": "password",
                            "username": username.strip(),
                            "password": password,
                            "redirect_uri": "frodo://app/oauth/callback/",
                            "disable_account_create": "false",
                            **device,
                        },
                    )
                except FrodoError as exc:
                    if exc.code != "9000":
                        raise
                    if not exc.verification_user_id:
                        raise FrodoError(
                            "verification_context_missing",
                            "豆瓣要求手机号验证，但返回的验证上下文不完整，请重新登录。",
                        ) from None
                    try:
                        return await self._begin_phone_verification(
                            exc.verification_user_id, device["device_id"]
                        )
                    except BaseException:
                        self._clear_login_challenge()
                        raise
                finally:
                    self._http.cookies.clear()
                self._save_token(payload)
        return self.auth_status()

    async def import_token(
        self, access_token: str, refresh_token: str | None = None, expires_in: int | None = None
    ) -> dict:
        if not access_token or any(c.isspace() for c in access_token):
            raise FrodoError("invalid_token", "Supply the token value without the Bearer prefix")
        async with self._auth_lock:
            with self.store.locked():
                self._clear_login_challenge()
                # Frodo's authenticated identity endpoint is /~me. /user/me is a public username.
                # Validate the proposed identity before replacing the existing session.
                me = await self._send("GET", "/api/v2/~me", token=access_token)
                if not isinstance(me, dict) or not me.get("id"):
                    raise FrodoError("invalid_token", "Frodo did not return a user identity")
                self._save_token(
                    {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "expires_in": expires_in,
                        "user_id": me["id"],
                    }
                )
        return self.auth_status()

    async def _refresh_locked(self, state: dict) -> None:
        if not state.get("refresh_token"):
            raise FrodoError("login_required", "Refresh token unavailable; log in again")
        # Caller holds the file lock; read the already persisted device without acquiring it twice.
        device = self.settings.device_id or self.store.read("device.json").get("device_id")
        form = {
            "grant_type": "refresh_token",
            "refresh_token": state["refresh_token"],
            "client_id": self.settings.api_key,
            "client_secret": self.settings.api_secret,
            "redirect_uri": "frodo://app/oauth/callback/",
            "disable_account_create": "false",
        }
        if device:
            form.update(
                udid=device, device_id=device, douban_udid=hashlib.sha1(device.encode()).hexdigest()
            )
        payload = await self._send("POST", "/service/auth2/token", data=form)
        self._save_token(payload, state)

    async def refresh(self) -> dict:
        async with self._auth_lock:
            with self.store.locked():
                await self._refresh_locked(self.store.read("credentials.json"))
        return self.auth_status()

    async def logout(self) -> dict:
        async with self._auth_lock:
            with self.store.locked():
                self._clear_login_challenge()
                self.store.clear_tokens()
        return {"authenticated": False, "scope": "local_credentials_removed"}

    async def _token(self, required: bool = False) -> str:
        async with self._auth_lock:
            with self.store.locked():
                state = self.store.read("credentials.json")
                expiry = state.get("expires_at")
                if state.get("access_token") and expiry and expiry <= time.time() + 60:
                    await self._refresh_locked(state)
                    state = self.store.read("credentials.json")
                token = state.get("access_token") or ""
        if required and not token:
            raise FrodoError(
                "login_required", "Log in or import an access token before this operation"
            )
        return token

    async def get(self, path: str, *, params: dict | None = None, require_auth: bool = False):
        return await self._send("GET", path, params=params, token=await self._token(require_auth))

    async def set_interest(
        self,
        subject_type: str,
        subject_id: str,
        status: str,
        rating: int | None = None,
        comment: str | None = None,
        tags: list[str] | None = None,
        share: bool = False,
    ) -> dict:
        path = f"/api/v2/{segment(subject_type)}/{segment(subject_id)}"
        async with self._write_lock:
            token = await self._token(required=True)
            # Read/merge preserves ratings and comments when the caller changes only the status.
            subject = await self._send("GET", path, token=token)
            if not isinstance(subject, dict) or "interest" not in subject:
                raise FrodoError(
                    "invalid_response", "Subject response has no interest field; update stopped"
                )
            old = subject.get("interest") or {}
            old_rating = old.get("rating") or {}
            value = old_rating.get("value", 0) if isinstance(old_rating, dict) else old_rating
            old_tags = old.get("tags") or []
            if isinstance(old_tags, str):
                old_tags = old_tags.split()
            if any(not isinstance(tag, str) for tag in old_tags):
                raise FrodoError("invalid_response", "Unsupported existing tags; update stopped")
            form = {
                "rating": rating if rating is not None else value,
                "comment": comment if comment is not None else (old.get("comment") or ""),
                "share_to_douban": "1" if share else "0",
            }
            if tags is not None or "tags" in old:
                form["tags"] = " ".join(tags if tags is not None else old_tags)
            if "is_private" in old:
                form["is_private"] = "1" if old["is_private"] in (True, 1, "1") else "0"
            result = await self._send("POST", path + "/" + status, data=form, token=token)
            try:
                current = await self._send("GET", path, token=token)
            except FrodoError as exc:
                return {
                    "submitted": True,
                    "verified": False,
                    "result": result,
                    "verification_error": exc.as_dict(),
                }
            interest = current.get("interest") or {}
            actual_rating = interest.get("rating") or {}
            actual_rating = (
                actual_rating.get("value", 0) if isinstance(actual_rating, dict) else actual_rating
            )
            verified = (
                interest.get("status") == status
                and actual_rating == form["rating"]
                and (interest.get("comment") or "") == form["comment"]
            )
            if tags is not None:
                verified = verified and interest.get("tags", []) == tags
            return {"submitted": True, "verified": verified, "interest": interest, "result": result}

    async def delete_interest(self, subject_type: str, subject_id: str) -> dict:
        async with self._write_lock:
            token = await self._token(required=True)
            result = await self._send(
                "POST",
                f"/api/v2/{segment(subject_type)}/{segment(subject_id)}/unmark",
                token=token,
            )
            try:
                current = await self._send(
                    "GET", f"/api/v2/{subject_type}/{subject_id}", token=token
                )
            except FrodoError as exc:
                return {
                    "submitted": True,
                    "verified": False,
                    "result": result,
                    "verification_error": exc.as_dict(),
                }
            interest = current.get("interest") or {}
            verified = "interest" in current and interest.get("status") in (None, "unmark")
            return {"submitted": True, "verified": verified, "interest": interest, "result": result}
