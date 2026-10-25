"""Frodo transport, token lifecycle and subject mutations. No background traffic."""

import asyncio
import base64
import hashlib
import hmac
import re
import time
from typing import Any
from urllib.parse import quote

import httpx

from .config import Settings
from .state import StateStore

ORIGIN = "https://frodo.douban.com"


class FrodoError(Exception):
    def __init__(
        self, code: str, message: str, *, status: int | None = None, outcome_unknown: bool = False
    ):
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
        self._pace_lock = asyncio.Lock()
        self._auth_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._last_request = 0.0

    async def close(self):
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
            raise FrodoError(
                code[:80],
                message[:500],
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

    async def login(self, username: str, password: str) -> dict:
        if not username.strip() or not password:
            raise FrodoError("credentials_required", "Username and password are required")
        async with self._auth_lock:
            device = self._device_params()
            with self.store.locked():
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
                self._save_token(payload)
        return self.auth_status()

    async def import_token(
        self, access_token: str, refresh_token: str | None = None, expires_in: int | None = None
    ) -> dict:
        if not access_token or any(c.isspace() for c in access_token):
            raise FrodoError("invalid_token", "Supply the token value without the Bearer prefix")
        async with self._auth_lock:
            with self.store.locked():
                # Validate the proposed identity before replacing the existing session.
                me = await self._send("GET", "/api/v2/user/me", token=access_token)
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
