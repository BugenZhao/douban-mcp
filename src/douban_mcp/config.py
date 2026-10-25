import os
from dataclasses import dataclass, field
from pathlib import Path

# Shared Frodo Android application constants; individual account tokens stay in local state.
API_KEY = "0dad551ec0f84ed02907ff5c42e8ec70"
API_SECRET = "bf7dddc7c9cfe6f7"
USER_AGENT = (
    "api-client/1 com.douban.frodo/7.22.0.beta9(231) Android/23 "
    "product/Mate40 vendor/HUAWEI model/Mate40 brand/HUAWEI "
    "rom/android network/wifi platform/AndroidPad"
)


@dataclass(frozen=True)
class Settings:
    api_key: str = field(default=API_KEY, repr=False)
    api_secret: str = field(default=API_SECRET, repr=False)
    user_agent: str = USER_AGENT
    state_dir: Path = field(default_factory=lambda: Path.home() / ".local/state/douban-mcp")
    proxy: str | None = field(default=None, repr=False)
    timeout: float = 20
    request_interval: float = 1.2
    device_id: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        root = Path(os.getenv("XDG_STATE_HOME", str(Path.home() / ".local/state")))
        settings = cls(
            api_key=os.getenv("DOUBAN_API_KEY", API_KEY),
            api_secret=os.getenv("DOUBAN_API_SECRET", API_SECRET),
            user_agent=os.getenv("DOUBAN_USER_AGENT", USER_AGENT),
            state_dir=Path(os.getenv("DOUBAN_STATE_DIR", str(root / "douban-mcp"))).expanduser(),
            proxy=os.getenv("DOUBAN_PROXY") or None,
            timeout=float(os.getenv("DOUBAN_TIMEOUT", "20")),
            request_interval=float(os.getenv("DOUBAN_REQUEST_INTERVAL", "1.2")),
            device_id=os.getenv("DOUBAN_DEVICE_ID") or None,
        )
        if settings.timeout <= 0 or settings.request_interval < 0:
            raise ValueError("DOUBAN_TIMEOUT must be positive; request interval must be >= 0")
        return settings
