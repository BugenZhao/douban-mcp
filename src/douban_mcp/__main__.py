import argparse
import asyncio
import getpass
import json
import sys

from .client import FrodoClient, FrodoError
from .config import Settings
from .state import StateError


async def auth_command(command: str):
    client = FrodoClient(Settings.from_env())
    try:
        if command == "login":
            username = input("豆瓣手机号 / 邮箱: ")
            password = getpass.getpass("密码: ")
            result = await client.login(username, password)
            del password
            if result.get("verification_required"):
                print(result["message"], file=sys.stderr)
                challenge_id = result["challenge_id"]
                for attempt in range(5):
                    sms_code = getpass.getpass("短信验证码: ")
                    try:
                        result = await client.login(challenge_id=challenge_id, sms_code=sms_code)
                        break
                    except FrodoError as exc:
                        if (
                            exc.code not in {"sms_verification_failed", "invalid_sms_code"}
                            or attempt == 4
                        ):
                            raise
                        print(exc.message, file=sys.stderr)
                    finally:
                        del sms_code
        elif command == "import-token":
            token = getpass.getpass("Access token: ")
            refresh = getpass.getpass("Refresh token（可留空）: ") or None
            result = await client.import_token(token, refresh)
        elif command == "refresh":
            result = await client.refresh()
        elif command == "logout":
            result = await client.logout()
        else:
            result = client.auth_status()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        await client.close()


def main():
    parser = argparse.ArgumentParser(description="Douban Frodo MCP server (stdio)")
    parser.add_argument(
        "command",
        nargs="?",
        default="serve",
        choices=["serve", "login", "import-token", "status", "refresh", "logout"],
    )
    args = parser.parse_args()
    try:
        if args.command == "serve":
            from .server import run

            run()
        else:
            asyncio.run(auth_command(args.command))
    except FrodoError as exc:
        print(json.dumps(exc.as_dict(), ensure_ascii=False), file=sys.stderr)
        sys.exit(1)
    except (StateError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    except OSError:
        print("Local state I/O failed; check DOUBAN_STATE_DIR permissions", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        sys.exit(130)


if __name__ == "__main__":
    main()
