from __future__ import annotations

import asyncio

from .server import server
from .settings import BifrostSettings


def main() -> None:
    settings = BifrostSettings.from_env()
    if settings.transport == "stdio":
        asyncio.run(server.run_stdio_async())
        return

    asyncio.run(
        server.run_streamable_http_async(
            host=settings.host,
            port=settings.port,
            streamable_http_path=settings.mcp_path,
            stateless_http=True,
        )
    )


if __name__ == "__main__":
    main()
