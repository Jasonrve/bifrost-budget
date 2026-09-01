from __future__ import annotations

import asyncio
import logging

from .logging import configure_logging, log_event
from .server import server
from .settings import BifrostSettings


def main() -> None:
    settings = BifrostSettings.from_env()
    configure_logging()
    log_event(
        logging.INFO,
        "app_start",
        transport=settings.transport,
        host=settings.host,
        port=settings.port,
        mcp_path=settings.mcp_path,
        quota_url=settings.quota_url,
    )
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
