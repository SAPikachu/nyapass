#!/usr/bin/env python3

import asyncio
import ssl
import logging

from common import nyapass_run, ConnectionHandler
from config import Config
from signature import sign_headers


class ClientHandler(ConnectionHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ssl_ctx = create_ssl_ctx(self.config)
        self.default_remote = (
            self.config.server_host,
            self.config.server_port,
        )

    @asyncio.coroutine
    def process_request(self):
        self._local_headers = sign_headers(
            self.config,
            self._local_headers,
        )

    @asyncio.coroutine
    def connect_to_remote(self, remote, **kwargs):
        kwargs["ssl"] = self._ssl_ctx
        ret = yield from super().connect_to_remote(
            remote,
            **kwargs
        )
        return ret


def create_ssl_ctx(config):
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
    )
    ctx.options = (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
        ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
    if not config.ssl_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


def main(config):
    logging.basicConfig(level=config.log_level)
    nyapass_run(
        handler_factory=ClientHandler,
        config=config,
    )


if __name__ == "__main__":
    main(Config("client"))
