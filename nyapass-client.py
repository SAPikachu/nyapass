#!/usr/bin/env python3

import asyncio
import ssl
import logging

from common import nyapass_run
from config import Config
from signature import sign_headers, SignatureError

log = logging.getLogger("nyapass")

class RequestHandler:
    def __init__(self, config):
        self.config = config
        self._ssl_ctx = create_ssl_ctx(config)

    @asyncio.coroutine
    def connect_to_server(self):
        ret = yield from asyncio.open_connection(
            self.config.server_host,
            self.config.server_port,
            ssl=self._ssl_ctx,
        )
        return ret

    @asyncio.coroutine
    def handle_request(self, request, writer):
        request = sign_headers(self.config, request)

        br, bw = yield from self.connect_to_server()
        bw.write(request)
        return br, bw


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
        request_handler=RequestHandler(config).handle_request,
        config=config,
    )


if __name__ == "__main__":
    main(Config("client"))
