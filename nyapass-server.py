#!/usr/bin/env python3

import asyncio
import ssl
import logging

from utils import pipe_data
from common import nyapass_run
from config import Config

log = logging.getLogger("nyapass")


class RequestHandler:
    def __init__(self, config):
        self.config = config

    @asyncio.coroutine
    def create_masq_backend(self):
        ret = yield from asyncio.open_connection(
            self.config.masq_host, self.config.masq_port,
        )
        return ret

    @asyncio.coroutine
    def create_forwarder_backend(self):
        ret = yield from asyncio.open_connection(
            self.config.forwarder_host, self.config.forwarder_port,
        )
        return ret


    def is_authorized(self, request, writer):
        return b"X-Nyapass: cee85fee-9a98-4019-aa8c-7ee644fd74e3" in request

    @asyncio.coroutine
    def handle_request(self, request, writer):
        br, bw = None, None
        if self.is_authorized(request, writer):
            br, bw = yield from self.create_forwarder_backend()
        else:
            br, bw = yield from self.create_masq_backend()
        bw.write(request)
        return br, bw


def create_ssl_ctx(config):
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH,
    )
    ctx.load_cert_chain(config.tls_cert, config.tls_key)
    ctx.options = (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
        ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers(config.tls_ciphers)
    return ctx


def main(config):
    logging.basicConfig(level=config.log_level)
    nyapass_run(
        request_handler=RequestHandler(config).handle_request,
        config=config,
        listener_ssl_ctx=create_ssl_ctx(config),
    )


if __name__ == "__main__":
    main(Config("server"))
