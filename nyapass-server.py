#!/usr/bin/env python3

import asyncio
import ssl
import logging

from utils import pipe_data
from common import nyapass_run
from config import Config
from signature import unsign_headers, SignatureError

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


    def try_unsign_readers(self, request):
        try:
            return unsign_headers(self.config, request)
        except SignatureError as e:
            log.debug("Unauthorized request: %s", repr(e))
            return None

    @asyncio.coroutine
    def handle_request(self, request, writer):
        br, bw = None, None
        unsigned_request = self.try_unsign_readers(request)
        if unsigned_request:
            br, bw = yield from self.create_forwarder_backend()
            bw.write(unsigned_request)
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
