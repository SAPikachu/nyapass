#!/usr/bin/env python3

import asyncio
import ssl
import logging

from common import nyapass_run, ConnectionHandler
from config import Config
from signature import unsign_headers, SignatureError


class ServerHandler(ConnectionHandler):
    def try_unsign_readers(self, request):
        try:
            return unsign_headers(self.config, request)
        except SignatureError as e:
            self.debug("Unauthorized request: %s", repr(e))
            return None

    @asyncio.coroutine
    def process_request(self):
        unsigned_headers = self.try_unsign_readers(self._local_headers)
        if unsigned_headers:
            self._local_headers = unsigned_headers
            self.default_remote = \
                self.config.forwarder_host, self.config.forwarder_port
        else:
            self.default_remote = \
                self.config.masq_host, self.config.masq_port


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
        handler_factory=ServerHandler,
        config=config,
        listener_ssl_ctx=create_ssl_ctx(config),
    )


if __name__ == "__main__":
    main(Config("server"))
