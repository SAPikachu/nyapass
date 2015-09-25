#!/usr/bin/env python3

import asyncio
import ssl
import logging
import sys
from functools import partial

from common import nyapass_run, ConnectionHandler
from config import Config
from signature import sign_headers, unsign_headers, SignatureError


class ClientHandler(ConnectionHandler):
    def __init__(self, divert_cache, ssl_ctx, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._divert_cache = divert_cache
        self.buffer_request_body = self.config.divert_banned_requests
        self._ssl_ctx = ssl_ctx

    def reset_request(self):
        super().reset_request()
        self._local_headers_unsigned = None
        self._is_diverted_request = False
        self.default_remote = (
            self.config.server_host,
            self.config.server_port,
        )

    @property
    def should_divert(self):
        if not self.config.divert_banned_requests:
            return False

        if self._is_diverted_request:
            return True

        if not self._local_headers:
            return False

        host = self.request_hostname.lower()
        if host in self._divert_cache:
            return True

        if not self._remote_headers:
            return False

        ret = self.response_code == 410 and \
            b"\r\nX-Nyapass-Status: banned\r\n" in self._remote_headers
        if ret:
            self._divert_cache[host] = True

        return ret

    @asyncio.coroutine
    def divert_request(self):
        assert not self._is_diverted_request
        self.debug("Diverting request")
        self._is_diverted_request = True
        if self._local_headers_unsigned:
            self._local_headers = self._local_headers_unsigned

        yield from self.prepare_standalone_request()

    @asyncio.coroutine
    def process_request(self):
        if self.should_divert:
            yield from self.divert_request()
            return

        self._local_headers_unsigned = self._local_headers
        self._local_headers = sign_headers(
            self.config,
            self._local_headers,
        )

    @asyncio.coroutine
    def process_response(self):
        if self._is_diverted_request:
            return

        try:
            self._remote_headers = unsign_headers(
                self.config,
                self._remote_headers,
            )
        except SignatureError:
            self.critical(
                "Failed to verify response signature, server may be "
                "improperly configured or we are experiencing MITM attack"
            )
            sys.exit(1)

        if self.should_divert:
            self._send_request_future.cancel()
            yield from asyncio.sleep(0)
            assert self._send_request_future.done()
            self._send_request_future = None

            self.destroy_remote_connection()
            self._remote_headers = None
            yield from self.divert_request()
            if self.request_has_body and self._reader.too_much_data:
                yield from self.respond_and_close(
                    code=503,
                    status="Service Unavailable",
                    body="Diverting request, please retry.",
                )
                assert False  # Unreachable

            yield from self.ensure_remote_connection()
            self.begin_send_request()
            yield from self.read_remote_headers()

    @asyncio.coroutine
    def connect_to_remote(self, remote, **kwargs):
        if not self._is_diverted_request:
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
    divert_cache = {}
    ssl_ctx = create_ssl_ctx(config)
    nyapass_run(
        handler_factory=partial(
            ClientHandler,
            divert_cache=divert_cache,
            ssl_ctx=ssl_ctx,
        ),
        config=config,
    )


if __name__ == "__main__":
    main(Config("client"))
