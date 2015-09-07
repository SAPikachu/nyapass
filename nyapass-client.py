#!/usr/bin/env python3

import asyncio
import ssl
import logging

from common import nyapass_run

log = logging.getLogger("nyapass")


@asyncio.coroutine
def connect_to_server():
    ret = yield from asyncio.open_connection("127.0.0.1", 8888, ssl=create_ssl_ctx())
    return ret


@asyncio.coroutine
def handle_request(request, writer):
    request = request[:-2]
    request += b"X-Nyapass: cee85fee-9a98-4019-aa8c-7ee644fd74e3\r\n\r\n"

    br, bw = yield from connect_to_server()
    bw.write(request)
    return br, bw


def create_ssl_ctx():
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
    )
    ctx.options = (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
        ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def main():
    nyapass_run(
        request_handler=handle_request,
        host="0.0.0.0",
        port=3333,
    )


if __name__ == "__main__":
    logging.basicConfig(level="DEBUG")
    main()

