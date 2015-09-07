#!/usr/bin/env python3

import asyncio
import ssl
import logging

from utils import pipe_data
from common import nyapass_run

log = logging.getLogger("nyapass")


@asyncio.coroutine
def create_masq_backend():
    ret = yield from asyncio.open_connection("127.0.0.1", 3128)
    return ret


@asyncio.coroutine
def create_forwarder_backend():
    ret = yield from asyncio.open_connection("127.0.0.1", 3129)
    return ret


def is_authorized(request, writer):
    return b"\r\nX-Nyapass: cee85fee-9a98-4019-aa8c-7ee644fd74e3\r\n" in request


@asyncio.coroutine
def handle_request(request, writer):
    br, bw = None, None
    if is_authorized(request, writer):
        br, bw = yield from create_forwarder_backend()
    else:
        br, bw = yield from create_masq_backend()
    bw.write(request)
    return br, bw


def create_ssl_ctx():
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH,
    )
    ctx.load_cert_chain("nyapass-server.crt", "nyapass-server.key")
    ctx.options = (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
        ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers(r"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK")
    return ctx


def main():
    nyapass_run(
        request_handler=handle_request,
        host="0.0.0.0",
        port=8888,
        listener_ssl_ctx=create_ssl_ctx(),
    )


if __name__ == "__main__":
    logging.basicConfig(level="DEBUG")
    main()
