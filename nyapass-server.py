#!/usr/bin/env python3

import asyncio
import ssl
import logging

from utils import pipe_data

try:
    from asyncio import ensure_future
except ImportError:
    from asyncio import async as ensure_future

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
def handle_connection(reader, writer):
    request = b""
    br, bw = None, None
    try:
        while True:
            line = yield from reader.readline()
            request += line
            if not line.strip():
                break

        if is_authorized(request, writer):
            br, bw = yield from create_forwarder_backend()
        else:
            br, bw = yield from create_masq_backend()
        bw.write(request)
        tx_task = ensure_future(pipe_data(reader, bw))
        rx_task = ensure_future(pipe_data(br, writer))
        yield from asyncio.wait([tx_task, rx_task])
    except ConnectionError as e:
        log.debug("ConnectionError: %s", e)
    finally:
        try:
            writer.close()
        except Exception:
            pass

        try:
            if bw:
                bw.close()
        except Exception:
            pass


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
    ctx = create_ssl_ctx()
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_connection, "0.0.0.0", 8888, loop=loop, ssl=ctx)
    server = loop.run_until_complete(coro)

    # Serve requests until CTRL+c is pressed
    print("Serving on {}".format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == "__main__":
    main()
