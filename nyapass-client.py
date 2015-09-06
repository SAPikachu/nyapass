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
def connect_to_server():
    ret = yield from asyncio.open_connection("127.0.0.1", 8888, ssl=create_ssl_ctx())
    return ret


@asyncio.coroutine
def handle_connection(reader, writer):
    request = b""
    br, bw = None, None
    try:
        while True:
            is_first_line = not request
            line = yield from reader.readline()
            request += line
            if is_first_line:
                request += b"X-Nyapass: cee85fee-9a98-4019-aa8c-7ee644fd74e3\r\n"

            if not line.strip():
                break

        br, bw = yield from connect_to_server()
        bw.write(request)
        tx_task = ensure_future(pipe_data(reader, bw))
        rx_task = ensure_future(pipe_data(br, writer))
        yield from asyncio.wait([tx_task, rx_task])
    except ConnectionError as e:
        raise
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
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_connection, "0.0.0.0", 3333, loop=loop)
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
