import asyncio
import ssl
import logging
from socket import SHUT_RDWR

from utils import pipe_data

try:
    from asyncio import ensure_future
except ImportError:
    from asyncio import async as ensure_future

log = logging.getLogger("nyapass")


def safe_close(obj):
    try:
        if obj:
            obj.close()
    except Exception:
        pass


class ConnectionHandler:
    def __init__(self, request_handler):
        self._request_handler = request_handler
        self.log = log.getChild(self.__class__.__name__)
        self.active_writers = []

    @asyncio.coroutine
    def handle_connection(self, reader, writer):
        self.log.debug("New connection from %s",
                       writer.get_extra_info("peername"))
        self.active_writers.append(writer)
        request = b""
        br, bw = None, None
        try:
            while True:
                line = yield from reader.readline()
                request += line

                if not line.strip():
                    break

            br, bw = yield from self._request_handler(request, writer)
            if not br or not bw:
                return

            self.active_writers.append(bw)
            tx_task = ensure_future(pipe_data(reader, bw))
            rx_task = ensure_future(pipe_data(br, writer))
            yield from asyncio.wait([tx_task, rx_task])
        except ConnectionError as e:
            log.debug("ConnectionError: %s", e)
        finally:
            safe_close(writer)
            safe_close(bw)
            self.active_writers.remove(writer)
            self.active_writers.remove(bw)


def nyapass_run(request_handler, host, port, listener_ssl_ctx=None):
    loop = asyncio.get_event_loop()
    handler = ConnectionHandler(request_handler)
    coro = asyncio.start_server(
        handler.handle_connection,
        host=host,
        port=port,
        loop=loop,
        ssl=listener_ssl_ctx,
    )
    server = loop.run_until_complete(coro)

    # Serve requests until CTRL+c is pressed
    log.info("Serving on {}".format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    for writer in handler.active_writers:
        safe_close(writer)

    loop.run_until_complete(server.wait_closed())
    while handler.active_writers:
        loop.run_until_complete(asyncio.sleep(0.1))

    loop.stop()
    loop.close()
