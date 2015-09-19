#!/usr/bin/env python3

import asyncio
from asyncio import CancelledError
try:
    from asyncio import ensure_future
except ImportError:
    from asyncio import async as ensure_future

import logging
import re

HTTP_VERB_RE = re.compile(
    b"^([A-Z]+) [^\r\n]+ [A-Z]+/[0-9].[0-9]\r\n",
    flags=re.S,
)
HTTP_STATUS_CODE_RE = re.compile(
    b"^[A-Z]+/[0-9].[0-9] ([0-9]{3}) ",
    flags=re.S,
)
HTTP_IS_CHUNKED_RE = re.compile(
    b"\r\nTransfer-Encoding:\\s*(?:[^\r\n]+,\\s*)?chunked\\s*\r\n",
    flags=re.S | re.I,
)
HTTP_CONTENT_LENGTH_RE = re.compile(
    b"\r\nContent-Length:\\s*([^\r\n]*?)\\s*\r\n",
    flags=re.S | re.I,
)
log = logging.getLogger("nyapass")


class HttpProtocolError(ValueError):
    pass


def safe_close(obj):
    if not obj:
        return

    if hasattr(obj, "can_write_eof") and obj.can_write_eof():
        try:
            obj.write_eof()
        except Exception:
            pass

    try:
        obj.close()
    except Exception:
        pass


@asyncio.coroutine
def read_headers(reader):
    headers = b""
    while True:
        line = yield from reader.readline()
        headers += line

        if not line:
            raise EOFError("EOF while reading headers")

        if not line.strip():
            break

    return headers


@asyncio.coroutine
def pipe_chunked_body(reader, writer):
    try:
        while True:
            size_line = yield from reader.readline()
            writer.write(size_line)

            # Strip chunk extension
            size_str = size_line.decode("utf-8").strip().split(";")[0]
            size = int(size_str, base=16)
            if not size:
                break

            # Size doesn't include trailing CRLF
            yield from pipe_exact(reader, writer, size + 2)

        # Chunked trailer
        while True:
            line = yield from reader.readline()
            writer.write(line)
            if line == b"\r\n":
                break

        yield from writer.drain()
    except (ValueError, TypeError) as e:
        raise HttpProtocolError("Invalid chunked body") from e


@asyncio.coroutine
def pipe_forever(reader, writer):
    while True:
        data = yield from reader.read(65536)
        if not data:
            raise EOFError("EOF in pipe_forever")

        writer.write(data)
        yield from writer.drain()


@asyncio.coroutine
def pipe_exact(reader, writer, length):
    while length > 0:
        data = yield from reader.read(min(length, 65536))
        if not data:
            raise EOFError("EOF in pipe_exact, %s bytes remaining" %
                           (length,))

        length -= len(data)
        assert length >= 0
        writer.write(data)
        yield from writer.drain()


def get_content_length(headers):
    m = HTTP_CONTENT_LENGTH_RE.search(headers)
    if not m:
        return None

    try:
        return int(m.group(1))
    except (TypeError, ValueError) as e:
        raise HttpProtocolError(
            "Invalid Content-Length: " + m.group(1),
        ) from e


@asyncio.coroutine
def pipe_body_generic(headers, reader, writer):
    assert headers
    assert reader
    assert writer

    if HTTP_IS_CHUNKED_RE.search(headers):
        yield from pipe_chunked_body(reader, writer)
        return True

    content_length = get_content_length(headers)
    if content_length:
        yield from pipe_exact(reader, writer, content_length)
        return True

    return content_length == 0


class ConnectionHandler:
    GLOBAL_CONNECTION_COUNTER = 0

    def __init__(self, reader, writer, config):
        self.config = config
        self.init_logging()
        self._reader = reader
        self._writer = writer
        self._active_writers = []
        self._remote_conn = None
        self.reset_request()

    def init_logging(self):
        sn = self.__class__.GLOBAL_CONNECTION_COUNTER
        self.__class__.GLOBAL_CONNECTION_COUNTER += 1
        self._logger = \
            log.getChild(self.__class__.__name__).getChild(str(sn))
        for f in ("log", "debug", "info", "warn", "warning", "error",
                  "critical", "exception", "isEnabledFor",):
            assert not hasattr(self, f)
            setattr(self, f, getattr(self._logger, f))

    def reset_request(self):
        self._local_headers = None
        self._remote_headers = None

    @asyncio.coroutine
    def run(self):
        self.debug("Handling connection from %s",
                   self._writer.get_extra_info("peername"))
        self._active_writers.append(self._writer)
        try:
            while True:
                yield from self.handle_one_request()
        finally:
            self.destroy_remote_connection()
            safe_close(self._writer)
            self._active_writers.remove(self._writer)
            assert not self.is_active

    @asyncio.coroutine
    def monitor_remote_connection(self):
        if not self._remote_conn:
            return

        reader, _ = self._remote_conn
        try:
            b = yield from reader.read()
            if b:
                self.warning("Got bytes without sending requests: %s", b)

            self.close()
        except CancelledError:
            pass

    @asyncio.coroutine
    def handle_one_request(self):
        monitor = ensure_future(self.monitor_remote_connection())
        yield from self.read_local_headers()
        monitor.cancel()
        self.debug("Handling request (%s)", self.request_verb)
        yield from self.process_request()
        yield from self.ensure_remote_connection()
        yield from asyncio.wait_for(asyncio.gather(
            self.send_request(),
            self.handle_one_response(),
        ), timeout=None)
        self.reset_request()

    @property
    def is_tunnel_request(self):
        if self.request_verb == b"CONNECT" and \
           200 <= self.response_code <= 299:
            return True

        if self.response_code == 101:  # 101 Switching Protocol
            return True

        return False

    @property
    def response_has_body(self):
        # RFC 7230 Section 3.3.3
        if self.request_verb == b"HEAD":
            return False

        if 100 <= self.response_code <= 199:
            return False

        if self.response_code in (204, 304):
            return False

        if HTTP_IS_CHUNKED_RE.search(self._remote_headers):
            return True

        if get_content_length(self._remote_headers) == 0:
            return False

        return True

    @asyncio.coroutine
    def handle_one_response(self):
        yield from self.read_remote_headers()
        assert self.response_code
        if self.response_code == 100:
            yield from self.handle_100_continue()

        self.debug("Handling response (%s)", self.response_code)
        yield from self.process_response()
        yield from self.send_response()

    @asyncio.coroutine
    def send_response(self):
        assert self._writer
        assert self._remote_headers
        self._writer.write(self._remote_headers)
        if self.is_tunnel_request:
            self.debug("Is tunnel request")
            yield from self.run_tunnel()
            assert False  # Should be unreachable

        if not self.response_has_body:
            yield from self._writer.drain()
            return

        remote_reader, _ = self._remote_conn
        assert remote_reader
        is_normal_resp = yield from pipe_body_generic(
            self._remote_headers, remote_reader, self._writer,
        )
        if is_normal_resp:
            return

        # Content length not defined
        yield from self.run_tunnel()
        assert False  # Should be unreachable

    @asyncio.coroutine
    def process_request(self):
        pass

    @asyncio.coroutine
    def process_response(self):
        pass

    @asyncio.coroutine
    def run_tunnel(self):
        assert self._reader
        assert self._writer
        remote_reader, remote_writer = self._remote_conn
        assert remote_reader
        assert remote_writer

        self.debug("Tunneling")
        yield from asyncio.wait_for(asyncio.gather(
            pipe_forever(self._reader, remote_writer),
            pipe_forever(remote_reader, self._writer),
        ), timeout=None)

    @asyncio.coroutine
    def handle_100_continue(self):
        assert self.response_code == 100
        self.debug("100 Continue")
        self._writer.write(self._remote_headers)
        yield from self._writer.drain()
        self._remote_headers = None
        yield from self.read_remote_headers()

    @asyncio.coroutine
    def send_request(self):
        assert self._local_headers
        assert self._reader
        _, remote_writer = self._remote_conn
        assert remote_writer

        remote_writer.write(self._local_headers)
        yield from pipe_body_generic(
            self._local_headers,
            self._reader,
            remote_writer,
        )

    @asyncio.coroutine
    def read_local_headers(self):
        if self._local_headers:
            return

        self.debug("Reading local headers")
        self._local_headers = yield from read_headers(self._reader)
        assert self.request_verb

    @property
    def request_verb(self):
        headers = self._local_headers
        if not headers:
            return None

        if headers[:2] == "\r\n":
            # Broken clients?
            headers = headers[2:]

        m = HTTP_VERB_RE.match(headers)
        if not m:
            raise HttpProtocolError("Invalid HTTP request")

        return m.group(1)

    @property
    def response_code(self):
        headers = self._remote_headers
        if not headers:
            return None

        if headers[:2] == "\r\n":
            # Broken clients?
            headers = headers[2:]

        m = HTTP_STATUS_CODE_RE.match(headers)
        if not m:
            raise HttpProtocolError("Invalid HTTP response")

        return int(m.group(1))

    @asyncio.coroutine
    def read_remote_headers(self):
        if self._remote_headers:
            return

        self.debug("Reading remote headers")
        reader, _ = self._remote_conn
        self._remote_headers = yield from read_headers(reader)
        assert self.response_code

    @asyncio.coroutine
    def connect_to_remote(self, remote, **kwargs):
        self.debug("Connecting to %s", remote)
        host, port = remote
        conn = yield from asyncio.open_connection(
            host=host, port=port, **kwargs
        )
        return conn

    @property
    def connected_remote_endpoint(self):
        if not self._remote_conn:
            return None

        _, writer = self._remote_conn
        assert writer
        return writer.get_extra_info("peername")

    @asyncio.coroutine
    def get_remote(self):
        return self.default_remote

    @asyncio.coroutine
    def ensure_remote_connection(self):
        remote = yield from self.get_remote()
        assert remote

        if self._remote_conn:
            recreate = False
            if self.connected_remote_endpoint != remote:
                recreate = True
                self.debug("Destroying old connection to %s",
                           self.connected_remote_endpoint)
            else:
                reader, _ = self._remote_conn
                if reader.at_eof() or reader.exception():
                    recreate = True
                    self.debug("Recreating broken connection")

            if recreate:
                self.destroy_remote_connection()
                assert not self._remote_conn

        if not self._remote_conn:
            yield from self.setup_remote_connection(remote)

        return self._remote_conn

    @asyncio.coroutine
    def setup_remote_connection(self, remote):
        assert not self._remote_conn
        self._remote_conn = yield from self.connect_to_remote(remote)
        _, writer = self._remote_conn
        assert writer
        self._active_writers.append(writer)

    def destroy_remote_connection(self):
        if not self._remote_conn:
            return

        _, writer = self._remote_conn
        assert writer
        safe_close(writer)
        self._active_writers.remove(writer)
        self._remote_conn = None

    @property
    def is_active(self):
        return bool(self._active_writers)

    def close(self):
        self.destroy_remote_connection()
        [safe_close(x) for x in self._active_writers]


class Nyapass:
    def __init__(self, handler_factory, config):
        self._handler_factory = handler_factory
        self.config = config
        self.log = log.getChild(self.__class__.__name__)
        self.active_handlers = []

    @asyncio.coroutine
    def handle_connection(self, reader, writer):
        handler = self._handler_factory(
            reader=reader,
            writer=writer,
            config=self.config,
        )
        self.active_handlers.append(handler)
        try:
            yield from handler.run()
        except HttpProtocolError as e:
            self.log.warning("HttpProtocolError: %s", e)
        except (ConnectionError, EOFError) as e:
            self.log.debug("%s", e)
        except Exception as e:
            self.log.exception(e)
        finally:
            handler.close()
            while handler.is_active:
                yield from asyncio.sleep(0.1)

            self.active_handlers.remove(handler)

    def close_all(self):
        [x.close() for x in self.active_handlers]

    @property
    def has_active_connection(self):
        return bool(self.active_handlers)


def nyapass_run(handler_factory, config, listener_ssl_ctx=None):
    loop = asyncio.get_event_loop()
    instance = Nyapass(handler_factory=handler_factory, config=config)
    coro = asyncio.start_server(
        instance.handle_connection,
        host=config.listen_host,
        port=config.port,
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
    instance.close_all()

    loop.run_until_complete(server.wait_closed())
    while instance.has_active_connection:
        loop.run_until_complete(asyncio.sleep(0.1))

    loop.stop()
    loop.close()
