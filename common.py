#!/usr/bin/env python3

import asyncio
from asyncio import CancelledError, Task
try:
    from asyncio import ensure_future
except ImportError:
    from asyncio import async as ensure_future

from io import BytesIO
import logging
import re
from urllib.parse import urlparse, urlsplit, urlunsplit
from socket import IPPROTO_TCP, TCP_NODELAY

HTTP_REQUEST_RE = re.compile(
    b"^([A-Z]+) ([^\r\n]+) [A-Z]+/[0-9].[0-9]\r\n",
    flags=re.S,
)
HTTP_STATUS_CODE_RE = re.compile(
    b"^[A-Z]+/[0-9].[0-9] ([0-9]{3}) ",
    flags=re.S,
)
HTTP_IS_CHUNKED_RE = re.compile(
    b"\r\nTransfer-Encoding:\\s*(?:[^\r\n]+,\\s*)?chunked\\s*?\r\n",
    flags=re.S | re.I,
)
HTTP_CONTENT_LENGTH_RE = re.compile(
    b"\r\nContent-Length:\\s*([^\r\n]*?)\\s*?\r\n",
    flags=re.S | re.I,
)
HTTP_MULTIPLE_CONTENT_LENGTH_RE = re.compile(
    b"\r\nContent-Length:.*\r\nContent-Length:",
    flags=re.S | re.I,
)
HTTP_HOST_RE = re.compile(
    b"\r\nHost:\\s*([^\r\n]*?)\\s*?\r\n",
    flags=re.S | re.I,
)
HTTP_PROXY_HEADERS_RE = re.compile(
    b"\r\nProxy-[^:]*?:\\s*([^\r\n]*?)\\s*?\r\n",
    flags=re.S | re.I,
)
MAX_HEADER_LENGTH = 65536

log = logging.getLogger("nyapass")


class HttpProtocolError(ValueError):
    pass


class HeaderTooLongError(HttpProtocolError):
    def __init__(self, *args, buffered_data, **kwargs):
        super().__init__("Header is too long", *args, **kwargs)
        self.buffered_data = buffered_data


class TerminateConnection(Exception):
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


def enable_nodelay(writer):
    socket = writer.get_extra_info("socket")
    socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)


@asyncio.coroutine
def read_headers(reader):
    headers = b""
    while True:
        try:
            line = yield from reader.readline()
        except ValueError:
            # There is no \n in the last 64kB(?) of data.
            # These bytes are lost due to implementation of StreamReader,
            # but in this case it is likely that the client is sending
            # garbage to us, either by mistake or to probe existence of
            # nyapass. So we just replace the data block with another
            # pile of garbage, and let consumer handle it.
            log.warn("Client is sending garbage to us")
            line = b"A" * (MAX_HEADER_LENGTH + 1)

        headers += line

        if not line:
            raise EOFError("EOF while reading headers")

        if not line.strip():
            break

        if len(headers) > MAX_HEADER_LENGTH:
            raise HeaderTooLongError(buffered_data=headers)

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
        try:
            data = yield from reader.read(65536)
            if not data:
                raise EOFError("EOF in pipe_forever")
        except Exception:
            safe_close(writer)
            raise

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

    length_str = m.group(1).decode("utf-8")
    try:
        return int(length_str)
    except (TypeError, ValueError) as e:
        raise HttpProtocolError(
            "Invalid Content-Length: " + length_str,
        ) from e


def has_invalid_content_length(headers):
    if HTTP_MULTIPLE_CONTENT_LENGTH_RE.search(headers):
        return True

    try:
        get_content_length(headers)
    except HttpProtocolError:
        return True
    else:
        return False


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


class TeeStreamReader:
    """Buffer request body so that we can resend it later"""
    def __init__(self, inner):
        self._inner = inner
        self._limit = 524288
        self.reset()

    def __getattr__(self, name):
        return getattr(self._inner, name)

    @property
    def _len_buffered_data(self):
        return self._buffer.getbuffer().nbytes

    def _buffer_data(self, data):
        if not self.buffering_enabled or self.too_much_data:
            return

        if self._len_buffered_data + len(data) > self._limit:
            self.too_much_data = True
            self._buffer = None
            return

        self._buffer.write(data)

    def _ensure_buffer(self):
        if not self.buffering_enabled:
            raise ValueError("Buffering is not enabled")

        if self.too_much_data:
            raise ValueError("Data length limit has been exceeded")

    def reread_from_buffer(self):
        self._ensure_buffer()
        self._buffer.seek(0)

    @property
    def _should_reread_from_buffer(self):
        if not self.buffering_enabled or self.too_much_data:
            return False

        return self._buffer.tell() < self._len_buffered_data

    def reset(self):
        self._buffer = BytesIO()
        self.buffering_enabled = False
        self.too_much_data = False

    def get_buffered_data(self):
        self._ensure_buffer()
        return self._buffer.getvalue()

    @asyncio.coroutine
    def read(self, n=-1):
        if self._should_reread_from_buffer:
            data = self._buffer.read(n)
            if n == -1:
                assert not self._should_reread_from_buffer
                data += self.read()

            return data

        data = yield from self._inner.read(n)
        if data:
            self._buffer_data(data)

        return data

    @asyncio.coroutine
    def readexactly(self, n):
        if self._should_reread_from_buffer:
            data = self._buffer.read(n)
            if len(data) < n:
                assert not self._should_reread_from_buffer
                data += yield from self.readexactly(n - len(data))

            return data

        data = yield from self._inner.readexactly(n)
        if data:
            self._buffer_data(data)

        return data

    @asyncio.coroutine
    def readline(self):
        if self._should_reread_from_buffer:
            data = self._buffer.readline()
            assert data
            if data[-1] != b"\n":
                assert not self._should_reread_from_buffer
                data += yield from self.readline()

            return data

        data = yield from self._inner.readline()
        if data:
            self._buffer_data(data)

        return data


class ConnectionHandler:
    GLOBAL_CONNECTION_COUNTER = 0

    def __init__(self, reader, writer, config):
        self.config = config
        self.init_logging()
        self._num_handled_requests = 0
        self._reader = TeeStreamReader(reader)
        self._writer = writer
        self._active_writers = []
        self._remote_conn = None
        self.buffer_request_body = False
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
        self._reader.reset()
        self._send_request_future = None
        self.is_generated_response = False
        self.is_standalone_request = False

    @asyncio.coroutine
    def run(self):
        try:
            yield from self._run_impl()
        except TerminateConnection:
            pass
        except HttpProtocolError as e:
            self.warning("HttpProtocolError: %s", e)
        except (ConnectionError, EOFError) as e:
            self.debug("%s", e)
        except Exception as e:
            self.exception(e)

    @asyncio.coroutine
    def _run_impl(self):
        self.debug("Handling connection from %s",
                   self._writer.get_extra_info("peername"))
        self._active_writers.append(self._writer)
        try:
            while True:
                yield from self.handle_one_request()
                self._num_handled_requests += 1
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
        self.debug("handle_one_request")
        monitor = ensure_future(self.monitor_remote_connection())
        yield from self.read_local_headers()
        monitor.cancel()
        yield from asyncio.sleep(0)
        self.debug("Handling request (%s, %s)",
                   self.request_verb,
                   self.request_uri,)
        yield from self.process_request()
        yield from self.ensure_remote_connection()
        self.begin_send_request()
        try:
            yield from self.handle_one_response()
        except:
            self._send_request_future.cancel()
            raise
        else:
            if not self._send_request_future.done():
                # Last chance to clean up
                yield from asyncio.sleep(0)

            if not self._send_request_future.done():
                self._send_request_future.cancel()
                yield from asyncio.sleep(0)
                raise RuntimeError("Got response before request is sent")

            self._send_request_future.result()

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
    def request_has_body(self):
        assert self._local_headers
        if HTTP_IS_CHUNKED_RE.search(self._local_headers):
            return True

        return bool(get_content_length(self._local_headers))

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
        if has_invalid_content_length(self._remote_headers):
            self.respond_and_close(
                code=502,
                status="Bad Gateway",
                body="Unable to determine response length",
            )

        self.debug("Handling response (%s)", self.response_code)
        yield from self.process_response()
        yield from self.send_response()

    @asyncio.coroutine
    def send_response_headers(self):
        assert self._remote_headers
        self._writer.write(self._remote_headers)

    @asyncio.coroutine
    def send_response(self):
        assert self._writer
        self.debug("send_response")
        yield from self.send_response_headers()
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
    def respond_and_close(
        self, code, status, body=b"", extra_headers=b"",
        process_response=True,
    ):
        assert 200 <= code <= 999
        code = str(code).encode("utf-8")
        if isinstance(status, str):
            status = status.encode("utf-8")

        if isinstance(body, str):
            body = body.encode("utf-8")

        if isinstance(extra_headers, str):
            extra_headers = extra_headers.encode("utf-8")

        if extra_headers and extra_headers[-2:] != b"\r\n":
            extra_headers += b"\r\n"

        len_bytes = str(len(body)).encode("utf-8")
        self.debug("respond_and_close: %s %s", code, status)
        self._remote_headers = \
            b"HTTP/1.1 " + code + b" " + status + b"\r\n" + \
            b"Connection: close\r\n" + \
            b"Content-Length: " + len_bytes + b"\r\n" + \
            extra_headers + b"\r\n"
        self.is_generated_response = True

        if process_response:
            yield from self.process_response()

        yield from self.send_response_headers()
        if body and self.request_verb != b"HEAD":
            self._writer.write(body)

        yield from self._writer.drain()
        raise TerminateConnection

    @asyncio.coroutine
    def respond_bad_request(self):
        yield from self.respond_and_close(
            code=400,
            status="Bad Request",
            body="Bad Request",
        )

    @asyncio.coroutine
    def prepare_standalone_request(self):
        assert self._local_headers
        if has_invalid_content_length(self._local_headers):
            self.debug("Bad request: Invalid content length")
            yield from self.respond_bad_request()
            assert False  # Should be unreachable

        host = self.request_host
        if not host:
            self.debug("Bad request: No host in request")
            yield from self.respond_bad_request()
            assert False  # Should be unreachable

        if ":" in host:
            hostname, port = host.split(":", 1)
        else:
            hostname, port = host, 80

        try:
            port = int(port)
            if port < 0 or port > 65535:
                raise ValueError
        except (TypeError, ValueError):
            self.debug("Bad request: Invalid port number")
            yield from self.respond_bad_request()
            assert False  # Should be unreachable

        if self.request_verb != b"CONNECT":
            self.set_request_host(host)  # Sanitize host header
            m = self._request_re_match()
            uri = m.group(2)
            splitted = list(urlsplit(uri))
            if splitted[0] and splitted[0] != b"http":
                self.debug("Bad request: Unsupported scheme")
                yield from self.respond_bad_request()
                assert False  # Should be unreachable

            # Remove scheme and host
            splitted[0] = b""
            splitted[1] = b""
            fixed_url = urlunsplit(splitted)
            self._local_headers = \
                self._local_headers[:m.start(2)] + \
                fixed_url + \
                self._local_headers[m.end(2):]

        self._local_headers = HTTP_PROXY_HEADERS_RE.sub(
            b"\r\n", self._local_headers,
        )

        self.default_remote = (hostname, port)
        self.is_standalone_request = True

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
    def handle_10x(self):
        assert self.response_code
        while (100 <= self.response_code <= 199 and
               self.response_code != 101):
            self.debug("Forwarding status %s", self.response_code)
            yield from self.send_response_headers()
            yield from self._writer.drain()
            self._remote_headers = None
            yield from self.read_remote_headers(auto_handle_10x=False)

    @asyncio.coroutine
    def standalone_tunnel_created(self):
        self._remote_headers = \
            b"HTTP/1.1 200 Connection Established\r\n\r\n"

    @asyncio.coroutine
    def standalone_connection_error(self, e):
        yield from self.respond_and_close(
            code=502,
            status="Bad Gateway",
            body="Failed to connect to remote server: " + str(e),
        )
        assert False  # Should be unreachable

    def begin_send_request(self):
        assert not self._send_request_future
        self._send_request_future = ensure_future(self.send_request())

    @asyncio.coroutine
    def send_request(self):
        assert self._local_headers
        assert self._reader
        _, remote_writer = self._remote_conn
        assert remote_writer

        self.debug("send_request")
        if self.is_standalone_request and self.request_verb == b"CONNECT":
            self.debug("send_request: CONNECT")
            # No need to send anything
            return

        remote_writer.write(self._local_headers)
        if not self.request_has_body:
            yield from remote_writer.drain()
            return

        if self._reader.buffering_enabled:
            self._reader.reread_from_buffer()

        if self.buffer_request_body:
            self._reader.buffering_enabled = True

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

    def _request_re_match(self):
        headers = self._local_headers
        if not headers:
            return None

        if headers[:2] == "\r\n":
            # Broken clients?
            headers = headers[2:]

        m = HTTP_REQUEST_RE.match(headers)
        if not m:
            raise HttpProtocolError("Invalid HTTP request")

        return m

    @property
    def request_verb(self):
        m = self._request_re_match()
        if m:
            return m.group(1)

    @property
    def request_uri(self):
        m = self._request_re_match()
        if m:
            return m.group(2)

    @property
    def request_host(self):
        if not self._local_headers:
            return None

        uri = self.request_uri.decode("utf-8")
        if self.request_verb == b"CONNECT":
            return uri

        if "://" not in uri:
            m = HTTP_HOST_RE.search(self._local_headers)
            return m.group(1).decode("utf-8") if m else None

        parsed_uri = urlparse(uri)
        return parsed_uri.netloc

    @property
    def request_hostname(self):
        host = self.request_host
        if not host:
            return None

        return host.split(":")[0]

    def set_request_host(self, host, port=None):
        assert self._local_headers
        if isinstance(host, str):
            host = host.encode("utf-8")

        if port and port != 80:
            assert b":" not in host
            host = host + b":" + port

        self._local_headers = HTTP_HOST_RE.sub(
            b"\r\n", self._local_headers,
        )
        self._local_headers = HTTP_REQUEST_RE.sub(
            b"\\g<0>Host: " + host + b"\r\n", self._local_headers,
        )

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
    def read_remote_headers(self, auto_handle_10x=True):
        if self._remote_headers:
            return

        self.debug("Reading remote headers")
        if self.is_standalone_request and self.request_verb == b"CONNECT":
            yield from self.standalone_tunnel_created()
            return

        reader, _ = self._remote_conn
        self._remote_headers = yield from read_headers(reader)
        if auto_handle_10x:
            yield from self.handle_10x()

        assert self.response_code

    @asyncio.coroutine
    def connect_to_remote(self, remote, **kwargs):
        self.debug("Connecting to %s", remote)
        host, port = remote
        conn = yield from asyncio.open_connection(
            host=host, port=port, **kwargs
        )
        return conn

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
            try:
                yield from self.setup_remote_connection(remote)
            except Exception as e:
                if self.is_standalone_request:
                    yield from self.standalone_connection_error(e)

                raise

        return self._remote_conn

    @asyncio.coroutine
    def setup_remote_connection(self, remote):
        assert not self._remote_conn
        self._remote_conn = yield from self.connect_to_remote(remote)
        _, writer = self._remote_conn
        assert writer
        enable_nodelay(writer)
        self._active_writers.append(writer)
        self.connected_remote_endpoint = remote

    def destroy_remote_connection(self):
        if not self._remote_conn:
            return

        _, writer = self._remote_conn
        assert writer
        safe_close(writer)
        self._active_writers.remove(writer)
        self.connected_remote_endpoint = None
        self._remote_conn = None

    @property
    def is_active(self):
        return bool(self._active_writers)

    def close(self):
        self.destroy_remote_connection()
        [safe_close(x) for x in self._active_writers]

    def dump_info(self):
        self.debug("Dumping info:")
        self.debug("Local: %s, %s", self._reader, self._writer)
        self.debug("Remote: %s (%s)",
                   self._remote_conn,
                   self.connected_remote_endpoint)
        self.debug("Is active: %s", self.is_active)
        self.debug("Active writers: %s", self._active_writers)
        self.debug("Local headers: %s", self._local_headers)
        self.debug("Remote headers: %s", self._remote_headers)
        self.debug("Number of handled requests: %s",
                   self._num_handled_requests)


class Nyapass:
    def __init__(
        self, handler_factory, config, listener_ssl_ctx=None, port=None,
    ):
        self._handler_factory = handler_factory
        self.config = config
        self.listener_ssl_ctx = listener_ssl_ctx
        self.port = port
        self.log = log.getChild(self.__class__.__name__)
        self.active_handlers = []

    @asyncio.coroutine
    def handle_connection(self, reader, writer):
        enable_nodelay(writer)
        handler = self._handler_factory(
            reader=reader,
            writer=writer,
            config=self.config,
        )
        self.active_handlers.append(handler)
        try:
            yield from handler.run()
        except Exception as e:
            self.log.error("Unexpected error from handler.run")
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

    @asyncio.coroutine
    def init(self):
        config = self.config
        self.server = yield from asyncio.start_server(
            self.handle_connection,
            host=config.listen_host,
            port=self.port or config.port,
            ssl=self.listener_ssl_ctx,
        )
        self.log.info(
            "%s serving on %s",
            getattr(
                self._handler_factory,
                "__name__",
                str(self._handler_factory)
            ),
            self.server.sockets[0].getsockname(),
        )

    @asyncio.coroutine
    def shutdown(self):
        server = self.server
        server.close()
        yield from self.server.wait_closed()
        self.close_all()
        for i in range(20):
            if not self.has_active_connection:
                break

            yield from asyncio.sleep(0.1)
        else:
            self.log.warning("Some connections are not properly closed")
            for handler in self.active_handlers:
                handler.dump_info()


def detect_nt():
    import os
    import sys
    if os.name == 'nt':
        if sys.version_info < (3, 5, 0):
            log.fatal(
                "On Windows, Python 3.5+ is required to run nyapass"
            )
            sys.exit(1)

        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)


def setup_signal():
    """By default Python won't exit on SIGTERM, we exit on that."""
    def _handler(signum, frame):
        raise KeyboardInterrupt

    import signal
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handler)


def nyapass_run(handler_factory, config, listener_ssl_ctx=None):
    instance = Nyapass(
        handler_factory=handler_factory,
        config=config,
        listener_ssl_ctx=listener_ssl_ctx,
    )
    nyapass_run_instances(config, instance)


def nyapass_run_instances(config, *instances):
    detect_nt()
    setup_signal()
    if config.use_custom_dns_resolver:
        try:
            from dns.resolver import (
                Cache, get_default_resolver, override_system_resolver,
            )
        except ImportError:
            log.warning(
                "dnspython3 is not installed, "
                "can't switch to custom resolver"
            )
        else:
            resolver = get_default_resolver()
            resolver.cache = Cache()
            override_system_resolver(resolver)

    loop = asyncio.get_event_loop()
    if config.threadpool_workers:
        from concurrent.futures import ThreadPoolExecutor
        loop.set_default_executor(ThreadPoolExecutor(
            max_workers=config.threadpool_workers,
        ))

    loop.run_until_complete(asyncio.gather(
        *[x.init() for x in instances]
    ))

    def _cleanup(disable_pending_task_warnings=False):
        # Close the server
        loop.run_until_complete(asyncio.gather(
            *[x.shutdown() for x in instances]
        ))
        loop.stop()
        if disable_pending_task_warnings:
            [t.result() for t in Task.all_tasks()]

        loop.close()

    try:
        loop.run_forever()
    except SystemExit:
        try:
            _cleanup(True)
        except:
            pass

        raise
    except KeyboardInterrupt:
        pass

    _cleanup()
