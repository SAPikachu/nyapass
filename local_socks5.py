#!/usr/bin/env python3

import asyncio
from asyncio import IncompleteReadError
from socket import inet_ntop, AF_INET, AF_INET6
from struct import unpack

from common import TerminateConnection
from local import ClientHandler


class SocksClientHandler(ClientHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._hijack_http = False

    @asyncio.coroutine
    def read_local_headers(self):
        if self._hijack_http:
            ret = yield from super().read_local_headers()
            return ret

        reader = self._reader
        writer = self._writer
        try:
            yield from self._socks_init(reader, writer)
        except IncompleteReadError as e:
            raise EOFError("Incomplete SOCKS handshake") from e

        assert self.request_verb

    @asyncio.coroutine
    def _socks_read_addr(self, reader):
        addr = None
        atyp, = yield from reader.readexactly(1)
        if atyp == 1:
            addr_bytes = yield from reader.readexactly(4)
            addr = inet_ntop(AF_INET, addr_bytes)
        elif atyp == 4:
            addr_bytes = yield from reader.readexactly(16)
            addr = "[%s]" % (inet_ntop(AF_INET6, addr_bytes),)
        elif atyp == 3:
            domain_len = yield from reader.readexactly(1)
            addr_bytes = yield from reader.readexactly(ord(domain_len))
            addr = addr_bytes.decode("ascii")
        else:
            self.warning("Unsupported address type (%s)", atyp)

        return addr

    @asyncio.coroutine
    def _socks_read_port(self, reader):
        port_bytes = yield from reader.readexactly(2)
        port, = unpack("!H", port_bytes)
        return port

    @asyncio.coroutine
    def _socks_read_headers(self, reader, writer):
        self.debug("Handshake")
        ver = yield from reader.readexactly(1)
        if ver != b"\x05":
            self.warning("Invalid version byte: %s", ver)
            raise TerminateConnection

        nmethod = yield from reader.readexactly(1)
        methods = yield from reader.readexactly(ord(nmethod))
        self.debug("Methods: %s", methods)
        if b"\x00" not in methods:
            self.warning("No acceptable method")
            writer.write(b"\x05\xff")
            raise TerminateConnection

        writer.write(b"\x05\x00")
        ver, cmd, rsv = yield from reader.readexactly(3)
        code = None
        if ver != 5 or rsv != 0:
            self.warning("Unexpected bytes (%s, %s)", ver, rsv)
            code = b"\x01"

        if cmd != 1:
            self.warning("Unsupported command (%s)", cmd)
            code = b"\x07"

        addr = yield from self._socks_read_addr(reader)
        if not addr:
            code = b"\x08"

        if code:
            writer.write(
                b"\x05" + code + b"\x00\x01\x00\x00\x00\x00\x00\x00"
            )
            raise TerminateConnection

        port = yield from self._socks_read_port(reader)
        return addr, port

    @asyncio.coroutine
    def _socks_send_response(self, success):
        code = b"\x00" if success else b"\x05"
        self._writer.write(
            b"\x05" + code + b"\x00\x01\x42\x42\x42\x42\x42\x42"
        )
        if code != b"\x00":
            raise TerminateConnection

    @asyncio.coroutine
    def _socks_init(self, reader, writer):
        addr, port = yield from self._socks_read_headers(reader, writer)
        if port == 80 and self.config.socks5_hijack_http:
            self._hijack_http = True
            yield from self._socks_send_response(True)
            yield from self.read_local_headers()
        else:
            self._local_headers = \
                ("CONNECT %s:%s HTTP/1.1\r\n\r\n" % (addr, port)) \
                .encode("utf-8")

    @asyncio.coroutine
    def send_response_headers(self):
        if self._hijack_http:
            ret = yield from super().send_response_headers()
            return ret

        assert self.request_verb == b"CONNECT"
        yield from self._socks_send_response(self.response_code == 200)
