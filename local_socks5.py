#!/usr/bin/env python3

import asyncio
from asyncio import IncompleteReadError
from socket import inet_ntop, AF_INET, AF_INET6
from struct import unpack

from common import TerminateConnection
from local import ClientHandler


class SocksClientHandler(ClientHandler):
    @asyncio.coroutine
    def read_local_headers(self):
        reader = self._reader
        writer = self._writer
        try:
            yield from self._socks_init(reader, writer)
        except IncompleteReadError as e:
            raise EOFError("Incomplete SOCKS handshake") from e

        assert self.request_verb

    @asyncio.coroutine
    def _socks_init(self, reader, writer):
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
        ver, cmd, rsv, atyp = yield from reader.readexactly(4)
        code = None
        if ver != 5 or rsv != 0:
            self.warning("Unexpected bytes (%s, %s)", ver, rsv)
            code = b"\x01"

        if cmd != 1:
            self.warning("Unsupported command (%s)", cmd)
            code = b"\x07"

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
            code = b"\x08"

        if code:
            writer.write(
                b"\x05" + code + b"\x00\x01\x00\x00\x00\x00\x00\x00"
            )
            raise TerminateConnection

        port_bytes = yield from reader.readexactly(2)
        port, = unpack("!H", port_bytes)
        self._local_headers = \
            ("CONNECT %s:%s HTTP/1.1\r\n\r\n" % (addr, port)) \
            .encode("utf-8")

    @asyncio.coroutine
    def send_response_headers(self):
        assert self.request_verb == b"CONNECT"
        code = b"\x00" if self.response_code == 200 else b"\x05"
        self._writer.write(
            b"\x05" + code + b"\x00\x01\x42\x42\x42\x42\x42\x42"
        )
        if code != b"\x00":
            raise TerminateConnection
