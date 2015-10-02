#!/usr/bin/env python3

import asyncio

from shadowsocks.encrypt import Encryptor

from common import TerminateConnection
from local_socks5 import SocksClientHandler


def wrap_streams(config, reader, writer):
    encryptor = Encryptor(
        config.shadowsocks_password or config.password,
        config.shadowsocks_method,
    )
    old_feed_data = reader.feed_data
    old_transport_write = writer.transport.write

    def _feed_data(data):
        if data:
            data = encryptor.decrypt(data)

        return old_feed_data(data)

    def _transport_write(data):
        if data:
            data = encryptor.encrypt(data)

        return old_transport_write(data)

    setattr(reader, "feed_data", _feed_data)
    setattr(writer.transport, "write", _transport_write)
    return reader, writer


class ShadowsocksClientHandler(SocksClientHandler):
    def __init__(self, *args, **kwargs):
        reader, writer = wrap_streams(
            kwargs["config"],
            kwargs["reader"],
            kwargs["writer"],
        )
        kwargs["reader"] = reader
        kwargs["writer"] = writer
        super().__init__(*args, **kwargs)

    @asyncio.coroutine
    def _socks_read_headers(self, reader, writer):
        self.debug("Handshake")
        addr = yield from self._socks_read_addr(reader)
        if not addr:
            raise TerminateConnection

        port = yield from self._socks_read_port(reader)
        return addr, port

    @asyncio.coroutine
    def _socks_send_response(self, success):
        if not success:
            raise TerminateConnection
