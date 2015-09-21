#!/usr/bin/env python3

import asyncio
import ssl
import logging
import re
from functools import partial
from socket import gaierror, IPPROTO_TCP

from common import nyapass_run, ConnectionHandler
from config import Config
from signature import sign_headers, unsign_headers, SignatureError

FILTERED_RESPONSE_HEADERS = re.compile(
    b"\r\nX-Nyapass[^:]*:\s*[^\r\n]+",
    flags=re.S | re.I,
)


class BannedNetworks:
    def __init__(
        self,
        list_file,
        cache_seconds=60*60*24,
        neg_cache_seconds=60,
    ):
        self.log = logging.getLogger(self.__class__.__name__)
        self._banned_hosts = dict()
        self._load_banned_networks(list_file)
        self.cache_seconds = cache_seconds
        self.neg_cache_seconds = neg_cache_seconds

    @asyncio.coroutine
    def is_banned(self, host):
        if not self._banned_networks:
            return False

        host = host.lower()
        cached_result = self._banned_hosts.get(host, None)
        if cached_result is not None:
            return cached_result

        loop = asyncio.get_event_loop()
        try:
            addresses = yield from loop.getaddrinfo(
                host, None, proto=IPPROTO_TCP,
            )
        except gaierror as e:
            self.log.warning("Failed to resolve %s: %s", host, e)
            self._banned_hosts[host] = False
            loop.call_later(
                self.neg_cache_seconds,
                lambda: self._banned_hosts.pop(host, None),
            )
            return

        is_banned = False
        for _, _, _, _, (ip, _) in addresses:
            is_banned = bool(self._banned_networks.search_best(ip))
            if is_banned:
                break

        self._banned_hosts[host] = is_banned
        loop.call_later(
            self.cache_seconds,
            lambda: self._banned_hosts.pop(host, None),
        )
        return is_banned

    def _load_banned_networks(self, list_file):
        self._banned_networks = None
        if not list_file:
            return

        try:
            from radix import Radix
        except ImportError:
            self.log.warning(
                "py-radix is not installed, can't ban networks",
            )
            return

        try:
            with open(list_file, "r") as f:
                self._banned_networks = Radix()
                networks = 0
                for l in f:
                    l = l.strip()
                    if not l or l.startswith("#"):
                        continue

                    try:
                        self._banned_networks.add(l)
                    except (TypeError, ValueError) as e:
                        self.log.warning(
                            "Invalid banned network: %s", l,
                        )
                    else:
                        networks += 1

            self.log.info("Loaded %s banned networks", networks)
        except Exception as e:
            self.log.warning(
                "Failed to load banned network list: %s", e,
            )


class ServerHandler(ConnectionHandler):
    def __init__(self, banned_net, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._banned_net = banned_net

    def try_unsign_readers(self, request):
        try:
            return unsign_headers(self.config, request)
        except SignatureError as e:
            self.debug("Unauthorized request: %s", repr(e))
            return None

    @asyncio.coroutine
    def send_banned_response(self):
        yield from self.respond_and_close(
            code=410,
            status="Gone",
            body="Nyapass: banned",
            extra_headers="X-Nyapass-Status: banned",
        )

    @asyncio.coroutine
    def process_request(self):
        unsigned_headers = self.try_unsign_readers(self._local_headers)
        self._should_sign_response = bool(unsigned_headers)
        if not unsigned_headers:
            self.set_request_host(
                self.config.masq_host,
                self.config.masq_port,
            )
            self.default_remote = \
                self.config.masq_host, self.config.masq_port

            return

        banned = yield from self._banned_net.is_banned(
            self.request_hostname,
        )
        if banned:
            self.default_remote = None
            yield from self.send_banned_response()
            return

        self._local_headers = unsigned_headers
        self.default_remote = \
            self.config.forwarder_host, self.config.forwarder_port

    @asyncio.coroutine
    def process_response(self):
        if self._should_sign_response:
            if not self.is_generated_response:
                self._remote_headers = FILTERED_RESPONSE_HEADERS.sub(
                    b"", self._remote_headers,
                )

            self._remote_headers = sign_headers(
                self.config,
                self._remote_headers,
            )


def create_ssl_ctx(config):
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH,
    )
    ctx.load_cert_chain(config.tls_cert, config.tls_key)
    ctx.options = (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
        ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers(config.tls_ciphers)
    return ctx


def main(config):
    logging.basicConfig(level=config.log_level)
    banned_net = BannedNetworks(config.banned_network_list)
    nyapass_run(
        handler_factory=partial(ServerHandler, banned_net=banned_net),
        config=config,
        listener_ssl_ctx=create_ssl_ctx(config),
    )


if __name__ == "__main__":
    main(Config("server"))
