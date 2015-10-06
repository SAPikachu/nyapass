#!/usr/bin/env python3

import asyncio
import ssl
import logging
import os
import sys
import json
from hashlib import sha512

from common import nyapass_run, ConnectionHandler
from signature import sign_headers, unsign_headers, SignatureError

log = logging.getLogger("nyapass")


class ClientHandler(ConnectionHandler):
    def __init__(self, divert_cache, ssl_ctx, manager, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._divert_cache = divert_cache
        self.buffer_request_body = self.config.divert_banned_requests
        self._ssl_ctx = ssl_ctx
        self._manager = manager

    def reset_request(self):
        super().reset_request()
        self._local_headers_unsigned = None
        self._is_diverted_request = False
        self.default_remote = (
            self.config.server_host,
            self.config.server_port,
        )

    @property
    def should_divert(self):
        if not self.config.divert_banned_requests:
            return False

        if self._is_diverted_request:
            return True

        if not self._local_headers:
            return False

        host = self.request_hostname.lower()
        if host in self._divert_cache:
            return True

        if not self._remote_headers:
            return False

        ret = self.response_code == 410 and \
            b"\r\nX-Nyapass-Status: banned\r\n" in self._remote_headers
        if ret:
            self._divert_cache[host] = True

        return ret

    @asyncio.coroutine
    def divert_request(self):
        assert not self._is_diverted_request
        self.debug("Diverting request")
        self._is_diverted_request = True
        if self._local_headers_unsigned:
            self._local_headers = self._local_headers_unsigned

        yield from self.prepare_standalone_request()

    @asyncio.coroutine
    def process_request(self):
        if self.should_divert:
            yield from self.divert_request()
            return

        self._local_headers_unsigned = self._local_headers
        self._local_headers = sign_headers(
            self.config,
            self._local_headers,
        )

    @asyncio.coroutine
    def process_response(self):
        if self._is_diverted_request:
            return

        try:
            self._remote_headers = unsign_headers(
                self.config,
                self._remote_headers,
            )
        except SignatureError:
            self.critical(
                "Failed to verify response signature, server may be "
                "improperly configured or we are experiencing MITM attack"
            )
            self.dump_info()
            sys.exit(1)

        if self.should_divert:
            fut = self._send_request_future
            fut.cancel()
            yield from asyncio.sleep(0)
            assert fut.done()

            self.destroy_remote_connection()
            self._remote_headers = None
            yield from self.divert_request()
            if self.request_has_body and self._reader.too_much_data:
                yield from self.respond_and_close(
                    code=503,
                    status="Service Unavailable",
                    body="Diverting request, please retry.",
                )
                assert False  # Unreachable

            yield from self.ensure_remote_connection()
            assert self._send_request_future == fut
            self._send_request_future = None
            self.begin_send_request()
            yield from self.read_remote_headers()

    @asyncio.coroutine
    def connect_to_remote(self, remote, **kwargs):
        if not self._is_diverted_request:
            kwargs["ssl"] = self._ssl_ctx

        ret = yield from super().connect_to_remote(
            remote,
            **kwargs
        )

        if not self._is_diverted_request:
            self._manager.validate_remote(remote, ret[1])

        return ret


class ClientHandlerManager:
    def __init__(self, config, handler_cls=ClientHandler):
        self.log = log.getChild(self.__class__.__name__)
        self.config = config
        self._handler_cls = handler_cls
        self._ssl_ctx = create_ssl_ctx(config)
        self._divert_cache = {}
        self._known_hosts = {}
        if self.config.known_hosts_file:
            self.config.known_hosts_file = os.path.expanduser(
                self.config.known_hosts_file,
            )
            self._read_known_hosts()

    def __call__(self, *args, **kwargs):
        return self._handler_cls(
            *args,
            divert_cache=self._divert_cache,
            ssl_ctx=self._ssl_ctx,
            manager=self,
            **kwargs
        )

    @property
    def __name__(self):
        return "%s(%s)" % (
            self.__class__.__name__,
            getattr(
                self._handler_cls,
                "__name__",
                str(self._handler_cls),
            ),
        )

    def _read_known_hosts(self):
        if not os.path.isfile(self.config.known_hosts_file):
            return

        try:
            with open(self.config.known_hosts_file, "r") as f:
                self._known_hosts.update(json.load(f))
        except Exception as e:
            self.log.warning("Failed to load saved known hosts: %s", e)

    def _write_known_hosts(self):
        if not self.config.known_hosts_file:
            return

        try:
            dir = os.path.dirname(self.config.known_hosts_file)
            if not os.path.isdir(dir):
                os.makedirs(dir)

            with open(self.config.known_hosts_file, "w") as f:
                json.dump(self._known_hosts, f)
        except Exception as e:
            self.log.warning("Failed to save known hosts: %s", e)

    def get_remote_cert(self, writer):
        sslobj = writer.get_extra_info("ssl_object")  # Python 3.5.1+
        if not sslobj:
            sslobj = writer.get_extra_info("socket")  # Python 3.4.x?
            assert sslobj

        if not hasattr(sslobj, "getpeercert"):
            # Python 3.5.0, no public way to get this, so we have to...
            sslobj = writer.transport._ssl_protocol._sslpipe.ssl_object

        return sslobj.getpeercert(True)

    def validate_remote(self, remote, remote_writer):
        if not self.config.pin_server_cert:
            return

        self.validate_host_cert(
            "%s:%s" % remote,
            self.get_remote_cert(remote_writer),
        )

    def validate_host_cert(self, host, cert):
        assert cert
        cert_hash = sha512(cert).hexdigest()
        if host not in self._known_hosts:
            self.log.info(
                "Adding %s to known hosts (fingerprint: %s)",
                host, cert_hash,
            )
            self._known_hosts[host] = cert_hash
            self._write_known_hosts()
        elif self._known_hosts[host] != cert_hash:
            self.log.critical(
                "Certificate of %s has changed (old = %s, new = %s). "
                "If you haven't changed your certificate recently, "
                "this probably means that someone is MITMing us. "
                "If you believe that %s is safe, "
                "delete entry of %s in %s and restart nyapass.",
                host, self._known_hosts[host], cert_hash,
                host, host, self.config.known_hosts_file,
            )
            sys.exit(1)


def create_ssl_ctx(config):
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
    )
    ctx.options = (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
        ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
    if not config.ssl_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


def main(config, handler_cls=ClientHandler):
    logging.basicConfig(level=config.log_level)
    nyapass_run(
        handler_factory=ClientHandlerManager(
            config,
            handler_cls=handler_cls,
        ),
        config=config,
    )
