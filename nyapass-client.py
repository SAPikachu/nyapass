#!/usr/bin/env python3

import sys
import logging

from common import nyapass_run_instances, Nyapass
from local import ClientHandlerManager
from local_socks5 import SocksClientHandler
from config import Config


def main():
    config = Config("client")
    logging.basicConfig(level=config.log_level)
    instances = []
    if config.port:
        instances.append(Nyapass(
            handler_factory=ClientHandlerManager(config),
            config=config,
        ))

    if config.socks5_port:
        instances.append(Nyapass(
            handler_factory=ClientHandlerManager(
                config,
                handler_cls=SocksClientHandler,
            ),
            config=config,
            port=config.socks5_port,
        ))

    if config.shadowsocks_port:
        try:
            from local_shadowsocks import ShadowsocksClientHandler
        except ImportError:
            logging.warning(
                "Shadowsocks is not installed, "
                "can't enable shadowsocks handler"
            )
        else:
            instances.append(Nyapass(
                handler_factory=ClientHandlerManager(
                    config,
                    handler_cls=ShadowsocksClientHandler,
                ),
                config=config,
                port=config.shadowsocks_port,
            ))

    if not instances:
        logging.error("All handlers are disabled")
        sys.exit(1)

    nyapass_run_instances(config, *instances)


if __name__ == "__main__":
    main()
