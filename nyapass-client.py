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

    if not instances:
        logging.error("All modules are disabled")
        sys.exit(1)

    nyapass_run_instances(*instances)


if __name__ == "__main__":
    main()
