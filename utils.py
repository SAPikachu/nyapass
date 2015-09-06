import asyncio


@asyncio.coroutine
def pipe_data(reader, writer):
    try:
        while not reader.at_eof():
            data = yield from reader.read(65536)
            writer.write(data)
            yield from writer.drain()
    except ConnectionError:
        pass
    finally:
        try:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except AttributeError:
                # On self._sock.shutdown(socket.SHUT_WR)
                pass

            yield from writer.drain()
        except ConnectionError:
            pass

