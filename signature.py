import hmac
from hashlib import sha512
import base64
import re
import time

SIGNATURE_RE = re.compile(
    b"\r\nX-Nyapass: ([A-Za-z0-9+/=]+)\r\n\r\n$",
    re.S,
)


class SignatureError(ValueError):
    pass


class SignatureNotExist(SignatureError):
    pass


class SignatureInvalid(SignatureError):
    pass


def get_signature_ticker(config, skew=0):
    return ("%s-%s" % (
        config.key_interval,
        (int(time.time()) // config.key_interval) + skew,
    )).encode("utf-8")


def compute_signature(config, data, time_skew=0):
    return hmac.new(
        config.signing_key + get_signature_ticker(config, skew=time_skew),
        data,
        sha512,
    ).digest()


def sign_headers(config, headers):
    assert isinstance(headers, bytes)
    if headers[-4:] != b"\r\n\r\n":
        raise ValueError("Headers are not properly terminated")

    if b"\r\nX-Nyapass:" in headers:
        raise ValueError("Headers already have signature")

    headers = headers[:-4]
    signature = compute_signature(config, headers)
    headers += b"\r\nX-Nyapass: " + base64.b64encode(signature)
    headers += b"\r\n\r\n"
    return headers


def unsign_headers(config, headers):
    assert isinstance(headers, bytes)
    m = SIGNATURE_RE.search(headers)
    if not m:
        raise SignatureNotExist

    signature = base64.b64decode(m.group(1))
    unsigned_headers = headers[:m.start()]
    for skew in (0, -1, 1):
        if compute_signature(config, unsigned_headers, skew) == signature:
            break
    else:
        raise SignatureInvalid

    return unsigned_headers + b"\r\n\r\n"


if __name__ == "__main__":
    from config import Config
    config = Config("server")
    config.key_interval = 1
    test_headers = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
    signed_headers = sign_headers(config, test_headers)
    print(signed_headers.decode("utf-8"))
    assert unsign_headers(config, signed_headers) == test_headers
    try:
        unsign_headers(config, test_headers)
        assert False
    except SignatureNotExist:
        pass

    try:
        unsign_headers(config, b" " + signed_headers)
        assert False
    except SignatureInvalid:
        pass

    time.sleep(1.01)
    unsign_headers(config, signed_headers)
    time.sleep(1.01)
    try:
        unsign_headers(config, b" " + signed_headers)
        assert False
    except SignatureInvalid:
        pass
