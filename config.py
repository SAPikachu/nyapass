import json
from hashlib import pbkdf2_hmac, sha512
import hmac
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")
DEFAULT_CONFIG_FILE = os.path.join(
    os.path.dirname(__file__),
    "config.json.example",
)


class Config:
    def __init__(self, mode, file=CONFIG_FILE, load_defaults=True):
        if mode not in ("client", "server"):
            raise ValueError("mode must be either config or server")

        if load_defaults:
            if not os.path.isfile(DEFAULT_CONFIG_FILE):
                print("Warning: Couldn't find default configuration file")
            else:
                self._load(mode, DEFAULT_CONFIG_FILE)

        self._load(mode, file)

    def _load(self, mode, file):
        with open(file, "r") as f:
            config_data = json.load(f)

        self._raw = config_data
        converted_data = dict(config_data)
        converted_data.update(config_data[mode])
        del converted_data["client"]
        del converted_data["server"]
        for k, v in converted_data.items():
            setattr(self, k, v)

        self.generate_keys()

    def generate_keys(self):
        self.master_key = pbkdf2_hmac(
            "sha512",
            self.password.encode("utf-8"),
            self.salt.encode("utf-8"),
            self.pbkdf2_rounds,
        )
        self.signing_key = hmac.new(
            self.master_key, b"nyapass-signing-key", sha512,
        ).digest()
