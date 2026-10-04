"""Step 1: give every agent (and the auth server) its own Ed25519 key pair."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from a2a_auth.config import ALL_SERVICES, Settings  # noqa: E402
from a2a_auth.keys import bootstrap_keys  # noqa: E402

if __name__ == "__main__":
    settings = Settings.from_env()
    bootstrap_keys(settings.keys_dir, ALL_SERVICES, overwrite="--rotate" in sys.argv)
    for name in ALL_SERVICES:
        print(f"  {name:15} private: keys/{name}.key.pem   public: keys/{name}.jwk.json")
