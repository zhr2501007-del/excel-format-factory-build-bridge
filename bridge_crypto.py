#!/usr/bin/env python3
import base64, os, sys, tarfile, tempfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
MAGIC = b"EFB1"
key = base64.urlsafe_b64decode(os.environ["BUILD_BUNDLE_KEY"].encode("ascii"))
def decrypt(src, dst):
    data = Path(src).read_bytes()
    if not data.startswith(MAGIC): raise SystemExit("invalid sealed payload")
    nonce = data[4:16]
    Path(dst).write_bytes(AESGCM(key).decrypt(nonce, data[16:], None))
def seal_files(dst, files):
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "bundle.tar.gz"
        with tarfile.open(bundle, "w:gz", compresslevel=9) as archive:
            for item in files:
                path = Path(item)
                archive.add(path, arcname=path.name, recursive=True)
        nonce = os.urandom(12)
        data = bundle.read_bytes()
        Path(dst).parent.mkdir(parents=True, exist_ok=True)
        Path(dst).write_bytes(MAGIC + nonce + AESGCM(key).encrypt(nonce, data, None))
if sys.argv[1] == "decrypt": decrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == "seal-files": seal_files(sys.argv[2], sys.argv[3:])
else: raise SystemExit("unknown command")
