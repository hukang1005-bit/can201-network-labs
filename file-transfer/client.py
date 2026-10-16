import argparse
import gzip
import hashlib
import json
import os
import shutil
import struct
import tempfile
import threading
import time
from socket import AF_INET, SOCK_STREAM, socket

from tqdm import tqdm

# Constants
DEFAULT_WORKERS = max(2, os.cpu_count() or 4)

OP_LOGIN, OP_SAVE, OP_UPLOAD, OP_GET = "LOGIN", "SAVE", "UPLOAD", "GET"
DIR_REQUEST, TYPE_AUTH, TYPE_FILE = "REQUEST", "AUTH", "FILE"

FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE = "operation", "direction", "type"
FIELD_TOKEN, FIELD_USERNAME, FIELD_PASSWORD = "token", "username", "password"
FIELD_STATUS, FIELD_KEY, FIELD_SIZE, FIELD_BLOCK_SIZE, FIELD_TOTAL_BLOCK = (
    "status",
    "key",
    "size",
    "block_size",
    "total_block",
)
FIELD_BLOCK_INDEX, FIELD_MD5 = "block_index", "md5"


# IO helpers
def connect(ip, port=1379):
    """Build TCP connection to server port 1379."""
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(30)
    try:
        s.connect((ip, port))
    except OSError:
        s.close()
        raise
    return s


def _make_packet(j, b=None):
    """Pack JSON header + json part + optional binary part"""
    js = json.dumps(j, ensure_ascii=False).encode()
    len_jb = len(js)
    if b is None:
        len_b = 0
    else:
        len_b = len(b)
    packed_header = struct.pack("!II", len_jb, len_b)
    if b is None or not b:
        b_data = b""
    else:
        b_data = b
    result = packed_header + js + b_data
    return result


def _recv(conn):
    """Receive one packet and return (JSON, bytes)."""
    hdr = b""
    while len(hdr) < 8:
        x = conn.recv(8 - len(hdr))
        if not x:
            return None, None
        hdr += x
    jlen, blen = struct.unpack("!II", hdr)
    jb = b""
    while len(jb) < jlen:
        x = conn.recv(jlen - len(jb))
        if not x:
            return None, None
        jb += x
    try:
        j = json.loads(jb.decode())
    except (OSError, ValueError):
        return None, None
    b_data = b""
    while len(b_data) < blen:
        x = conn.recv(blen - len(b_data))
        if not x:
            return None, None
        b_data += x
    return j, b_data


def send_recv(conn, j, b=None, retry=1):
    """Send one packet and wait response, with one retry"""
    for k in range(retry + 1):
        try:
            conn.sendall(_make_packet(j, b))
            return _recv(conn)
        except (OSError, ValueError):
            if k == retry:
                raise
    return None, None


# Utilities
def md5sum(path):
    """Compute the MD5 of a local file (streamed)."""
    md5_hash = hashlib.md5()
    with open(path, "rb") as file:
        while True:
            chunk = file.read(1 << 20)  # read 1MB at a time.
            if chunk == b"":
                break
            md5_hash.update(chunk)
    return md5_hash.hexdigest()


def read_range(path, off, n):
    """Read [off, off+n) bytes from file."""
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(n)


def compress_file(p):
    """Gzip a file with compresslevel=6, return compressed path."""
    fd, q = tempfile.mkstemp(suffix=".gz", prefix="step-")
    os.close(fd)
    with open(p, "rb") as fi, gzip.open(q, "wb", compresslevel=6) as fo:
        shutil.copyfileobj(fi, fo)
    return q


# Protocol helpers
def login(conn, username):
    req = {
        FIELD_OPERATION: OP_LOGIN,
        FIELD_DIRECTION: DIR_REQUEST,
        FIELD_TYPE: TYPE_AUTH,
        FIELD_USERNAME: username,
        FIELD_PASSWORD: hashlib.md5(username.encode()).hexdigest(),
    }
    resp, _ = send_recv(conn, req)
    if resp and resp.get(FIELD_STATUS) == 200:
        return resp.get(FIELD_TOKEN)
    else:
        return None


# Uploader
def upload_file(server_ip, token, file_path, workers=DEFAULT_WORKERS, port=1379):
    size = os.path.getsize(file_path)
    fname = os.path.basename(file_path)

    # 1) SAVE: ask server for upload plan
    with connect(server_ip, port) as c:
        plan_req = {
            FIELD_OPERATION: OP_SAVE,
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_TYPE: TYPE_FILE,
            FIELD_TOKEN: token,
            FIELD_SIZE: size,
            FIELD_KEY: fname,
        }
        plan, _ = send_recv(c, plan_req)
    if not plan or plan.get(FIELD_STATUS) != 200:
        raise RuntimeError(f"Upload plan failed: {plan}")

    key = plan[FIELD_KEY]
    block_size = plan[FIELD_BLOCK_SIZE]
    total = plan[FIELD_TOTAL_BLOCK]
    print(
        f" Plan: key={key} size={size / 1024 / 1024:.2f}MB total={total} block={block_size}B"
    )

    stop_evt = threading.Event()
    err_lock = threading.Lock()
    errs = []

    # striped worker
    def worker(tid, n_worker, progress):
        try:
            if total <= 1:
                return
            with connect(server_ip, port) as s:
                last = total - 1
                i = tid
                while i < last and not stop_evt.is_set():
                    off = i * block_size
                    data = read_range(file_path, off, block_size)
                    if len(data) != block_size:
                        data = data.ljust(block_size, b"\0")
                    req = {
                        FIELD_OPERATION: OP_UPLOAD,
                        FIELD_DIRECTION: DIR_REQUEST,
                        FIELD_TYPE: TYPE_FILE,
                        FIELD_TOKEN: token,
                        FIELD_KEY: key,
                        FIELD_BLOCK_INDEX: i,
                    }
                    resp, _ = send_recv(s, req, data, retry=1)
                    if not resp:
                        raise RuntimeError(f"Empty response for block {i}")
                    st = resp.get(FIELD_STATUS)
                    if st == 408:
                        stop_evt.set()
                        break
                    if st != 200:
                        raise RuntimeError(f"Upload failed for block {i}: {resp}")
                    progress.update(1)
                    i += n_worker
        except Exception as e:
            with err_lock:
                errs.append(e)
            stop_evt.set()

    # 2) Upload(striped)
    if total > 1:
        n = min(workers, max(1, total - 1))
    else:
        n = 0
    with tqdm(total=total, unit="block", desc=" Uploading", ncols=80) as progress:
        ts = []

        for tid in range(n):
            thread = threading.Thread(
                target=worker, args=(tid, n, progress), daemon=True
            )
            ts.append(thread)

        for t in ts:
            t.start()
        for t in ts:
            t.join()
        if stop_evt.is_set() and not errs:
            raise RuntimeError("Server stopped the upload")
        if errs:
            raise RuntimeError(f"Upload aborted: {errs[0]}")

        # 3) Finalize last block and get MD5 from server.
        server_md5 = None
        if total > 0 and not stop_evt.is_set():
            last = total - 1
            start = last * block_size
            last_len = size - start
            last_data = read_range(file_path, start, last_len)
            with connect(server_ip, port) as s:
                req = {
                    FIELD_OPERATION: OP_UPLOAD,
                    FIELD_DIRECTION: DIR_REQUEST,
                    FIELD_TYPE: TYPE_FILE,
                    FIELD_TOKEN: token,
                    FIELD_KEY: key,
                    FIELD_BLOCK_INDEX: last,
                }
                resp, _ = send_recv(s, req, last_data, retry=1)
                if not resp or resp.get(FIELD_STATUS) not in (200, 408):
                    raise RuntimeError(f"Last block failed: {resp}")
                server_md5 = resp.get(FIELD_MD5)
            progress.update(1)

    print(f" Uploaded: {fname}")

    # Local MD5
    local_md5 = md5sum(file_path)
    if server_md5:
        if local_md5.lower() == (server_md5 or "").lower():
            print(" MD5 OK: " + local_md5)
        else:
            raise RuntimeError(f"MD5 mismatch: local={local_md5} server={server_md5}")
    else:
        print(f" Server didn't return MD5 in UPLOAD. Local MD5: {local_md5}")


# CLI
def main():
    p = argparse.ArgumentParser(description="STEP Client")
    p.add_argument(
        "--server_ip",
        required=True,
        help="IP address of the STEP server (e.g., 192.168.1.100)",
    )
    p.add_argument(
        "--id", required=True, help="Unique ID for the client (e.g., client_001)"
    )
    p.add_argument(
        "--f", required=True, help="File path to upload (e.g., ./data/test.txt)"
    )
    p.add_argument(
        "--compress",
        action="store_true",
        help="Enable gzip compression for uploaded file",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Number of worker threads (default: {DEFAULT_WORKERS})",
    )
    p.add_argument("--port", type=int, default=1379)
    a = p.parse_args()
    if not 1 <= a.port <= 65535:
        p.error("--port must be between 1 and 65535")
    if a.workers < 1:
        p.error("--workers must be positive")
    if not os.path.isfile(a.f) or os.path.getsize(a.f) == 0:
        p.error("--f must name a non-empty file")
    total_t0 = time.time()

    # Login
    with connect(a.server_ip, a.port) as c:
        token = login(c, a.id)
        if not token:
            raise RuntimeError("Login failed")
        print(" Login successful!")

    # Optional compression
    upload_path = a.f
    if a.compress:
        print(" Compressing file ...")
        t0 = time.time()
        upload_path = compress_file(a.f)
        before = os.path.getsize(a.f)
        after = os.path.getsize(upload_path)
        print(
            f" Compressed: {after / 1024 / 1024:.2f} MB ({after / before * 100 if before > 0 else 0:.1f}% of original)"
        )
        print(f" Compression time: {time.time() - t0:.3f}s")

    # Upload
    try:
        upload_file(a.server_ip, token, upload_path, workers=a.workers, port=a.port)
    finally:
        if a.compress:
            os.remove(upload_path)

    print(f" Total elapsed time: {time.time() - total_t0:.3f}s")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from error
