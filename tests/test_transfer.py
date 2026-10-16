import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "file-transfer" / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = load("server")
client = load("client")


class PacketTests(unittest.TestCase):
    def test_utf8_header_uses_byte_length(self):
        data = {"message": "你好, network"}
        packet = server.make_packet(data, b"\0\xff")
        size, binary = struct.unpack("!II", packet[:8])
        self.assertEqual(json.loads(packet[8 : 8 + size]), data)
        self.assertEqual(packet[8 + size :], b"\0\xff")
        self.assertEqual(binary, 2)

    def test_fragmented_packet(self):
        a, b = socket.socketpair()
        try:
            packet = client._make_packet({"message": "分片"}, b"abc")
            for byte in packet:
                a.sendall(bytes([byte]))
            self.assertEqual(server.get_tcp_packet(b), ({"message": "分片"}, b"abc"))
        finally:
            a.close()
            b.close()


class TransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.process = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "file-transfer/server.py"),
                "--ip",
                "127.0.0.1",
                "--port",
                str(cls.port),
            ],
            cwd=cls.temp.name,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            try:
                with client.connect("127.0.0.1", cls.port):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("Test server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.temp.cleanup()

    def login(self):
        with client.connect("127.0.0.1", self.port) as conn:
            token = client.login(conn, "local-test")
        self.assertTrue(token)
        return token

    def test_parallel_upload_and_checksum(self):
        token = self.login()
        path = Path(self.temp.name) / "中文-sample.bin"
        payload = bytes(range(256)) * 1000 + b"end"
        path.write_bytes(payload)
        client.upload_file("127.0.0.1", token, str(path), workers=4, port=self.port)
        self.assertEqual(
            (Path(self.temp.name) / "file/local-test" / path.name).read_bytes(), payload
        )

    def test_path_traversal_is_rejected(self):
        token = self.login()
        for key in ["../outside", "/absolute", "..", "nested/file", "nested\\file"]:
            with client.connect("127.0.0.1", self.port) as conn:
                response, _ = client.send_recv(
                    conn,
                    {
                        "operation": "SAVE",
                        "direction": "REQUEST",
                        "type": "FILE",
                        "token": token,
                        "key": key,
                        "size": 10,
                    },
                )
                self.assertEqual(response["status"], 400)

    def test_last_block_does_not_finalize_incomplete_upload(self):
        token = self.login()
        with client.connect("127.0.0.1", self.port) as conn:
            request = {
                "operation": "SAVE",
                "direction": "REQUEST",
                "type": "FILE",
                "token": token,
                "key": "incomplete.bin",
                "size": 20481,
            }
            plan, _ = client.send_recv(conn, request)
            self.assertEqual(plan["status"], 200)
            request.update(operation="UPLOAD", block_index=1)
            response, _ = client.send_recv(conn, request, b"x")
            self.assertEqual(response["status"], 200)
            self.assertNotIn("md5", response)
            self.assertFalse(
                (Path(self.temp.name) / "file/local-test/incomplete.bin").exists()
            )

    def test_bad_token_is_rejected(self):
        with client.connect("127.0.0.1", self.port) as conn:
            response, _ = client.send_recv(
                conn,
                {
                    "operation": "GET",
                    "direction": "REQUEST",
                    "type": "FILE",
                    "token": "bad!",
                    "key": "x",
                },
            )
            self.assertEqual(response["status"], 403)


if __name__ == "__main__":
    unittest.main()
