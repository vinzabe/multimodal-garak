"""Tiny HTTP server that serves probe assets (images/audio) so a remote
multimodal model can fetch them via URL. Returns the public URL for an asset."""
from __future__ import annotations

import http.server
import os
import socketserver
import threading
import time
import uuid
from pathlib import Path


class AssetServer:
    def __init__(self, root: str | None = None, port: int = 0,
                 host: str = "127.0.0.1") -> None:
        self.root = root or os.path.join(os.path.dirname(__file__),
                                         "..", "assets", "_serve")
        os.makedirs(self.root, exist_ok=True)
        self.host = host
        self._explicit_port = port
        self.port = port
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def start(self) -> None:
        root = self.root

        class _H(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=root, **kw)
            def log_message(self, *a, **kw):
                pass  # silence

        self._server = socketserver.TCPServer((self.host, self._explicit_port), _H)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        time.sleep(0.1)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def publish(self, data: bytes, ext: str = "png") -> str:
        name = f"{uuid.uuid4().hex[:12]}.{ext}"
        Path(os.path.join(self.root, name)).write_bytes(data)
        return f"http://{self.host}:{self.port}/{name}"

    def url_for(self, filename: str) -> str:
        return f"http://{self.host}:{self.port}/{filename}"
