from __future__ import annotations
import os
import json
import threading
import base64
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from phishing_detector.predictor import PhishingDetector


import os

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 10000))

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"
STYLE_FILE = STATIC_DIR / "styles.css"
SCRIPT_FILE = STATIC_DIR / "script.js"

detector = PhishingDetector()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def safe_result(payload: dict[str, str]) -> dict[str, str | list[str]]:
    url = payload.get("url", "").strip()
    image_data = payload.get("image_data", "").strip()
    temp_path: Path | None = None
    image_path: Path | None = None
    if image_data:
        try:
            header, encoded = image_data.split(",", 1)
            suffix = ".png"
            if "jpeg" in header or "jpg" in header:
                suffix = ".jpg"
            elif "webp" in header:
                suffix = ".webp"
            raw_bytes = base64.b64decode(encoded)
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
                handle.write(raw_bytes)
                temp_path = Path(handle.name)
            image_path = temp_path
        except Exception:
            image_path = None

    try:
        result = detector.predict(url, image_path=image_path)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)

    return {
        "verdict": "SAFE" if result.label == "Legitimate" else "UNSAFE",
        "score": f"{result.score:.3f}",
        "confidence": f"{result.score:.0%}",
        "reasons": result.reasons,
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            self._send(read_text(INDEX_FILE).encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/styles.css":
            self._send(read_text(STYLE_FILE).encode("utf-8"), "text/css; charset=utf-8")
            return
        if path == "/script.js":
            self._send(read_text(SCRIPT_FILE).encode("utf-8"), "application/javascript; charset=utf-8")
            return
        self._send(b"Not Found", "text/plain; charset=utf-8", status=404)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/check":
            self._send(b"Not Found", "text/plain; charset=utf-8", status=404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        try:
            payload = json.loads(raw or "{}")
        except json.JSONDecodeError:
            self._send(
                json.dumps({"error": "Invalid JSON"}).encode("utf-8"),
                "application/json; charset=utf-8",
                status=400,
            )
            return

        url = str(payload.get("url", "")).strip()
        if not url:
            self._send(
                json.dumps({"error": "Please enter a URL"}).encode("utf-8"),
                "application/json; charset=utf-8",
                status=400,
            )
            return

        body = safe_result({"url": url})
        self._send(json.dumps(body).encode("utf-8"), "application/json; charset=utf-8")

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def main() -> int:
    server = ThreadingHTTPServer((HOST, PORT), Handler)

    print(f"Server running on {HOST}:{PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()

    return 0
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
