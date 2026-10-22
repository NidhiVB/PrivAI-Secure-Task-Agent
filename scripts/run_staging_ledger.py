"""Lightweight PrivAI-Compatible Staging Ledger Service.

Provides a reproducible, local HTTP/TLS-capable mock transparency ledger implementing
the exact POST /v1/checkpoints REST contract required by ProductionAuditAnchorAdapter.

Usage:
    python scripts/run_staging_ledger.py --port 8443 [--token secret-token]
"""

import argparse
import datetime
import hashlib
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("staging-ledger")

# In-memory append-only log of anchored checkpoints
_ANCHORED_LEDGER: dict[str, dict[str, Any]] = {}
_EXPECTED_AUTH_TOKEN: str = ""


class StagingLedgerHandler(BaseHTTPRequestHandler):
    """HTTP request handler implementing PrivAI's external audit anchor REST contract."""

    def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        """Health check and checkpoint query endpoint."""
        if self.path in ("/health", "/v1/health"):
            self._send_json(200, {
                "status": "healthy",
                "service": "PrivAI-Staging-Ledger-Sidecar",
                "total_anchored": len(_ANCHORED_LEDGER),
            })
            return

        if self.path.startswith("/v1/checkpoints/"):
            chk_id = self.path.split("/")[-1]
            if chk_id in _ANCHORED_LEDGER:
                self._send_json(200, _ANCHORED_LEDGER[chk_id])
                return
            self._send_json(404, {"error": "Checkpoint not found in ledger"})
            return

        self._send_json(404, {"error": "Not Found"})

    def do_POST(self) -> None:
        """Anchor checkpoint endpoint (POST /v1/checkpoints)."""
        if self.path != "/v1/checkpoints":
            self._send_json(404, {"error": f"Endpoint '{self.path}' not found."})
            return

        # 1. Bearer Token Authentication (if configured)
        if _EXPECTED_AUTH_TOKEN:
            auth_header = self.headers.get("Authorization", "")
            expected_header = f"Bearer {_EXPECTED_AUTH_TOKEN}"
            if auth_header != expected_header:
                logger.warning("Unauthorized POST /v1/checkpoints: token mismatch.")
                self._send_json(401, {"error": "Unauthorized: Invalid or missing Bearer token."})
                return

        # 2. Parse JSON Payload
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length)
            body = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            logger.error(f"Failed to parse JSON body: {exc}")
            self._send_json(400, {"error": "Malformed JSON body."})
            return

        # 3. Validate Required Payload Fields
        required_fields = {
            "checkpoint_id",
            "epoch_index",
            "start_sequence",
            "end_sequence",
            "event_count",
            "merkle_root",
            "prev_checkpoint_hash",
            "checkpoint_hash",
        }
        missing = [f for f in required_fields if f not in body]
        if missing:
            self._send_json(422, {"error": f"Missing required checkpoint fields: {missing}"})
            return

        chk_id = body["checkpoint_id"]
        merkle_root = body["merkle_root"]

        # 4. Check for existing idempotent record
        if chk_id in _ANCHORED_LEDGER:
            existing = _ANCHORED_LEDGER[chk_id]
            logger.info(f"Idempotent re-anchor request for existing checkpoint: {chk_id}")
            self._send_json(200, existing)
            return

        # 5. Generate Immutable Confirmation Receipt
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        anchor_id = f"stg-ledger-{body['epoch_index']:04d}-{chk_id[:8]}"
        signature_material = f"{anchor_id}:{merkle_root}:{now_str}".encode("utf-8")
        external_signature = hashlib.sha256(signature_material).hexdigest()

        receipt = {
            "anchor_id": anchor_id,
            "root_hash": merkle_root,
            "anchored_at": now_str,
            "external_signature": f"sig:sha256:{external_signature}",
            "checkpoint_id": chk_id,
            "epoch_index": body["epoch_index"],
        }

        # Append to immutable in-memory ledger
        _ANCHORED_LEDGER[chk_id] = receipt
        logger.info(f"Anchored checkpoint {chk_id} (epoch {body['epoch_index']}) -> {anchor_id}")

        self._send_json(201, receipt)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP server stderr output in favor of logger."""
        logger.info(f"{self.address_string()} - {format % args}")


def run_server(host: str = "127.0.0.1", port: int = 8443, token: str = "") -> None:
    """Start the staging ledger HTTP server."""
    global _EXPECTED_AUTH_TOKEN
    _EXPECTED_AUTH_TOKEN = token.strip()

    server = HTTPServer((host, port), StagingLedgerHandler)
    logger.info(f"PrivAI Staging Ledger listening on http://{host}:{port}")
    if _EXPECTED_AUTH_TOKEN:
        logger.info("Bearer token authentication: ENABLED")
    else:
        logger.info("Bearer token authentication: DISABLED (open staging mode)")
    logger.info("Endpoints available: GET /health, POST /v1/checkpoints, GET /v1/checkpoints/{id}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down staging ledger server...")
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PrivAI Staging Ledger Mock Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="Bind port (default: 8443)")
    parser.add_argument("--token", default="", help="Optional Bearer token requirement")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, token=args.token)
