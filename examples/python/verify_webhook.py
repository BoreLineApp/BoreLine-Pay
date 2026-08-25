"""Verify a BoreLine webhook before acting on it.

BoreLine signs every webhook so you can confirm it genuinely came from BoreLine
and not an impostor. The pattern below is standard HMAC-SHA256: compute an HMAC
of the RAW request body with your webhook secret, then compare it in constant
time against the signature in the request headers.

Your Webhook Secret is on the dashboard Settings page (separate from your API
key). BoreLine sends the signature in X-BoreLine-Sig and the send time in
X-BoreLine-Time.

This example uses only the standard library (http.server) so it runs as-is.
In production use your real web framework (Flask, Django, FastAPI, ...).

    BORELINE_WEBHOOK_SECRET=your_webhook_secret python verify_webhook.py
"""

import hmac
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

WEBHOOK_SECRET = os.environ.get("BORELINE_WEBHOOK_SECRET", "").encode()  # "Webhook Secret" from the dashboard
SIGNATURE_HEADER = "X-BoreLine-Sig"   # BoreLine sends the HMAC here
TIMESTAMP_HEADER = "X-BoreLine-Time"  # unix seconds, reject if too old


def is_valid_signature(raw_body: bytes, provided_signature: str) -> bool:
    if not WEBHOOK_SECRET or not provided_signature:
        return False
    expected = hmac.new(WEBHOOK_SECRET, raw_body, hashlib.sha256).hexdigest()
    # compare_digest is constant time, which avoids timing attacks.
    return hmac.compare_digest(expected, provided_signature)


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)  # verify against the raw bytes
        signature = self.headers.get(SIGNATURE_HEADER, "")

        if not is_valid_signature(raw_body, signature):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"invalid signature")
            print("Rejected webhook: bad signature")
            return

        event = json.loads(raw_body.decode("utf-8"))
        # Now it is safe to act on the event, for example fulfil the order.
        print("Verified webhook:", event)
        # fulfil_order(event) ...

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


if __name__ == "__main__":
    print("Listening for BoreLine webhooks on :3000")
    HTTPServer(("", 3000), WebhookHandler).serve_forever()
