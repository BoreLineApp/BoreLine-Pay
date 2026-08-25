"""Create a BoreLine invoice from your backend and get a payment link.

Run this on your SERVER only. The API key must never reach the browser.

    BORELINE_API_KEY=your_secret_api_key python create_invoice.py

Requires: requests  ->  pip install requests
"""

import os
import sys
import requests

API_KEY = os.environ.get("BORELINE_API_KEY")
if not API_KEY:
    sys.exit("Set BORELINE_API_KEY in your environment first.")

API_URL = "https://api.borelinepay.uk/api/invoice"


def create_invoice(tier, email=None, months=1, metadata=None):
    payload = {"tier": tier, "months": months}
    if email:
        payload["email"] = email
    if metadata:
        payload["metadata"] = metadata

    resp = requests.post(
        API_URL,
        headers={
            "X-API-Key": API_KEY,          # secret: server-side only
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    invoice = create_invoice(
        tier="starter",                    # a product key from your dashboard
        email="customer@example.com",      # optional label
        months=1,                          # optional, defaults to 1
        metadata={"order_id": "A-1042"},   # optional, your own reference
    )
    print("Redirect the customer to:", invoice["invoice_url"])
    print("Amount (sats):", invoice["amount_sats"])
    print("Expires:", invoice["expires_at"])
