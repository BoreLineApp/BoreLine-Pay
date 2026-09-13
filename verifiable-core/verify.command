#!/bin/sh
# Double-click to open the BoreLine verifier menu (macOS: you may need to
# right-click > Open the first time, or run: chmod +x verify.command).
cd "$(dirname "$0")"
python3 verify_invoices.py --menu 2>/dev/null || python verify_invoices.py --menu
