#!/bin/sh
echo "=== /proxy/main.py lines 15-22 ===" >&2
sed -n '15,22p' /proxy/main.py >&2
echo "==============================" >&2
cd /
exec python3 -u -m proxy.main
