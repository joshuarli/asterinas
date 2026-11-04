#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
exec python3 - <<'PY'
import socket
listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(('192.0.2.1', 39144))
while True:
    listener.recvfrom(65535)
PY
