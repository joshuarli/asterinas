#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
exec python3 - <<'PY'
import socket, struct

def checksum(data):
    if len(data) & 1: data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16: value = (value & 65535) + (value >> 16)
    return (~value) & 65535
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind(('tap0', 0))
while True:
    frame = raw.recv(65535)
    if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6 or frame[36:38] != struct.pack('!H', 39145): continue
    ip = frame[14:]; ihl = (ip[0] & 15) * 4
    if len(ip) < ihl + 20 or not (ip[ihl+13] & 2) or checksum(ip[:ihl]): continue
    quote = ip[:ihl+20]
    icmp = struct.pack('!BBHI', 11, 0, 0, 0) + quote
    icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
    outer = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(icmp), 1, 0, 64, 1, 0, ip[16:20], ip[12:16])
    outer = outer[:10] + struct.pack('!H', checksum(outer)) + outer[12:]
    raw.send(frame[6:12] + frame[:6] + b'\x08\x00' + outer + icmp)
    print('RAW_TCP_QUOTE_SENT', flush=True)
    break
PY
