#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
exec python3 - <<'PY'
import socket, struct

def checksum(data):
    if len(data) & 1: data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16: total = (total & 65535) + (total >> 16)
    return (~total) & 65535
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind(('tap0', 0))
while True:
    frame = raw.recv(65535)
    if len(frame) != 50 or frame[12:14] != b'\x08\x00' or frame[23] != 1 or frame[34] != 8: continue
    ip = frame[14:34]; icmp = frame[34:]
    if ip[8] != 37 or ip[1] != 16 or checksum(ip) or checksum(icmp) or icmp[4:8] != struct.pack('!HH', 4983, 9) or icmp[8:] != b'wire-raw': continue
    icmp = b'\x00\x00\x00\x00' + icmp[4:]
    icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
    outer = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 36, 1, 0, 64, 1, 0, ip[16:20], ip[12:16])
    outer = outer[:10] + struct.pack('!H', checksum(outer)) + outer[12:]
    raw.send(frame[6:12] + frame[:6] + b'\x08\x00' + outer + icmp)
    print('RAW_PEER_SENT', flush=True)
    break
PY
