#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
exec python3 - <<'PY'
import socket, struct

def checksum(data):
    if len(data) % 2: data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while value >> 16: value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def send_error(frame, quote, mtu):
    ip = frame[14:]
    icmp = struct.pack('!BBHHH', 3, 4, 0, 0, mtu) + quote
    icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
    outer = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(icmp), 1, 0, 64, 1, 0, ip[16:20], ip[12:16])
    outer = outer[:10] + struct.pack('!H', checksum(outer)) + outer[12:]
    raw.send(frame[6:12] + frame[:6] + b'\x08\x00' + outer + icmp)

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(('192.0.2.1', 39141))
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind(('tap0', 0))
seen = 0
while seen < 3:
    frame = raw.recv(65535)
    if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17 or frame[36:38] != struct.pack('!H', 39141): continue
    ip = frame[14:]; total = struct.unpack('!H', ip[2:4])[0]
    if total != 928: continue
    seen += 1
    if seen == 1:
        for offset in (20, 22):
            quote = bytearray(ip[:total]); quote[offset] ^= 0x40
            send_error(frame, quote, 600)
        quote = bytearray(ip[:total]); quote[12:16] = socket.inet_aton('192.0.2.101'); quote[10:12] = b'\0\0'
        quote[10:12] = struct.pack('!H', checksum(quote[:20])); send_error(frame, quote, 600)
    else:
        send_error(frame, ip[:total], 600 if seen == 2 else 1200)
PY
