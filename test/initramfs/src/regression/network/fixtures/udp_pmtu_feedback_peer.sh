#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
exec python3 - <<'PY'
import socket, struct

def checksum(data):
    if len(data) % 2: data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while s >> 16: s = (s & 65535) + (s >> 16)
    return (~s) & 65535
listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(('192.0.2.1', 39139))
listener2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener2.bind(('192.0.2.1', 39140))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(('tap0', 0))
while True:
    frame = s.recv(65535)
    if len(frame) < 42 or frame[12:14] != b'\x08\x00': continue
    ip = frame[14:]; ihl = (ip[0] & 15) * 4
    if ip[9] != 17 or ip[16:20] != socket.inet_aton('192.0.2.1') or len(ip) < ihl+8: continue
    if struct.unpack('!H', ip[ihl+2:ihl+4])[0] != 39139: continue
    total = struct.unpack('!H', ip[2:4])[0]
    if total != 928: continue
    icmp = struct.pack('!BBHHH', 3, 4, 0, 0, 600) + ip[:total]
    icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
    outer = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(icmp), 1, 0, 64, 1, 0, ip[16:20], ip[12:16])
    outer = outer[:10] + struct.pack('!H', checksum(outer)) + outer[12:]
    damaged = icmp[:2] + bytes([icmp[2] ^ 1]) + icmp[3:]
    s.send(frame[6:12] + frame[:6] + b'\x08\x00' + outer + damaged)
    while True:
        frame = s.recv(65535)
        if len(frame) >= 42 and frame[12:14] == b'\x08\x00' and frame[23] == 17 and frame[36:38] == struct.pack('!H', 39139) and struct.unpack('!H', frame[16:18])[0] == 928:
            break
    s.send(frame[6:12] + frame[:6] + b'\x08\x00' + outer + icmp)
    observed = 0
    while observed < 3:
        frame = s.recv(65535)
        if len(frame) >= 42 and frame[12:14] == b'\x08\x00' and frame[23] == 17 and frame[36:38] == struct.pack('!H', 39139):
            print('DATA', len(frame)-14, hex(struct.unpack('!H', frame[20:22])[0]), flush=True)
            observed += 1
    while True:
        frame = s.recv(65535)
        if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17 or frame[36:38] != struct.pack('!H', 39140): continue
        ip = frame[14:]
        total = struct.unpack('!H', ip[2:4])[0]
        icmp = struct.pack('!BBHHH', 3, 4, 0, 0, 552) + ip[:total]
        icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
        outer = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(icmp), 1, 0, 64, 1, 0, ip[16:20], ip[12:16])
        outer = outer[:10] + struct.pack('!H', checksum(outer)) + outer[12:]
        s.send(frame[6:12] + frame[:6] + b'\x08\x00' + outer + icmp)
        break
    break
PY
