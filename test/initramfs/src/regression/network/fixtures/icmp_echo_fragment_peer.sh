#!/bin/bash
exec python3 - <<'PY'
import socket, struct

def checksum(data):
    if len(data) & 1: data += b'\0'
    n = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while n >> 16: n = (n & 65535) + (n >> 16)
    return ~n & 65535

def ip(src,dst,ident,flags,payload,proto=1):
    h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),ident,flags,64,proto,0,src,dst)
    return h[:10]+struct.pack('!H',checksum(h))+h[12:]+payload
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); raw.bind(('tap0',0))
while True:
    f=raw.recv(65535)
    if len(f) >= 47 and f[12:14]==b'\x08\x00' and f[23]==17 and f[34:38]==struct.pack('!HH',42567,42568) and f[42:47]==b'start': break
src,dst=f[30:34],f[26:30]; eth=f[6:12]+f[:6]+b'\x08\x00'
body=bytes((i%251 for i in range(2000))); icmp=struct.pack('!BBHHH',8,0,0,0x3982,7)+body
icmp=icmp[:2]+struct.pack('!H',checksum(icmp))+icmp[4:]
raw.send(eth+ip(src,dst,0x7821,0x2000,icmp[:1480]))
raw.send(eth+ip(src,dst,0x7821,185,icmp[1480:]))
fragments={}; ident=None; end=None
while True:
    f=raw.recv(65535)
    if len(f)<34 or f[12:14]!=b'\x08\x00' or f[23]!=1 or f[26:34]!=dst+src: continue
    hlen=(f[14]&15)*4; total=int.from_bytes(f[16:18],'big'); h=f[14:14+hlen]
    if checksum(h) or total>1500: continue
    flag=int.from_bytes(f[20:22],'big'); offset=(flag&8191)*8; payload=f[14+hlen:14+total]
    if offset==0 and (len(payload)<8 or payload[:2]!=b'\x00\x00' or payload[4:8]!=struct.pack('!HH',0x3982,7)): continue
    if ident is None: ident=f[18:20]
    if f[18:20]!=ident: continue
    fragments[offset]=payload
    if not flag&0x2000: end=offset+len(payload)
    if end is None or 0 not in fragments: continue
    assembled=bytearray(end); filled=bytearray(end)
    for pos,part in fragments.items(): assembled[pos:pos+len(part)]=part; filled[pos:pos+len(part)]=b'\x01'*len(part)
    if all(filled) and len(fragments)>1 and len(assembled)==2008 and checksum(assembled)==0 and assembled[8:]==body: break
msg=b'fragmented-ok'; udp=struct.pack('!HHHH',42568,42567,8+len(msg),0)+msg
raw.send(eth+ip(src,dst,0x7822,0,udp,17)); print('ECHO_FRAGMENT_OK',flush=True)
PY
