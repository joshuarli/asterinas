#!/bin/bash
exec python3 - <<'PY'
import socket, struct

def csum(data):
    if len(data)&1: data+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16: total=(total&65535)+(total>>16)
    return ~total&65535
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));raw.bind(('tap0',0))
while True:
    f=raw.recv(65535)
    if len(f)<59 or f[12:14]!=b'\x08\x00' or f[14]!=0x47 or f[23]!=17: continue
    ip=f[14:42]; udp=f[42:]
    if csum(ip) or ip[16:20]!=socket.inet_aton('192.0.2.1') or ip[20:28]!=b'\x01\x83\x07\x04'+socket.inet_aton('198.51.100.9'): continue
    if udp[:4]!=struct.pack('!HH',42567,42568) or udp[8:17]!=b'lsrr-wire': continue
    break
src,dst=socket.inet_aton('192.0.2.1'),ip[12:16]
quoted=f[14:14+int.from_bytes(ip[2:4],'big')];err=b'\x0b\x00\x00\x00\x00\x00\x00\x00'+quoted
err=err[:2]+struct.pack('!H',csum(err))+err[4:]
hdr=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(err),0x1827,0,64,1,0,src,dst); hdr=hdr[:10]+struct.pack('!H',csum(hdr))+hdr[12:]
raw.send(f[6:12]+f[:6]+b'\x08\x00'+hdr+err);print('SOURCE_ROUTE_ERROR_SENT',flush=True)
PY
