#!/bin/bash
exec python3 - <<'PY'
import socket, struct

def checksum(data):
    if len(data)&1:data+=b'\0'
    n=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while n>>16:n=(n&65535)+(n>>16)
    return ~n&65535
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));raw.bind(('tap0',0))
while True:
    f=raw.recv(65535)
    if len(f)>=47 and f[12:14]==b'\x08\x00' and f[23]==17 and f[34:38]==struct.pack('!HH',42567,42568) and f[42:47]==b'start':break
src,dst=f[30:34],f[26:30];eth=f[6:12]+f[:6]+b'\x08\x00'
def send(payload,opts=b''):
    udp=struct.pack('!HHHH',42568,42567,8+len(payload),0)+payload
    h=struct.pack('!BBHHHBBH4s4s',0x45+len(opts)//4,0,20+len(opts)+len(udp),0x8241,0,64,17,0,src,dst)+opts
    h=h[:10]+struct.pack('!H',checksum(h))+h[12:]
    raw.send(eth+h+udp)
send(b'unsafe',b'\x01\x83\x07\x04'+socket.inet_aton('198.51.100.9'))
send(b'done');print('INGRESS_SENT',flush=True)
PY
