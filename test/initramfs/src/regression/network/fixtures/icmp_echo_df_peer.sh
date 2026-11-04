#!/bin/bash
exec python3 - <<'PY'
import socket, struct

def csum(data):
    if len(data)&1: data+=b'\0'
    n=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while n>>16: n=(n&65535)+(n>>16)
    return ~n&65535

def ip(src,dst,proto,payload):
    h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),0x4832,0,64,proto,0,src,dst)
    return h[:10]+struct.pack('!H',csum(h))+h[12:]+payload
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); raw.bind(('tap0',0))
while True:
    f=raw.recv(65535)
    if len(f)>=47 and f[12:14]==b'\x08\x00' and f[23]==17 and f[34:38]==struct.pack('!HH',42567,42568) and f[42:47]==b'start':break
src,dst=f[30:34],f[26:30];eth=f[6:12]+f[:6]+b'\x08\x00';body=b'echo-no-df'
req=struct.pack('!BBHHH',8,0,0,0x9382,7)+body;req=req[:2]+struct.pack('!H',csum(req))+req[4:];raw.send(eth+ip(src,dst,1,req))
while True:
    f=raw.recv(65535)
    if len(f)<52 or f[12:14]!=b'\x08\x00' or f[23]!=1 or f[26:34]!=dst+src:continue
    ihl=(f[14]&15)*4; length=int.from_bytes(f[16:18],'big'); hdr=f[14:14+ihl];icmp=f[14+ihl:14+length]
    if csum(hdr) or csum(icmp):continue
    if icmp[:2]!=b'\0\0' or icmp[4:8]!=struct.pack('!HH',0x9382,7) or icmp[8:]!=body:continue
    df=bool(int.from_bytes(f[20:22],'big')&0x4000); print('ECHO_REPLY_DF='+str(int(df)),flush=True)
    if not df: break
msg=b'echo-df-ok';udp=struct.pack('!HHHH',42568,42567,len(msg)+8,0)+msg
raw.send(eth+ip(src,dst,17,udp));print('ECHO_DF_OK',flush=True)
PY
