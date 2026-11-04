#!/bin/bash
exec python3 - <<'PY'
import socket,struct

def checksum(data):
 if len(data)&1:data+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while n>>16:n=(n&65535)+(n>>16)
 return ~n&65535
sink=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sink.bind(('192.0.2.1',42568))
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));raw.bind(('tap0',0));seen=[]
while len(seen)<4:
 f=raw.recv(65535)
 if len(f)<50 or f[12:14]!=b'\x08\x00' or f[23]!=17 or f[36:38]!=struct.pack('!H',42568):continue
 data=f[42:50]
 if data not in (b'ordinary',b'unmasked',b'device-0',b'device-1') or data in seen:continue
 src,dst=f[30:34],f[26:30];udp=struct.pack('!HHHH',42568,struct.unpack('!H',f[34:36])[0],16,0)+data
 h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0x1200+len(seen),0,64,17,0,src,dst);h=h[:10]+struct.pack('!H',checksum(h))+h[12:]
 raw.send(f[6:12]+f[:6]+b'\x08\x00'+h+udp);seen.append(data)
print('SO_MARK_RULE_PEER_OK',flush=True)
PY
