#!/bin/bash
exec python3 - <<'PY'
import socket,struct

def checksum(data):
 if len(data)&1:data+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while n>>16:n=(n&65535)+(n>>16)
 return ~n&65535
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));raw.bind(('tap0',0));mac=bytes.fromhex(open('/sys/class/net/tap0/address').read().strip().replace(':',''));alternate=bytes.fromhex('02aabbccdd02');guestip=socket.inet_aton('192.0.2.100');altip=socket.inet_aton('192.0.2.2');remote=socket.inet_aton('198.51.100.9');seen=[]
while len(seen)<2:
 f=raw.recv(65535)
 if len(f)>=42 and f[12:14]==b'\x08\x06' and f[20:22]==b'\x00\x01' and f[38:42]==altip:
  arp=struct.pack('!HHBBH',1,0x800,6,4,2)+alternate+altip+f[22:28]+f[28:32]
  raw.send(f[6:12]+alternate+b'\x08\x06'+arp);continue
 if len(f)<50 or f[12:14]!=b'\x08\x00' or f[23]!=17 or f[30:34]!=remote or f[34:38]!=struct.pack('!HH',42567,42568):continue
 data=f[42:50]
 if data==b'ordinary' and f[:6]!=mac:continue
 if data==b'marked-7' and f[:6]!=alternate:continue
 if data not in (b'ordinary',b'marked-7') or data in seen:continue
 udp=struct.pack('!HHHH',42568,42567,16,0)+data;h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0x1400+len(seen),0,64,17,0,remote,guestip);h=h[:10]+struct.pack('!H',checksum(h))+h[12:]
 raw.send(f[6:12]+mac+b'\x08\x00'+h+udp);seen.append(data)
print('MARK_ALTERNATE_GATEWAY_OK',flush=True)
PY
