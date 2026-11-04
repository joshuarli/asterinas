#!/bin/bash
exec python3 - <<'PY'
import socket,struct

def checksum(data):
 if len(data)&1:data+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while n>>16:n=(n&65535)+(n>>16)
 return ~n&65535
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));raw.bind(('tap0',0)); mac=bytes.fromhex('02aabbccdd03');alt=bytes.fromhex('02aabbccdd02');altip=socket.inet_aton('192.0.2.2');mainip=socket.inet_aton('192.0.2.3');remote=socket.inet_aton('198.51.100.9')
while True:
 f=raw.recv(65535)
 if len(f)>=42 and f[12:14]==b'\x08\x06' and f[20:22]==b'\x00\x01' and f[38:42] in (altip,mainip):
  peer=alt if f[38:42]==altip else mac; peerip=f[38:42]; arp=struct.pack('!HHBBH',1,0x800,6,4,2)+peer+peerip+f[22:28]+f[28:32];raw.send(f[6:12]+peer+b'\x08\x06'+arp);continue
 if len(f)<42 or f[12:14]!=b'\x08\x00' or f[23]!=17 or f[30:34]!=remote or f[34:38]!=struct.pack('!HH',42567,42568):continue
 ip=f[14:]; total=struct.unpack('!H',ip[2:4])[0]
 if total==928 and f[:6]==mac:
  icmp=struct.pack('!BBHHH',3,4,0,0,600)+ip[:total];icmp=icmp[:2]+struct.pack('!H',checksum(icmp))+icmp[4:]
  outer=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(icmp),1,0,64,1,0,remote,ip[12:16]);outer=outer[:10]+struct.pack('!H',checksum(outer))+outer[12:];raw.send(f[6:12]+mac+b'\x08\x00'+outer+icmp)
 if total==728 and f[:6]==alt:
  udp=struct.pack('!HHHH',42568,42567,16,0)+b'alt-path'; outer=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),2,0,64,17,0,remote,ip[12:16]); outer=outer[:10]+struct.pack('!H',checksum(outer))+outer[12:]; raw.send(f[6:12]+alt+b'\x08\x00'+outer+udp)
  print('MARK_PMTU_ALTERNATE_GATEWAY_OK',flush=True);break
PY
