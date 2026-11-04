#!/bin/bash
exec python3 - <<'PY'
import socket,struct

def checksum(data):
 if len(data)&1:data+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while n>>16:n=(n&65535)+(n>>16)
 return ~n&65535
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));raw.bind(('tap0',0));mac=bytes.fromhex('02aabbccdd03');alt=bytes.fromhex('02aabbccdd02');mainip=socket.inet_aton('192.0.2.3');altip=socket.inet_aton('192.0.2.2');remote=socket.inet_aton('198.51.100.9');seen=[]
while len(seen)<2:
 f=raw.recv(65535)
 if len(f)>=42 and f[12:14]==b'\x08\x06' and f[20:22]==b'\x00\x01' and f[38:42] in (altip,mainip):
  peer=alt if f[38:42]==altip else mac;peerip=f[38:42];arp=struct.pack('!HHBBH',1,0x800,6,4,2)+peer+peerip+f[22:28]+f[28:32];raw.send(f[6:12]+peer+b'\x08\x06'+arp);continue
 if len(f)<50 or f[12:14]!=b'\x08\x00' or f[23]!=1 or f[30:34]!=remote:continue
 ip=f[14:];ihl=(ip[0]&15)*4;icmp=ip[ihl:struct.unpack('!H',ip[2:4])[0]];data=icmp[8:]
 if len(icmp)!=16 or icmp[0]!=8 or checksum(icmp)!=0:continue
 if data==b'ordinary' and f[:6]!=mac:continue
 if data==b'marked-7' and f[:6]!=alt:continue
 if data not in (b'ordinary',b'marked-7') or data in seen:continue
 reply=b'\x00\x00\x00\x00'+icmp[4:];reply=reply[:2]+struct.pack('!H',checksum(reply))+reply[4:]
 h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(reply),0x1400+len(seen),0,64,1,0,remote,ip[12:16]);h=h[:10]+struct.pack('!H',checksum(h))+h[12:]
 raw.send(f[6:12]+mac+b'\x08\x00'+h+reply);seen.append(data)
print('RAW_MARK_ALTERNATE_GATEWAY_OK',flush=True)
PY
