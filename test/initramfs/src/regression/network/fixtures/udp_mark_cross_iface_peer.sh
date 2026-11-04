#!/bin/bash
exec python3 - <<'PY'
import socket,select,struct

def checksum(data):
 if len(data)&1:data+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while n>>16:n=(n&65535)+(n>>16)
 return ~n&65535
s=[]
for name in ('tap0','tap1'):
 x=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));x.bind((name,0));s.append(x)
macs=[bytes.fromhex('02aabbccdd03'),bytes.fromhex('02aabbccdd02')];ips=[socket.inet_aton('192.0.2.3'),socket.inet_aton('192.0.3.2')];remote=socket.inet_aton('198.51.100.9');done=set()
while len(done)<4:
 for x in select.select(s,[],[],20)[0]:
  f=x.recv(65535);idx=s.index(x);mac=macs[idx]
  if len(f)>=42 and f[12:14]==b'\x08\x06' and f[20:22]==b'\x00\x01' and f[38:42]==ips[idx]:
   arp=struct.pack('!HHBBH',1,0x800,6,4,2)+mac+ips[idx]+f[22:28]+f[28:32];x.send(f[6:12]+mac+b'\x08\x06'+arp);continue
  if len(f)<42 or f[12:14]!=b'\x08\x00' or f[23]!=17 or f[30:34]!=remote or f[36:38]!=struct.pack('!H',42568):continue
  ip=f[14:];ihl=(ip[0]&15)*4;udp=ip[ihl:];data=udp[8:];tag=data[:8];
  if tag not in (b'ordinary',b'changed!',b'mtu-test',b'restored') or tag in done:continue
  if idx!=(1 if tag in (b'changed!',b'mtu-test') else 0) or f[:6]!=mac:continue
  if tag==b'mtu-test':
   payload=struct.pack('!BBHHH',3,4,0,0,600)+ip[:ihl+16];payload=payload[:2]+struct.pack('!H',checksum(payload))+payload[4:];proto=1
  else:
   payload=struct.pack('!HHHH',42568,struct.unpack('!H',udp[:2])[0],16,0)+tag;proto=17
  h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),100+len(done),0,64,proto,0,remote,ip[12:16]);h=h[:10]+struct.pack('!H',checksum(h))+h[12:];x.send(f[6:12]+mac+b'\x08\x00'+h+payload);done.add(tag)
  if tag==b'changed!':
   other=struct.pack('!HHHH',42568,42569,16,0)+b'boundif!';h2=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(other),200,0,64,17,0,remote,ip[12:16]);h2=h2[:10]+struct.pack('!H',checksum(h2))+h2[12:];x.send(f[6:12]+mac+b'\x08\x00'+h2+other)
   quote=bytearray(ip[:ihl+16]);quote[ihl:ihl+2]=struct.pack('!H',(struct.unpack('!H',quote[ihl:ihl+2])[0]+1)&65535)
   forged=struct.pack('!BBHHH',3,4,0,0,500)+quote;forged=forged[:2]+struct.pack('!H',checksum(forged))+forged[4:]
   bad=struct.pack('!BBHHH',3,4,0,0,500)+ip[:ihl+16];bad=bad[:2]+struct.pack('!H',checksum(bad)^1)+bad[4:]
   for fake in (forged,bad):
    fh=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(fake),220,0,64,1,0,remote,ip[12:16]);fh=fh[:10]+struct.pack('!H',checksum(fh))+fh[12:];x.send(f[6:12]+mac+b'\x08\x00'+fh+fake)
   barrier=struct.pack('!HHHH',42568,struct.unpack('!H',udp[:2])[0],16,0)+b'barrier!';bh=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(barrier),221,0,64,17,0,remote,ip[12:16]);bh=bh[:10]+struct.pack('!H',checksum(bh))+bh[12:];x.send(f[6:12]+mac+b'\x08\x00'+bh+barrier)
   large=struct.pack('!HHHH',42568,42569,2008,0)+b'fragtest'+bytes(1992)
   for offset in (0,1480):
    fragment=large[offset:offset+1480];flag=(0x2000 if offset==0 else 0)|(offset//8);h3=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(fragment),201,flag,64,17,0,remote,ip[12:16]);h3=h3[:10]+struct.pack('!H',checksum(h3))+h3[12:];x.send(f[6:12]+mac+b'\x08\x00'+h3+fragment)
print('UDP_CROSS_FEEDBACK_OK',flush=True)
PY
