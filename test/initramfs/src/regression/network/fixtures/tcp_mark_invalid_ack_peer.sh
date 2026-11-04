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
macs=[bytes.fromhex('02aabbccdd03'),bytes.fromhex('02aabbccdd02')];ips=[socket.inet_aton('192.0.2.3'),socket.inet_aton('192.0.3.2')];remote=socket.inet_aton('198.51.100.9');seen=[];serverseq=10000;base=None;received=bytearray();stage=0;marked_ip=None;stale_sent=False
while b'mtu-ok!!' not in seen:
 for x in select.select(s,[],[],15)[0]:
  f=x.recv(65535); idx=s.index(x);mac=macs[idx]
  if len(f)>=42 and f[12:14]==b'\x08\x06' and f[20:22]==b'\x00\x01' and f[38:42]==ips[idx]:
   arp=struct.pack('!HHBBH',1,0x800,6,4,2)+mac+ips[idx]+f[22:28]+f[28:32];x.send(f[6:12]+mac+b'\x08\x06'+arp);continue
  if len(f)<54 or f[12:14]!=b'\x08\x00' or f[23]!=6 or f[30:34]!=remote or f[36:38]!=struct.pack('!H',42568):continue
  ip=f[14:];ihl=(ip[0]&15)*4;total=struct.unpack('!H',ip[2:4])[0];t=ip[ihl:total];seq,ack=struct.unpack('!II',t[4:12]);hlen=(t[12]>>4)*4;flags=t[13];data=t[hlen:];pseudo=ip[12:20]+struct.pack('!BBH',0,6,len(t));
  if checksum(ip[:ihl])!=0:continue
  if idx==1 and len(data)>0 and all(byte==88 for byte in data):
   if base is None:
    if len(ip)<=600:continue
    base=seq;received=bytearray(900);stage=1
    invalid=struct.pack('!HHIIBBHHH',42568,struct.unpack('!H',t[:2])[0],serverseq+1000000,seq+len(data),0x50,0x10,65535,0,0)
    pseudo=remote+ip[12:16]+struct.pack('!BBH',0,6,len(invalid));invalid=invalid[:16]+struct.pack('!H',checksum(pseudo+invalid))+invalid[18:]
    h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(invalid),298,0,64,6,0,remote,ip[12:16]);h=h[:10]+struct.pack('!H',checksum(h))+h[12:];x.send(f[6:12]+mac+b'\x08\x00'+h+invalid)
    icmp=struct.pack('!BBHHH',3,4,0,0,600)+ip[:ihl+8];icmp=icmp[:2]+struct.pack('!H',checksum(icmp))+icmp[4:]
    outer=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(icmp),301,0,64,1,0,remote,ip[12:16]);outer=outer[:10]+struct.pack('!H',checksum(outer))+outer[12:];x.send(f[6:12]+mac+b'\x08\x00'+outer+icmp);stage=2;continue
   offset=seq-base
   if len(ip)>600 or offset<0 or offset+len(data)>900:continue
   received[offset:offset+len(data)]=data
   contiguous=0
   while contiguous<900 and received[contiguous]==88:contiguous+=1
   replyflags=0x10;acknowledged=base+contiguous;payload=b''
   if contiguous==900:
    payload=b'mtu-ok!!';replyflags=0x18;seen.append(payload)
  elif flags&2:
   if idx!=0:continue
   replyflags=0x12;serverseq=10000;acknowledged=seq+1;payload=b''
  elif data in (b'ordinary',b'marked-7'):
   if data==b'ordinary' and idx!=0:continue
   if data==b'marked-7' and idx!=1:continue
   if data in seen:continue
   if data==b'marked-7':marked_ip=ip[:ihl+8]
   seen.append(data);replyflags=0x18;acknowledged=seq+len(data);payload=data
  elif not data and idx==1 and b'marked-7' in seen and b'verified' not in seen and ack==serverseq:
   seen.append(b'verified');replyflags=0x18;acknowledged=seq;payload=b'verified'
  elif not data and idx==1 and b'verified' in seen and not stale_sent and ack==serverseq:
   stale_sent=True;icmp=struct.pack('!BBHHH',3,4,0,0,600)+marked_ip;icmp=icmp[:2]+struct.pack('!H',checksum(icmp))+icmp[4:]
   outer=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(icmp),299,0,64,1,0,remote,ip[12:16]);outer=outer[:10]+struct.pack('!H',checksum(outer))+outer[12:];x.send(f[6:12]+mac+b'\x08\x00'+outer+icmp)
   replyflags=0x18;acknowledged=seq;payload=b'stalebar'
  else:continue
  opts=b'\x02\x04\x05\xb4' if replyflags&2 else b''
  tcp=struct.pack('!HHIIBBHHH',42568,struct.unpack('!H',t[:2])[0],serverseq,acknowledged,((20+len(opts))//4)<<4,replyflags,65535,0,0)+opts+payload
  pseudo=remote+ip[12:16]+struct.pack('!BBH',0,6,len(tcp));tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
  h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),123,0,64,6,0,remote,ip[12:16]);h=h[:10]+struct.pack('!H',checksum(h))+h[12:]
  x.send(f[6:12]+mac+b'\x08\x00'+h+tcp);serverseq+=len(payload)+(1 if replyflags&2 else 0)
print('TCP_MARK_CROSS_INTERFACE_OK',flush=True)
PY
