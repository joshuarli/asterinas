#!/bin/bash
exec python3 - <<'PY'
import socket,struct

def csum(data):
 if len(data)&1:data+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while n>>16:n=(n&65535)+(n>>16)
 return ~n&65535
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));raw.bind(('tap0',0));parts={};ident=None;end=None;first=None
while True:
 f=raw.recv(65535)
 if len(f)<42 or f[12:14]!=b'\x08\x00' or f[14]!=0x47 or f[23]!=17:continue
 total=int.from_bytes(f[16:18],'big');h=f[14:42];flag=int.from_bytes(f[20:22],'big');offset=(flag&8191)*8
 if total>1500 or csum(h) or h[16:20]!=socket.inet_aton('192.0.2.1') or h[20:28]!=b'\x01\x83\x07\x04'+socket.inet_aton('198.51.100.9'):continue
 data=f[42:14+total]
 if offset==0 and (len(data)<8 or data[:4]!=struct.pack('!HH',42567,42568)):continue
 if ident is None:ident=f[18:20]
 if f[18:20]!=ident:continue
 parts[offset]=data
 if offset==0:first=f
 if not flag&0x2000:end=offset+len(data)
 if end is None or first is None:continue
 out=bytearray(end);seen=bytearray(end)
 for pos,part in parts.items():out[pos:pos+len(part)]=part;seen[pos:pos+len(part)]=b'\1'*len(part)
 if not all(seen) or len(parts)<2:continue
 pseudo=h[12:20]+b'\0\x11'+struct.pack('!H',len(out))
 if len(out)==2008 and csum(pseudo+out)==0 and out[8:]==bytes(i%251 for i in range(2000)):break
f=first;src,dst=socket.inet_aton('192.0.2.1'),f[26:30];msg=b'lsrr-valid';udp=struct.pack('!HHHH',42568,42567,8+len(msg),0)+msg
hdr=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0x1021,0,64,17,0,src,dst);hdr=hdr[:10]+struct.pack('!H',csum(hdr))+hdr[12:]
raw.send(f[6:12]+f[:6]+b'\x08\x00'+hdr+udp);print('SOURCE_ROUTE_FRAGMENT_OK',flush=True)
PY
