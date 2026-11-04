#!/bin/bash
exec python3 - <<'PY'
import socket,select
s=[]
for ip in ('192.0.2.1','192.0.3.1'):
 x=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);x.bind((ip,42568));s.append(x)
seen=set()
while len(seen)<2:
 for x in select.select(s,[],[],10)[0]:
  data,src=x.recvfrom(100);x.sendto(data,src);seen.add((x.getsockname()[0],data))
print('TWO_NIC_PEER_OK',flush=True)
PY
