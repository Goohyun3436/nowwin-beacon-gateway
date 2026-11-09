#!/usr/bin/env python3
"""Synthetic fixtures for the existing main.go layout, not real gateway evidence."""
import argparse, socket, struct, time
p=argparse.ArgumentParser();p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int,default=7001);p.add_argument('--csv',action='store_true');args=p.parse_args()
macs=['C30000000001','00C0B1C16BAD','00C0B1000001','AABBCC000001']
with socket.create_connection((args.host,args.port)) as s:
    for i in range(3):
        if args.csv:
            frame=''.join(f'{int(time.time())},{m},-60,0,A00600000001\n' for m in macs).encode()
        else:
            frame=b'\xbb\x01'+b'\0'*4+bytes.fromhex('A00600000001')+struct.pack('>H',len(macs))
            for m in macs:
                frame+=bytes.fromhex(m)+struct.pack('>H',1)+bytes.fromhex('0302010600C4')
            frame+=b'\xdd';frame=frame[:2]+struct.pack('>I',len(frame))+frame[6:]
        s.sendall(frame[:4]);s.sendall(frame[4:]);time.sleep(1)
print('synthetic samples sent (3 accepted MACs, 1 excluded MAC)')
