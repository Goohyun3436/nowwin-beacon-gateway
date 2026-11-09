#!/usr/bin/env python3
"""Launch a built test binary on temporary ports and verify TCP -> dashboard API."""
import json, pathlib, socket, subprocess, tempfile, time, urllib.request
root=pathlib.Path(__file__).resolve().parents[1]
def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]
tcp,web=port(),port()
with tempfile.TemporaryDirectory() as d:
    proc=subprocess.Popen([str(root/'.scanner'),'-tcp',f'127.0.0.1:{tcp}','-web',f'127.0.0.1:{web}','-log',str(pathlib.Path(d)/'capture.jsonl')])
    try:
        url=f'http://127.0.0.1:{web}'
        for _ in range(100):
            try:
                with urllib.request.urlopen(url) as r: assert b'Beacon Scanner Lab' in r.read()
                break
            except OSError: time.sleep(.05)
        else: raise RuntimeError('server did not start')
        for flags in ([],['--csv']):
            subprocess.run(['python3',str(root/'scripts/send_sample.py'),'--port',str(tcp),*flags],check=True)
        with urllib.request.urlopen(url+'/api/state') as r: state=json.load(r)
        assert state['Packets']==15, state
        assert state['Errors']==0, state
        assert state['Filtered']==6, state
        assert len(state['Beacons'])==3, state
        assert all(v['Count']==6 for v in state['Beacons'].values()), state
        assert not (pathlib.Path(d)/'capture.jsonl').exists(), 'unexpected disk capture'
        records=state['Events']
        assert any(e['Kind']=='raw-chunk' and e['RawHex'] for e in records)
        print('PASS: binary + CSV TCP ingestion, MAC filter, counts, raw capture, dashboard/API')
    finally:
        proc.terminate();proc.wait(timeout=10)
