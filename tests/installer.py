#!/usr/bin/env python3
"""Exercise piped interactive installation and rollback using an isolated Docker double."""
import errno
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import tempfile
import termios
import time

ROOT=Path(tempfile.mkdtemp(prefix="outpost-installer-test-"))
SCRIPT=(Path(__file__).resolve().parents[1]/"install.sh").read_bytes()
KEY="00000000-0000-0000-0000-000000000000"
checks=[]
FAKE=r'''#!/usr/bin/env python3
import json,os,pathlib,sys
root=pathlib.Path(os.environ['FAKE_ROOT']); file=root/'state.json'
s=json.loads(file.read_text()); a=sys.argv[1:]; mode=os.environ.get('FAKE_MODE','')
s.setdefault('calls',[]).append(a)
def done(code=0,output=''):
 file.write_text(json.dumps(s))
 if output: print(output)
 sys.exit(code)
if a[0]=='info': done()
if a[:2]==['context','inspect']: done(output='tcp://remote.example:2376' if mode=='remote' else 'unix:///var/run/docker.sock')
if a[:2]==['container','inspect']: done(0 if s.get('container') else 1)
if a[:2]==['image','inspect']: done(0 if s.get('image') else 1,'sha256:'+'1'*64 if s.get('image') else '')
if a[0]=='pull':
 if mode=='pull': done(1)
 s['image']=True; done()
if a[:2]==['volume','create']: s['volume']=a[-1]; done(output=a[-1])
if a[0]=='create':
 if mode=='create': done(1)
 s['container']=True; s['create_args']=a; done(output='test-container')
if a[0]=='run':
 key=sys.stdin.read()
 lines=key.splitlines()
 assert len(lines[0])==36
 if len(lines)>1:
  assert len(lines)==8 and lines[1]=='outpost-telemetry-v1'
  s['telemetry_bootstrap']=True
 assert '--network' in a and a[a.index('--network')+1]=='none'
 assert '--log-driver' in a and a[a.index('--log-driver')+1]=='none'
 done(1 if mode=='bootstrap' else 0)
if a[0]=='start': done(1 if mode=='start' else 0)
if a[0]=='inspect': done(output='running starting' if mode=='wait' else ('restarting unhealthy' if mode=='health' else 'running healthy'))
if a[0]=='exec': done(output='a'*64 if a[-1]=='credentials' else '100.64.0.2')
if a[:2]==['rm','-f']:
 if a[-1]=='outpost': s['container']=False
 done()
if a[:2]==['volume','rm']: s['volume']=None; done()
if a[:2]==['image','rm']: s['image']=False; done()
raise SystemExit('Unexpected Docker invocation')
'''

def run_case(label, mode='', existing=False, nonempty=False, preexisting=False, interrupt=False, hidden_interrupt=False, telemetry=False):
    case=ROOT/label; case.mkdir()
    binary=case/'bin'; binary.mkdir()
    (binary/'docker').write_text(FAKE); (binary/'docker').chmod(0o755)
    state={'image':False,'container':preexisting,'volume':None}
    (case/'state.json').write_text(json.dumps(state))
    data=case/'backup directory'
    if existing or nonempty:
        data.mkdir(mode=0o755)
    if nonempty: (data/'keep').write_text('preserve')
    original=data.stat() if data.exists() else None
    pipe_r,pipe_w=os.pipe()
    pid,master=pty.fork()
    if pid==0:
        os.close(pipe_w)
        os.dup2(pipe_r,0); os.close(pipe_r)
        env=dict(os.environ,PATH=str(binary)+':'+os.environ['PATH'],FAKE_ROOT=str(case),FAKE_MODE=mode)
        for key in ('DOCKER_HOST','DOCKER_CONTEXT','NB_MANAGEMENT_URL','OUTPOST_IMAGE','OUTPOST_MEMORY_LIMIT'):
            env.pop(key,None)
        if telemetry:
            env.update(OUTPOST_METRICS_URL='https://metrics.example/api/v1/write',OUTPOST_LOGS_URL='https://logs.example/insert/native',OUTPOST_TELEMETRY_TOKEN='test-ingest-token-not-a-real-secret')
        os.execvpe('sh',['sh'],env)
    os.close(pipe_r)
    with os.fdopen(pipe_w, "wb") as source: source.write(SCRIPT)
    output=b''; path_sent=False; key_sent=False; killed=False
    deadline=time.monotonic()+20
    try:
        while time.monotonic()<deadline:
            ready,_,_=select.select([master],[],[],.1)
            if ready:
                try: chunk=os.read(master,65536)
                except OSError as e:
                    if e.errno==errno.EIO: break
                    raise
                if not chunk: break
                output+=chunk
            if b'Dedicated backup directory' in output and not path_sent:
                os.write(master,str(data).encode()+b'\n'); path_sent=True
            if b'NetBird setup key (hidden)' in output and not key_sent:
                # Wait until stty has disabled echo before typing through the PTY.
                if termios.tcgetattr(master)[3] & termios.ECHO: continue
                if hidden_interrupt:
                    os.killpg(pid,signal.SIGINT); killed=True
                else: os.write(master,KEY.encode()+b'\n')
                key_sent=True
            if interrupt and b'Waiting for NetBird' in output and not killed:
                os.killpg(pid,signal.SIGINT); killed=True
        else: raise AssertionError('installer timed out: '+label)
        _,status=os.waitpid(pid,0)
        code=os.waitstatus_to_exitcode(status)
        assert termios.tcgetattr(master)[3]&termios.ECHO,'terminal echo was not restored'
    except BaseException:
        try: os.killpg(pid,signal.SIGKILL)
        except ProcessLookupError: pass
        try: os.waitpid(pid,0)
        except ChildProcessError: pass
        raise
    finally: os.close(master)
    state=json.loads((case/'state.json').read_text())
    success=not any((mode,nonempty,preexisting,hidden_interrupt))
    assert (code==0)==success,(label,code,output.decode(errors='replace'))
    assert b'Illegal number' not in output and b'integer expression expected' not in output, 'shell rollback error'
    assert KEY.encode() not in output,'setup key echoed'
    assert KEY not in json.dumps(state),'setup key in Docker metadata or arguments'
    if success:
        assert state['container'] and state['volume'] and state['image']
        if telemetry:
            assert state.get('telemetry_bootstrap')
            assert 'test-ingest-token-not-a-real-secret' not in json.dumps(state)
        args=state['create_args']
        assert '--read-only' in args and '--cap-drop' in args and '--publish' not in args and '--privileged' not in args
        assert not any('PASSWORD=' in arg or 'SETUP_KEY=' in arg for arg in args)
        assert not (case/'.env').exists()
        if not existing: assert data.stat().st_uid==65532 and data.stat().st_mode&0o777==0o700
    else:
        assert bool(state['container'])==preexisting
        assert not state.get('volume') and not state['image'],(label,state)
        if original:
            after=data.stat(); assert (after.st_uid,after.st_gid,after.st_mode)==(original.st_uid,original.st_gid,original.st_mode)
        else: assert not data.exists(),label
        if nonempty: assert (data/'keep').read_text()=='preserve'
    checks.append(label); print('PASS',label,flush=True)

try:
    assert os.geteuid()==0,'run the installer tests with sudo'
    run_case('piped-install-new-directory')
    run_case('piped-install-existing-directory',existing=True)
    run_case('piped-telemetry-bootstrap',telemetry=True)
    for mode in ('pull','create','bootstrap','start','health','remote'):
        run_case('rollback-'+mode,mode=mode)
    run_case('preserve-existing-container',preexisting=True)
    run_case('preserve-nonempty-directory',nonempty=True)
    run_case('rollback-interrupt',mode='wait',interrupt=True)
    run_case('restore-hidden-terminal-input',hidden_interrupt=True)
    evidence=Path(__file__).resolve().parents[1]/'evidence'
    evidence.mkdir(exist_ok=True)
    (evidence/'installer.json').write_text(json.dumps({'checks':checks,'limitations':['Docker orchestration is simulated; real data plane is tested separately.','No real NetBird enrollment.']},indent=2)+'\n')
    print('ALL',len(checks),'INSTALLER CHECKS PASSED')
finally:
    shutil.rmtree(ROOT)
