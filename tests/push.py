#!/usr/bin/env python3
"""Real Victoria receivers, a controllable SOCKS tunnel, and persistent sender queues."""
import datetime,io,json,os,secrets,shutil,socket,subprocess,sys,tarfile,tempfile,time,uuid,urllib.parse,urllib.request
from pathlib import Path

IMAGE=os.environ.get('OUTPOST_TEST_IMAGE','outpost-hardened:push-ci')
PREFIX='outpost-push-test-'+uuid.uuid4().hex[:10]
ROOT=Path(tempfile.mkdtemp(prefix=PREFIX+'-'))
STATE=PREFIX+'-state'
PASSWORD=secrets.token_hex(32)
INSTANCE='outpost-persistence-test'
containers=[];proxy=None;checks=[]
http=urllib.request.build_opener(urllib.request.ProxyHandler({}))

def run(*args,good=True,**kwargs):
 p=subprocess.run(args,text=True,capture_output=True,timeout=90,**kwargs)
 if good and p.returncode:raise AssertionError('command failed: '+str(args[:4])+'\n'+p.stderr[:300])
 return p

def docker(*args,**kwargs):return run('docker',*args,**kwargs)
def check(label,condition):
 assert condition,label
 checks.append(label);print('PASS',label,flush=True)
def wait(fn,timeout=30):
 until=time.monotonic()+timeout
 while time.monotonic()<until:
  try:
   value=fn()
   if value:return value
  except (OSError,ValueError,AssertionError):pass
  time.sleep(.5)
 raise AssertionError('timed out waiting for receiver or telemetry')
def get(url,data=None):return http.open(urllib.request.Request(url,data=data),timeout=5).read().decode()
def start_receiver(name,image,args=()):
 containers.append(name)
 docker('run','-d','--name',name,'--memory','256m',image,*args)
 return next(iter(json.loads(docker('inspect',name).stdout)[0]['NetworkSettings']['Networks'].values()))['IPAddress']
def start_outpost(metrics_url,logs_url):
 containers.append(PREFIX)
 docker('run','-d','--name',PREFIX,'--user','65532:65532','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','1g','--pids-limit','128','--stop-timeout','45',
  '--mount',f'type=bind,src={ROOT/"data"},dst=/data','--mount',f'type=volume,src={STATE},dst=/state',
  '--tmpfs','/run/outpost:rw,noexec,nosuid,nodev,size=4m,uid=65532,gid=65532,mode=0700','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700',
  '-e','NB_HOSTNAME='+INSTANCE,IMAGE,'receiver-local')
 wait(lambda:docker('exec',PREFIX,'/usr/bin/outpost','health',good=False).returncode==0)
def metrics(source='metrics'):
 return docker('exec',PREFIX,'/usr/bin/outpost','metrics',source).stdout
def scalar(text,name):
 return float(next(line.rsplit(' ',1)[1] for line in text.splitlines() if line.startswith(name+' ')))
def log_records():
 p=subprocess.run(['docker','cp',PREFIX+':/state/logs/outpost.jsonl','-'],capture_output=True,check=True)
 with tarfile.open(fileobj=io.BytesIO(p.stdout)) as archive:
  content=archive.extractfile(next(x for x in archive if x.isfile())).read().decode()
 return [json.loads(line) for line in content.splitlines()]

SOCKS=r'''
import select,socket,socketserver

def read(sock,n):
 data=b''
 while len(data)<n:
  part=sock.recv(n-len(data))
  if not part:raise EOFError()
  data+=part
 return data
class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  remote=None
  try:
   _,count=read(self.request,2);read(self.request,count);self.request.sendall(b'\x05\x00')
   version,command,_,kind=read(self.request,4)
   if version!=5 or command!=1:return
   if kind==1:host=socket.inet_ntoa(read(self.request,4))
   elif kind==3:host=read(self.request,read(self.request,1)[0]).decode()
   elif kind==4:host=socket.inet_ntop(socket.AF_INET6,read(self.request,16))
   else:return
   port=int.from_bytes(read(self.request,2),'big');remote=socket.create_connection((host,port),timeout=5)
   self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
   while True:
    ready,_,_=select.select([self.request,remote],[],[],10)
    for source in ready:
     data=source.recv(65536)
     if not data:return
     (remote if source is self.request else self.request).sendall(data)
  except (OSError,EOFError):pass
  finally:
   if remote:remote.close()
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
Server(('127.0.0.1',1080),Handler).serve_forever()
'''

try:
 assert os.geteuid()==0,'run with sudo'
 (ROOT/'data').mkdir();(ROOT/'data').chmod(0o777)
 (ROOT/'source').mkdir();(ROOT/'source'/'sample').write_bytes(secrets.token_bytes(67717))
 vm=start_receiver(PREFIX+'-vm','victoriametrics/victoria-metrics:v1.154.0',('-memory.allowedBytes=64MiB','-retentionPeriod=1d'))
 vl=start_receiver(PREFIX+'-vl','victoriametrics/victoria-logs:v1.53.0',('-memory.allowedBytes=64MiB','-retentionPeriod=1d'))
 vm_base='http://'+vm+':8428';vl_base='http://'+vl+':9428'
 wait(lambda:get(vm_base+'/health'));wait(lambda:get(vl_base+'/health'))
 selector='{job="outpost",instance="'+INSTANCE+'"}'
 def exported():return [json.loads(line) for line in get(vm_base+'/api/v1/export?'+urllib.parse.urlencode({'match[]':selector})).splitlines()]
 def remote_logs():return [json.loads(line) for line in get(vl_base+'/select/logsql/query',urllib.parse.urlencode({'query':'job:="outpost" instance:="'+INSTANCE+'" component:="outpost"'}).encode()).splitlines()]
 payload='\n'.join(['00000000-0000-0000-0000-000000000000','outpost-telemetry-v1',vm_base+'/api/v1/write',vl_base+'/insert/native','netbird','test-ingest-token-not-a-real-secret','512MiB','1s'])+'\n'
 docker('run','--rm','-i','--network','none','--user','65532:65532','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--mount',f'type=bind,src={ROOT/"data"},dst=/data','--mount',f'type=volume,src={STATE},dst=/state',IMAGE,'bootstrap',input=payload)
 start_outpost(vm_base+'/api/v1/write',vl_base+'/insert/native')
 PASSWORD=docker('exec',PREFIX,'/usr/bin/outpost','credentials').stdout.strip()
 metadata=json.loads(docker('inspect',PREFIX).stdout)[0]['Config']['Env']
 check('saved push configuration boots without credentials in Docker Env',not any('TOKEN=' in x or 'PASSWORD=' in x or 'SETUP_KEY=' in x for x in metadata))
 docker('run','--rm','--network','container:'+PREFIX,'--mount',f'type=bind,src={ROOT/"source"},dst=/source,readonly','--cap-drop','ALL','-e','RSYNC_PASSWORD','--entrypoint','/usr/bin/rsync',IMAGE,'-a','/source/','rsync://backup@127.0.0.1:8873/backup/probe/',env=dict(os.environ,RSYNC_PASSWORD=PASSWORD))
 before=metrics();old_start=scalar(before,'outpost_start_time_seconds')
 before_count=next(line for line in before.splitlines() if line.startswith('outpost_rsync_transferred_files_total{direction="receive"}'))
 expected=[record for record in log_records() if 'receiver started on loopback' in record['message']]
 check('persistent source logs contain the receiver start event',len(expected)==1)
 wait(lambda:'vm_persistentqueue_bytes_pending' in metrics('vmagent'))
 time.sleep(4)
 check('no direct bypass while the SOCKS tunnel is down',not exported() and not remote_logs())
 docker('restart','--time','40',PREFIX)
 wait(lambda:docker('exec',PREFIX,'/usr/bin/outpost','health',good=False).returncode==0)
 check('rsync counters survive a graceful offline restart',before_count in metrics())
 expected.extend(record for record in log_records() if 'receiver started on loopback' in record['message'] and record['time'] not in {x['time'] for x in expected})
 # Persist the sender queues, then additionally verify replay after an unclean exit and recreation.
 time.sleep(4)
 docker('kill','--signal','KILL',PREFIX)
 docker('rm',PREFIX)
 start_outpost(vm_base+'/api/v1/write',vl_base+'/insert/native')
 check('rsync counters survive recreation with the same state volume',before_count in metrics())
 check('source log history survives kill and recreation',all(any(x['time']==e['time'] and x['message']==e['message'] for x in log_records()) for e in expected))
 fixture=ROOT/'socks.py';fixture.write_text(SOCKS)
 pid=str(json.loads(docker('inspect',PREFIX).stdout)[0]['State']['Pid'])
 proxy=subprocess.Popen(['nsenter','-t',pid,'-n',sys.executable,str(fixture)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 def old_metrics_present():
  return any(x['metric'].get('__name__')=='outpost_start_time_seconds' and old_start in x['values'] for x in exported())
 wait(old_metrics_present,60)
 check('buffered metrics arrive after tunnel recovery and restart with original sample values',old_metrics_present())
 def normalize(value):return datetime.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
 def all_logs_present():
  remote=remote_logs()
  return all(any(x.get('_msg')==e['message'] and abs(normalize(x['_time'])-normalize(e['time']))<.00001 for x in remote) for e in expected)
 wait(all_logs_present,60)
 check('buffered logs arrive after tunnel recovery with original event timestamps',all_logs_present())
 old_samples=[timestamp for item in exported() if item['metric'].get('__name__')=='outpost_start_time_seconds' for value,timestamp in zip(item['values'],item['timestamps']) if value==old_start]
 check('metric timestamps remain earlier than the offline restart',bool(old_samples) and min(old_samples)<normalize(expected[-1]['time'])*1000)
 check('backend queries contain no backup credentials',PASSWORD not in json.dumps(exported()) and PASSWORD not in json.dumps(remote_logs()))
 evidence=Path(__file__).resolve().parents[1]/'evidence';evidence.mkdir(exist_ok=True)
 arch=docker('image','inspect',IMAGE,'--format','{{.Architecture}}').stdout.strip()
 (evidence/('push-'+arch+'.json')).write_text(json.dumps({'checks':checks,'limitations':['SOCKS proxy simulates the tunnel; real NetBird ACL and peer enrollment are separate acceptance.','Hard-kill test verifies previously persisted data; power-loss durability is not established.']},indent=2)+'\n')
 print('ALL',len(checks),'PUSH CHECKS PASSED')
finally:
 if proxy:
  proxy.terminate()
  try:proxy.wait(timeout=3)
  except subprocess.TimeoutExpired:proxy.kill();proxy.wait()
 for name in reversed(list(dict.fromkeys(containers))):docker('rm','-fv',name,good=False)
 docker('volume','rm',STATE,good=False)
 shutil.rmtree(ROOT)
