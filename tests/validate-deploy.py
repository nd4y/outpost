import json,os,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
env=dict(os.environ,BACKUP_PATH='/tmp/outpost-example',NB_HOSTNAME='outpost-example',NB_MANAGEMENT_URL='https://management.example',NB_SETUP_KEY='',OUTPOST_RSYNC_PASSWORD='test-only-configuration-password-0000')
p=subprocess.run(['docker','compose','--env-file',str(root/'.env.example'),'-f',str(root/'compose.yaml'),'config','--format','json'],env=env,text=True,capture_output=True,check=True)
s=json.loads(p.stdout)['services']['outpost']
assert s['user']=='65532:65532' and s['read_only'] and s['cap_drop']==['ALL']
assert 'ports' not in s and 'devices' not in s and 'privileged' not in s and 'network_mode' not in s
assert s['security_opt']==['no-new-privileges:true']
assert len(s['volumes'])==2
assert 'cpus' not in s and s['cpu_shares']==256
assert int(s['mem_limit'])==1073741824 and int(s['memswap_limit'])==1073741824
assert s['volumes'][0].get('bind', {}).get('create_host_path', False) is False
subprocess.run(['sh','-n',str(root/'docker-run.sh')],check=True)
subprocess.run(['sh','-n',str(root/'install.sh')],check=True)
assert not (root/'.env').exists()
print('Compose hardened settings, fail-closed bind and docker-run syntax verified')