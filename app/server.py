#!/usr/bin/env python3
"""Loopback-only SIP tunnel manager; WireGuard keys remain in wg-easy."""
import base64
import configparser
import contextlib
import fcntl
import hashlib
import http.cookiejar
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(os.environ.get('SIP_ROOT', '/opt/sip-tunnel'))
WEB = Path(__file__).resolve().parent / 'web'
NOT_FOUND_PAGE = (WEB / '404.html').read_text(encoding='utf-8')
NOT_FOUND_STYLE_HASH = base64.b64encode(hashlib.sha256(re.search(r'<style>(.*?)</style>',NOT_FOUND_PAGE,re.S)[1].encode()).digest()).decode()
NOT_FOUND_CSP = "default-src 'none'; style-src 'sha256-" + NOT_FOUND_STYLE_HASH + "'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
STATE = ROOT / 'clients.json'
SETTINGS = ROOT / 'settings.json'
ENROLLMENTS = ROOT / 'enrollments.json'
ADMIN = ROOT / 'panel-admin.json'
SESSION_STORE = ROOT / 'panel-sessions.json'
SESSION_SECONDS = 8 * 3600
UPSTREAM = 'http://127.0.0.1:51821/api/'
PUBLIC_IP = str(ipaddress.IPv4Address(os.environ.get('SIP_PUBLIC_IP','127.0.0.1')))
BIND_IP = str(ipaddress.IPv4Address(os.environ.get('SIP_BIND_IP',PUBLIC_IP)))
PUBLIC_IF = os.environ.get('SIP_PUBLIC_IF','eth0')
if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',PUBLIC_IF):
    raise ValueError('Invalid network interface')
PORT = 51822
SESSIONS = {}
LOGIN_ATTEMPTS = {}
CONNECT_ATTEMPTS = {}
PROFILE_ATTEMPTS = {}
LOCK = threading.RLock()
RESERVED = {2019, 51820, 51821, 51822}
# Cloudflare public proxy ranges: cloudflare.com/ips-v4 and /ips-v6.
CLOUDFLARE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22', '2400:cb00::/32',
    '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
    '2a06:98c0::/29', '2c0f:f248::/32',
))

class UserError(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status

class Upstream:
    def __init__(self):
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.lock = threading.RLock()

    def call(self, path, data=None, method=None, raw=False):
        body = None if data is None else json.dumps(data).encode()
        request = urllib.request.Request(UPSTREAM + path, data=body, method=method,
                                        headers={'Content-Type': 'application/json'})
        try:
            with self.lock, self.opener.open(request, timeout=25) as response:
                result = response.read()
                return result.decode() if raw else json.loads(result)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise UserError('登录已失效或账号密码不正确，请重新登录。', 401) from None
            raise UserError('WireGuard 后台操作失败，请刷新后重试。', 502) from None
        except (urllib.error.URLError, TimeoutError):
            raise UserError('WireGuard 后台暂时不可达，请稍后重试。', 503) from None

def load_state():
    return json.loads(STATE.read_text())

def load_enrollments():
    return json.loads(ENROLLMENTS.read_text()) if ENROLLMENTS.exists() else {}

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=32768,r=8,p=1,maxmem=64*1024*1024,dklen=32)
    return {'salt':salt,'hash':digest.hex()}

def password_matches(password, stored):
    return secrets.compare_digest(hash_password(password,stored['salt'])['hash'],stored['hash'])

def load_admin():
    return json.loads(ADMIN.read_text())

def initialize_admin():
    with mutation():
        if not ADMIN.exists():
            initial = json.loads((ROOT/'admin-credentials.json').read_text())
            save_json(ADMIN,{'username':initial['username'],'password':hash_password(initial['password']),'revision':0})

def authenticate_service():
    credentials = json.loads((ROOT/'admin-credentials.json').read_text())
    upstream = Upstream()
    try:
        result = upstream.call('auth/password',{
            'username':credentials['username'],'password':credentials['password'],'remember':False})
        if result.get('status') != 'success': raise UserError('内部服务需要管理员检查。',503)
        upstream.call('admin/userconfig')
        return upstream
    except UserError as error:
        try: upstream.call('session',method='DELETE')
        except UserError: pass
        if error.status == 401: raise UserError('内部服务凭据需要检查。',503) from None
        raise

class ServiceSession:
    def __init__(self):
        self.client = None
        self.lock = threading.RLock()

    def call(self, path, *args, **kwargs):
        with self.lock:
            if self.client is None: self.client = authenticate_service()
            try:
                return self.client.call(path,*args,**kwargs)
            except UserError as error:
                if error.status != 401: raise
                self.client = authenticate_service()
                try: return self.client.call(path,*args,**kwargs)
                except UserError as retry:
                    if retry.status == 401: raise UserError('内部服务暂不可用，请稍后重试。',503) from None
                    raise

def service_session():
    return ServiceSession()

def load_sessions():
    return json.loads(SESSION_STORE.read_text()) if SESSION_STORE.exists() else {}

def session_key(sid):
    return hashlib.sha256(sid.encode()).hexdigest()

def remember_session(sid, session):
    with mutation():
        revision = load_admin()['revision']
        if session['revision'] != revision: raise UserError('账号已修改，请重新登录。',401)
        records = {key:value for key,value in load_sessions().items()
                   if value['expires']>time.time() and value['revision']==revision}
        if len(records)>=100: raise UserError('会话过多，请稍后再试。',429)
        key = session_key(sid)
        records[key] = {field:session[field] for field in ('csrf','expires','revision')}
        save_json(SESSION_STORE,records)
        SESSIONS[key] = session
        for cached in list(SESSIONS):
            if cached not in records: SESSIONS.pop(cached,None)

def forget_session(sid):
    with mutation():
        key = session_key(sid)
        records = load_sessions()
        if key in records:
            records.pop(key)
            save_json(SESSION_STORE,records)
        SESSIONS.pop(key,None)

def restore_session(sid, csrf=None):
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}',sid): raise UserError('请重新登录。',401)
    key = session_key(sid)
    with LOCK:
        stored = load_sessions().get(key)
        if not stored or stored['expires']<=time.time() or stored['revision']!=load_admin()['revision']:
            forget_session(sid)
            raise UserError('请重新登录。',401)
        if csrf is not None and not secrets.compare_digest(csrf,stored['csrf']):
            raise UserError('请求校验失败，请刷新页面。',403)
        if key not in SESSIONS:
            SESSIONS[key] = {**stored,'upstream':service_session()}
        return SESSIONS[key]

def update_admin(body):
    username = body.get('username','')
    current = body.get('currentPassword','')
    password = body.get('newPassword','')
    confirm = body.get('confirmPassword','')
    if not all(isinstance(value,str) for value in (username,current,password,confirm)):
        raise UserError('填写内容格式不正确。')
    username = username.strip()
    if username and not re.fullmatch(r'[\w.@-]{2,48}',username):
        raise UserError('账号需为 2–48 位中文、字母、数字、点、横线或下划线。')
    if not current or len(current)>512: raise UserError('请输入当前密码。')
    if password != confirm: raise UserError('两次新密码不一致。')
    if password and not 8<=len(password)<=128: raise UserError('新密码需为 8–128 位。')
    with mutation():
        admin = load_admin()
        check_rate(PROFILE_ATTEMPTS,'administrator',5)
        if not password_matches(current,admin['password']): raise UserError('当前密码不正确。',403)
        username = username or admin['username']
        changed = username != admin['username'] or bool(password and password != current)
        if changed:
            admin['username'] = username
            if password: admin['password'] = hash_password(password)
            admin['revision'] += 1
            save_json(ADMIN,admin)
            save_json(SESSION_STORE,{})
            SESSIONS.clear()
        return {'ok':True,'changed':changed,'username':username}

def check_rate(bucket, address, limit):
    with LOCK:
        now = time.time()
        for key in list(bucket):
            bucket[key] = [stamp for stamp in bucket[key] if stamp > now-60]
            if not bucket[key]: del bucket[key]
        attempts = bucket.setdefault(address, [])
        if len(attempts) >= limit or sum(map(len, bucket.values())) >= 200:
            raise UserError('请求过于频繁，请一分钟后再试。',429)
        attempts.append(now)

def client_configuration(upstream, record):
    client = upstream.call(f'client/{record["id"]}')
    if client['ipv4Address'] != record['ip'] or not client['enabled']:
        raise UserError('客户端地址或启用状态已改变，请先核对。',409)
    raw = upstream.call(f'client/{record["id"]}/configuration',raw=True)
    return export_config(raw,record)

def redeem_enrollment(token, installation_id):
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}',token):
        raise UserError('接入码无效。',401)
    if not isinstance(installation_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,64}',installation_id):
        raise UserError('installationId 需为本地生成的 16–64 位随机标识。')
    digest = hashlib.sha256(token.encode()).hexdigest()
    with mutation():
        codes = load_enrollments()
        entry = next((value for value in codes.values() if secrets.compare_digest(value['hash'],digest)),None)
        if not entry: raise UserError('接入码无效或已被替换。',401)
        if entry.get('installationId'):
            if entry['installationId'] != installation_id:
                raise UserError('接入码已绑定其他本地服务器。',409)
        record = next((row for row in load_state()['clients'] if row['id']==entry['clientId']),None)
        if not record: raise UserError('客户端已删除。',410)
        upstream = service_session()
        try:
            configuration = client_configuration(upstream,record)
        finally:
            try: upstream.call('session',method='DELETE')
            except UserError: pass
        settings = load_settings()
        payload = {
            'version':1,
            'client':{'id':record['id'],'name':record['name']},
            'wireguard':{'interface':f'sip{record["id"]}','config':configuration},
            'sip':{'server':settings['sipDomain'] or PUBLIC_IP,'bindAddress':record['ip'],
                   'publicAddress':PUBLIC_IP,'portRange':{'start':record['start'],'end':record['end']},
                   'protocols':['tcp','udp']},
            'routing':{'mode':'source','preserveDefaultRoute':True,'preserveDns':True}
        }
        if not entry.get('installationId'):
            entry['installationId'] = installation_id
            save_json(ENROLLMENTS,codes)
        return payload

def load_settings():
    return json.loads(SETTINGS.read_text()) if SETTINGS.exists() else {'sipDomain':'','panelDomain':''}

def domain_name(value):
    if not isinstance(value,str) or len(value)>253:
        raise UserError('请输入有效域名，不含协议、端口或路径。')
    value=value.strip().lower().rstrip('.')
    if not value: return ''
    try: value=value.encode('idna').decode('ascii')
    except UnicodeError: raise UserError('域名格式不正确。') from None
    if len(value)>253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in value.split('.')):
        raise UserError('请输入有效域名，不含协议、端口或路径。')
    try: ipaddress.ip_address(value)
    except ValueError: return value
    raise UserError('此处请填写域名；留空即使用云服务器 IP。')

def check_domain(domain, allow_proxy=False):
    result = {'domain':domain,'addresses':[],'ok':False,'mode':'invalid'}
    if not domain:
        return {**result,'ok':True,'mode':'ip'}
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain,None,type=socket.SOCK_STREAM)})
    except socket.gaierror:
        return result
    result['addresses'] = addresses
    if addresses == [PUBLIC_IP]:
        return {**result,'ok':True,'mode':'direct'}
    # Proxy recognition does not verify the Cloudflare origin configuration.
    proxied = bool(addresses) and all(
        any(ipaddress.ip_address(address) in network for network in CLOUDFLARE_NETWORKS)
        for address in addresses
    )
    if allow_proxy and proxied:
        return {**result,'ok':True,'mode':'cloudflare'}
    return result


def enrollment_endpoint(settings):
    return 'https://' + (settings['sipDomain'] or PUBLIC_IP) + '/api/connect'

def caddy_config(domain, sip_domain=""):
    base='''{
    default_sni PUBLIC_IP
}
PUBLIC_IP {
    tls {
        issuer acme {
            dir https://acme-v02.api.letsencrypt.org/directory
            profile shortlived
        }
    }
    encode zstd gzip
    header {
        X-Robots-Tag "noindex, nofollow"
        Strict-Transport-Security "max-age=604800"
        -Server
    }
    reverse_proxy 127.0.0.1:51822
}
'''.replace('PUBLIC_IP',PUBLIC_IP)
    if domain:
        base+=f'''{domain} {{
    encode zstd gzip
    header X-Robots-Tag "noindex, nofollow"
    header -Server
    reverse_proxy 127.0.0.1:51822
}}
'''
    if sip_domain and sip_domain != domain:
        base+=f'''{sip_domain} {{
    header X-Robots-Tag "noindex, nofollow"
    header -Server
    handle /api/connect {{
        reverse_proxy 127.0.0.1:51822
    }}
    handle {{
        respond 404
    }}
}}
'''
    return base

def save_settings(settings):
    config_path=ROOT/'Caddyfile'
    old_config=config_path.read_text()
    new_config=caddy_config(settings['panelDomain'], settings['sipDomain'])
    def reload_config(value):
        req=urllib.request.Request('http://127.0.0.1:2019/load',data=value.encode(),headers={'Content-Type':'text/caddyfile'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=30) as response:
            response.read()
    try:
        if old_config != new_config:
            config_path.write_text(new_config)
            reload_config(new_config)
        temp=SETTINGS.with_suffix('.tmp')
        temp.write_text(json.dumps(settings,ensure_ascii=False,indent=2))
        os.chmod(temp,0o600)
        os.replace(temp,SETTINGS)
    except Exception:
        config_path.write_text(old_config)
        if old_config != new_config: reload_config(old_config)
        raise UserError('域名配置未完成，已回滚。请检查 DNS 和证书服务。',502) from None

def save_json(path, value):
    temp = path.with_suffix('.json.tmp')
    with temp.open('w') as f:
        os.chmod(temp, 0o600)
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)

def save_state(state):
    save_json(STATE,state)

@contextlib.contextmanager
def mutation():
    with LOCK, (ROOT / 'panel.lock').open('a') as lockfile:
        fcntl.flock(lockfile, fcntl.LOCK_EX)
        yield

def validate_client(name, start, end, clients):
    if not isinstance(name, str) or not re.fullmatch(r'[\w .\-]{1,48}', name.strip()):
        raise UserError('名称限 1–48 个中文、字母、数字、空格、点、横线或下划线。')
    name = name.strip()
    if type(start) is not int or type(end) is not int or not 1024 <= start <= end <= 65535:
        raise UserError('端口需为 1024–65535 的整数，起始端口不得大于结束端口。')
    if any(start <= port <= end for port in RESERVED):
        raise UserError('范围不能包含 2019、51820、51821、51822，这些端口用于隧道和管理。')
    for c in clients:
        if c['name'].casefold() == name.casefold():
            raise UserError('客户端名称已存在。')
        if start <= c['end'] and end >= c['start']:
            raise UserError(f'端口与「{c["name"]}」的 {c["start"]}–{c["end"]} 重叠。')
    return name

def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=25, **kwargs)

def apply_rules(state):
    # Validate persisted data before constructing the restore input.
    seen = []
    for c in state['clients']:
        validate_client(c['name'], c['start'], c['end'], seen)
        ip = ipaddress.IPv4Address(c['ip'])
        if ip not in ipaddress.ip_network('10.77.0.0/24') or int(str(ip).split('.')[-1]) not in range(2,255):
            raise UserError('客户端隧道地址不在可用网段。')
        if any(x['ip'] == c['ip'] for x in seen):
            raise UserError('客户端隧道地址重复。')
        seen.append(c)
    for table, chain in [('nat', 'SIPT_DNAT'), ('nat', 'SIPT_SNAT'), ('filter', 'SIPT_FORWARD')]:
        check = subprocess.run(['iptables','-w','10','-t',table,'-S',chain],capture_output=True)
        if check.returncode:
            run(['iptables','-w','10','-t',table,'-N',chain])
    nat = ['*nat', '-F SIPT_DNAT', '-F SIPT_SNAT']
    forward = ['*filter', '-F SIPT_FORWARD',
        f'-A SIPT_FORWARD -i wg0 -o {PUBLIC_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
        f'-A SIPT_FORWARD -i {PUBLIC_IF} -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT']
    for c in state['clients']:
        ip, ports = c['ip'], f'{c["start"]}:{c["end"]}'
        for protocol in ('tcp','udp'):
            nat.append(f'-A SIPT_DNAT -p {protocol} --dport {ports} -j DNAT --to-destination {ip}')
            forward.append(f'-A SIPT_FORWARD -i {PUBLIC_IF} -o wg0 -d {ip} -p {protocol} --dport {ports} -j ACCEPT')
            forward.append(f'-A SIPT_FORWARD -i wg0 -o {PUBLIC_IF} -s {ip} -p {protocol} --sport {ports} -j ACCEPT')
        nat.append(f'-A SIPT_SNAT -s {ip} -j SNAT --to-source {BIND_IP}')
    forward += ['-A SIPT_FORWARD -i wg0 -j DROP', '-A SIPT_FORWARD -o wg0 -j DROP',
                '-A SIPT_FORWARD -j RETURN', 'COMMIT']
    payload = '\n'.join(nat + ['COMMIT'] + forward) + '\n'
    run(['iptables-restore','-w','10','--noflush','--test'],input=payload)
    run(['iptables-restore','-w','10','--noflush'],input=payload)
    jumps = [('nat','PREROUTING',['-i',PUBLIC_IF,'-d',BIND_IP,'-j','SIPT_DNAT']),
             ('nat','POSTROUTING',['-o',PUBLIC_IF,'-j','SIPT_SNAT']),
             ('filter','FORWARD',['-j','SIPT_FORWARD'])]
    for table, chain, args in jumps:
        check = subprocess.run(['iptables','-w','10','-t',table,'-C',chain]+args,capture_output=True)
        if check.returncode:
            run(['iptables','-w','10','-t',table,'-I',chain,'1']+args)

def commit_state(old, new):
    try:
        save_state(new)
        apply_rules(new)
    except Exception:
        save_state(old)
        apply_rules(old)
        raise

def export_config(raw, record):
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read_string(raw)
    for section, field in [('Interface','PrivateKey'),('Peer','PublicKey'),('Peer','PresharedKey')]:
        if not re.fullmatch(r'[A-Za-z0-9+/]{43}=',cfg[section][field]):
            raise UserError('后台返回的密钥格式不正确。',502)
    ip = record['ip']
    table = 42000 + int(ip.split('.')[-1])
    priority = 14000 + int(ip.split('.')[-1])
    return f'''# Ubuntu 24.04 / Debian: wg-quick configuration
# Client: {record['name']}
# Public TCP/UDP ports: {record['start']}-{record['end']}
# Bind SIP and RTP to {ip}; advertise {PUBLIC_IP} externally.
# Contains a private key. Do not share or import on multiple machines.
# Only traffic sourced from {ip} uses the cloud; default route and DNS stay unchanged.
[Interface]
PrivateKey = {cfg['Interface']['PrivateKey']}
Address = {ip}/32
MTU = 1380
Table = off
PreUp = test -z "$(ip -4 route show table {table} 2>/dev/null)" && ! ip -4 rule show | grep -q '^{priority}:'
PostUp = ip -4 route add 10.77.0.1/32 dev %i
PostUp = ip -4 route add default dev %i table {table}
PostUp = ip -4 rule add priority {priority} from {ip}/32 lookup {table}
PostUp = sysctl -q -w net.ipv4.conf.%i.rp_filter=2
PostDown = ip -4 rule del priority {priority} from {ip}/32 lookup {table} 2>/dev/null || true

[Peer]
PublicKey = {cfg['Peer']['PublicKey']}
PresharedKey = {cfg['Peer']['PresharedKey']}
AllowedIPs = 0.0.0.0/0
Endpoint = {load_settings()['sipDomain'] or PUBLIC_IP}:51820
PersistentKeepalive = 25
'''

class Handler(BaseHTTPRequestHandler):
    server_version = 'SIPPanel'
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        # Never log request bodies, cookies, passwords or configuration files.
        pass

    def send(self, status, value, content_type='application/json; charset=utf-8', extra=None, cache='no-store', csp=None):
        if isinstance(value, (dict,list)):
            value = json.dumps(value,ensure_ascii=False).encode()
        elif isinstance(value,str):
            value = value.encode()
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(value)))
        self.send_header('Cache-Control',cache)
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',csp or "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key,val in (extra or {}).items():
            self.send_header(key,val)
        self.end_headers()
        self.wfile.write(value)

    def not_found(self):
        return self.send(404,NOT_FOUND_PAGE,'text/html; charset=utf-8',csp=NOT_FOUND_CSP)

    def body(self):
        try:
            size = int(self.headers.get('Content-Length','0'))
            if not 0 < size <= 16384:
                raise ValueError()
            if self.headers.get('Content-Type','').split(';')[0] != 'application/json':
                raise ValueError()
            data = json.loads(self.rfile.read(size))
            if not isinstance(data,dict):
                raise ValueError()
            return data
        except (ValueError,json.JSONDecodeError):
            raise UserError('请求格式不正确。') from None

    def session(self, csrf=False):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie',''))
            sid = cookie['sip_session'].value
        except Exception:
            raise UserError('请先登录。',401) from None
        session = restore_session(sid,self.headers.get('X-CSRF-Token','') if csrf else None)
        return sid,session

    def dispatch(self):
        host = self.headers.get('Host','')
        settings=load_settings()
        local=host in (f'127.0.0.1:{PORT}',f'localhost:{PORT}')
        public_hosts={PUBLIC_IP,PUBLIC_IP+':443'}
        if settings['panelDomain']: public_hosts.update({settings['panelDomain'],settings['panelDomain']+':443'})
        sip_hosts = {settings['sipDomain'],settings['sipDomain']+':443'} if settings['sipDomain'] else set()
        if host in sip_hosts and host not in public_hosts and not (self.command == 'POST' and self.path == '/api/connect'):
            return self.not_found()
        public_hosts.update(sip_hosts)
        if not local and host not in public_hosts:
            raise UserError('此访问域名尚未配置。',403)
        scheme='http' if local else 'https'
        if not local and self.headers.get('X-Forwarded-Proto')!='https':
            raise UserError('请使用 HTTPS 访问管理面板。',403)
        agent_request = self.command == 'POST' and self.path == '/api/connect'
        if agent_request and self.headers.get('Origin'):
            raise UserError('请由本地服务器后端调用接入接口。',403)
        if self.command != 'GET' and not agent_request and self.headers.get('Origin') != scheme+'://'+host:
            raise UserError('请求来源不正确。',403)
        path = self.path
        if agent_request:
            address=self.client_address[0] if local else self.headers.get('X-Forwarded-For',self.client_address[0]).split(',')[-1].strip()
            check_rate(CONNECT_ATTEMPTS,address,20)
            authorization = self.headers.get('Authorization','')
            if not authorization.startswith('Bearer '): raise UserError('缺少接入码。',401)
            body = self.body()
            return self.send(200,redeem_enrollment(authorization[7:],body.get('installationId')))
        parsed = urllib.parse.urlsplit(path)
        if self.command == 'GET' and parsed.path in ('/api','/api/'):
            return self.not_found()
        asset_types = {'app.js':'text/javascript; charset=utf-8', 'style.css':'text/css; charset=utf-8', 'logo.png':'image/png', 'favicon.ico':'image/x-icon'}
        asset_name = parsed.path.removeprefix('/gly/') if parsed.path.startswith('/gly/') else ''
        if self.command == 'GET' and (parsed.path in ('/gly','/gly/') or asset_name in asset_types):
            assets = {name:(WEB/name).read_bytes() for name in asset_types}
            version = hashlib.sha256(b''.join(assets.values())).hexdigest()[:16]
            if parsed.path in ('/gly','/gly/'):
                page = (WEB/'index.html').read_text(encoding='utf-8-sig').replace('__ASSET_VERSION__',version)
                return self.send(200,page,'text/html; charset=utf-8')
            filename = asset_name
            mime = asset_types[filename]
            cache = 'public, max-age=31536000, immutable' if urllib.parse.parse_qs(parsed.query).get('v') == [version] else 'no-cache'
            etag = '"'+hashlib.sha256(assets[filename]).hexdigest()+'"'
            if self.headers.get('If-None-Match') == etag:
                self.send_response(304)
                self.send_header('ETag',etag)
                self.send_header('Cache-Control',cache)
                self.end_headers()
                return
            return self.send(200,assets[filename],mime,{'ETag':etag},cache)
        if not parsed.path.startswith('/api/'):
            return self.not_found()
        if self.command == 'POST' and path == '/api/login':
            body = self.body()
            username,password = body.get('username'),body.get('password')
            if not isinstance(username,str) or not isinstance(password,str) or len(username)>128 or len(password)>512:
                raise UserError('账号或密码格式不正确。')
            now=time.time()
            address=self.client_address[0] if local else self.headers.get('X-Forwarded-For',self.client_address[0]).split(',')[-1].strip()
            check_rate(LOGIN_ATTEMPTS,address,10)
            admin=load_admin()
            matches=password_matches(password,admin['password'])
            if not matches or username != admin['username']:
                raise UserError('账号或密码不正确。',401)
            upstream=service_session()
            upstream.call('admin/userconfig')
            sid,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
            remember_session(sid,{'upstream':upstream,'csrf':csrf,'expires':now+SESSION_SECONDS,'revision':admin['revision']})
            return self.send(200,{'csrf':csrf},extra={'Set-Cookie':f'sip_session={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+('' if local else '; Secure')})
        sid,session=self.session(csrf=self.command!='GET')
        upstream=session['upstream']
        if self.command=='GET' and path=='/api/admin/profile':
            return self.send(200,{'username':load_admin()['username']})
        if self.command=='POST' and path=='/api/admin/profile':
            result=update_admin(self.body())
            extra={'Set-Cookie':'sip_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'+('' if local else '; Secure')} if result['changed'] else None
            return self.send(200,result,extra=extra)
        if self.command=='GET' and path=='/api/integration.md':
            return self.send(200,(WEB/'integration.md').read_bytes(),'text/plain; charset=utf-8')
        if self.command == 'GET' and path == '/api/state':
            existing={c['id']:c for c in upstream.call('client')}
            with LOCK:
                records=load_state()['clients']
            clients=[]
            for row in records:
                c=existing.get(row['id'],{})
                clients.append({**row,'exists':bool(c),'enabled':c.get('enabled',False),
                    'lastHandshake':c.get('latestHandshakeAt'),
                    'received':c.get('transferRx') or 0,'sent':c.get('transferTx') or 0})
            return self.send(200,{'csrf':session['csrf'],'publicIp':PUBLIC_IP,'sipHost':settings['sipDomain'] or PUBLIC_IP,'settings':settings,'clients':clients,'administrator':{'username':load_admin()['username']}})
        if self.command=='POST' and path in ('/api/settings/check','/api/settings'):
            body=self.body()
            values={key:domain_name(body.get(key,'')) for key in ('sipDomain','panelDomain')}
            checks={key:check_domain(value,allow_proxy=key=='panelDomain') for key,value in values.items()}
            if path.endswith('/check'): return self.send(200,{'checks':checks})
            if not checks['sipDomain']['ok']:
                raise UserError('SIP 域名须使用仅 DNS，并只解析到 '+PUBLIC_IP+'。')
            if not checks['panelDomain']['ok']:
                raise UserError('面板域名须解析到 '+PUBLIC_IP+' 或使用 Cloudflare 代理。')
            with mutation(): save_settings(values)
            return self.send(200,{'ok':True,'settings':values,'message':'已保存。新增面板域名的 HTTPS 证书会自动申请，请稍候访问；IP 入口仍保留。'})
        if self.command == 'POST' and path == '/api/logout':
            forget_session(sid)
            try: upstream.call('session',method='DELETE')
            except UserError: pass
            return self.send(200,{'ok':True},extra={'Set-Cookie':'sip_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})
        if self.command == 'POST' and path == '/api/clients':
            body=self.body()
            with mutation():
                old=load_state()
                name=validate_client(body.get('name'),body.get('start'),body.get('end'),old['clients'])
                if any(c['name'].casefold()==name.casefold() for c in upstream.call('client')):
                    raise UserError('WireGuard 后台已有同名客户端。')
                result=upstream.call('client',{'name':name,'expiresAt':None})
                client_id=int(result['clientId'])
                try:
                    client=upstream.call(f'client/{client_id}')
                    record={'id':client_id,'name':name,'ip':client['ipv4Address'],
                            'start':body['start'],'end':body['end']}
                    new={'clients':old['clients']+[record]}
                    commit_state(old,new)
                except Exception:
                    upstream.call(f'client/{client_id}',method='DELETE')
                    raise
            return self.send(201,{'client':record})
        match=re.fullmatch(r'/api/clients/(\d+)(/config|/enrollment)?',path)
        if match:
            client_id=int(match.group(1))
            with mutation():
                old=load_state()
                record=next((c for c in old['clients'] if c['id']==client_id),None)
                if record is None: raise UserError('客户端不存在。',404)
                if self.command=='GET' and match.group(2)=='/config':
                    return self.send(200,client_configuration(upstream,record),'application/octet-stream',
                                     {'Content-Disposition':f'attachment; filename="sip{client_id}.conf"'})
                if match.group(2)=='/enrollment' and self.command in ('POST','DELETE'):
                    codes=load_enrollments()
                    if self.command=='DELETE':
                        codes.pop(str(client_id),None)
                        save_json(ENROLLMENTS,codes)
                        return self.send(200,{'ok':True})
                    client_configuration(upstream,record)
                    token=secrets.token_urlsafe(32)
                    codes[str(client_id)]={'clientId':client_id,'hash':hashlib.sha256(token.encode()).hexdigest()}
                    save_json(ENROLLMENTS,codes)
                    endpoint=enrollment_endpoint(settings)
                    return self.send(201,{'endpoint':endpoint,'token':token,'expiresAt':None})
                if self.command=='DELETE' and not match.group(2):
                    # Remove exposure first; if upstream removal fails, restore the mapping.
                    new={'clients':[c for c in old['clients'] if c['id']!=client_id]}
                    commit_state(old,new)
                    try: upstream.call(f'client/{client_id}',method='DELETE')
                    except Exception:
                        commit_state(new,old)
                        raise
                    codes=load_enrollments()
                    codes.pop(str(client_id),None)
                    save_json(ENROLLMENTS,codes)
                    return self.send(200,{'ok':True})
        raise UserError('没有这个操作。',404)

    def handle_request(self):
        try:
            self.dispatch()
        except UserError as e:
            self.send(e.status,{'error':e.message})
        except (BrokenPipeError,ConnectionResetError,TimeoutError):
            pass
        except Exception as e:
            print('Request failed:',type(e).__name__,flush=True)
            self.send(500,{'error':'操作未完成，请刷新检查状态。'})

    do_GET=handle_request
    do_POST=handle_request
    do_DELETE=handle_request

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='apply':
        with mutation(): apply_rules(load_state())
    else:
        initialize_admin()
        server=ThreadingHTTPServer(('127.0.0.1',PORT),Handler)
        server.daemon_threads=True
        print(f'Simple panel listening on 127.0.0.1:{PORT}',flush=True)
        server.serve_forever()
