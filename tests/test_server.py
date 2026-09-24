import importlib.util
from pathlib import Path
import unittest
import tempfile
import json
import hashlib
import time
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('simplepanel',Path(__file__).resolve().parents[1]/'app/server.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
 def test_valid_names_and_range(self):
  self.assertEqual(m.validate_client(' 家里01 ',20000,29999,[]),'家里01')
 def test_overlap_and_reserved(self):
  existing=[{'name':'first','ip':'10.77.0.2','start':20000,'end':29999}]
  for start,end in [(19999,20000),(29999,30000),(22000,23000),(1024,65535),(51820,51820),(1,100),(4000,3999),(True,4000)]:
   with self.assertRaises(m.UserError):m.validate_client('test',start,end,existing)
 def test_invalid_names(self):
  for name in ['',None,'<script>','a\nb','a; reboot','x'*49]:
   with self.assertRaises(m.UserError):m.validate_client(name,20000,21000,[])
 def test_export_split_route(self):
  key='A'*43+'='
  raw=f'[Interface]\nPrivateKey = {key}\nAddress = 10.77.0.2/32\n[Peer]\nPublicKey = {key}\nPresharedKey = {key}\n'
  out=m.export_config(raw,{'name':'local','ip':'10.77.0.2','start':20000,'end':29999})
  self.assertIn('Table = off',out)
  self.assertIn('priority 14002 from 10.77.0.2/32 lookup 42002',out)
  self.assertIn('AllowedIPs = 0.0.0.0/0',out)
  self.assertIn('rp_filter=2',out)
  self.assertNotIn('DNS =',out)
  self.assertNotIn('route add default dev %i\n',out)

class EnrollmentTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory()
  self.root=Path(self.temp.name)
  self.patches=[patch.object(m,'ROOT',self.root),patch.object(m,'STATE',self.root/'clients.json'),patch.object(m,'SETTINGS',self.root/'settings.json'),patch.object(m,'ENROLLMENTS',self.root/'enrollments.json')]
  for item in self.patches:item.start()
  (self.root/'clients.json').write_text(json.dumps({'clients':[{'id':9,'name':'test','ip':'10.77.0.9','start':32000,'end':32999}]}))
  (self.root/'admin-credentials.json').write_text(json.dumps({'username':'test','password':'test'}))
  self.token='a'*43
  self.identity='local-installation-001'
  self.issue()
  key='A'*43+'='
  config=f'[Interface]\nPrivateKey = {key}\n[Peer]\nPublicKey = {key}\nPresharedKey = {key}\n'
  class FakeUpstream:
   def call(self,path,*args,**kwargs):
    if path=='auth/password':return {'status':'success'}
    if path=='client/9':return {'ipv4Address':'10.77.0.9','enabled':True}
    if path=='client/9/configuration':return config
    if path in ('session','admin/userconfig'):return {}
    raise AssertionError(path)
  self.upstream=patch.object(m,'Upstream',FakeUpstream);self.upstream.start()
 def tearDown(self):
  self.upstream.stop()
  for item in reversed(self.patches):item.stop()
  self.temp.cleanup()
 def issue(self):
  m.save_json(m.ENROLLMENTS,{'9':{'clientId':9,'hash':hashlib.sha256(self.token.encode()).hexdigest()}})
 def test_claim_and_retry(self):
  result=m.redeem_enrollment(self.token,self.identity)
  self.assertEqual(result['version'],1)
  self.assertEqual(result['wireguard']['interface'],'sip9')
  self.assertIn('Table = off',result['wireguard']['config'])
  self.assertEqual(result,m.redeem_enrollment(self.token,self.identity))
  stored=m.ENROLLMENTS.read_text()
  self.assertNotIn(self.token,stored)
  self.assertNotIn('PrivateKey',stored)
 def test_other_installation_rejected(self):
  m.redeem_enrollment(self.token,self.identity)
  with self.assertRaises(m.UserError) as error:m.redeem_enrollment(self.token,'local-installation-002')
  self.assertEqual(error.exception.status,409)
 def test_no_expiry_before_or_after_binding(self):
  future=time.time()+10*365*86400
  with patch.object(m.time,'time',return_value=future):
   first=m.redeem_enrollment(self.token,self.identity)
  with patch.object(m.time,'time',return_value=future*2):
   self.assertEqual(first,m.redeem_enrollment(self.token,self.identity))
 def test_legacy_timestamps_do_not_expire_current_code(self):
  codes=m.load_enrollments()
  codes['9'].update(expiresAt=1,claimedAt=1,installationId=self.identity)
  m.save_json(m.ENROLLMENTS,codes)
  self.assertEqual(m.redeem_enrollment(self.token,self.identity)['client']['id'],9)
 def test_invalid_token_and_identity(self):
  for token,identity in [('bad',self.identity),('b'*43,self.identity),(self.token,'short')]:
   with self.assertRaises(m.UserError):m.redeem_enrollment(token,identity)
 def test_deleted_client(self):
  m.save_state({'clients':[]})
  with self.assertRaises(m.UserError) as error:m.redeem_enrollment(self.token,self.identity)
  self.assertEqual(error.exception.status,410)

class DomainTests(unittest.TestCase):
 def setUp(self):
  public_ip=patch.object(m,'PUBLIC_IP','203.0.113.10')
  public_ip.start();self.addCleanup(public_ip.stop)
 def resolve(self, addresses, allow_proxy=False):
  rows=[(None,None,None,None,(address,0)) for address in addresses]
  with patch.object(m.socket,'getaddrinfo',return_value=rows):
   return m.check_domain('panel.example.com',allow_proxy=allow_proxy)
 def test_direct_and_empty(self):
  self.assertTrue(self.resolve([m.PUBLIC_IP])['ok'])
  self.assertEqual(m.check_domain('')['mode'],'ip')
 def test_cloudflare_panel_only(self):
  addresses=['104.21.80.105','172.67.178.112','2606:4700:3032::ac43:b270']
  self.assertEqual(self.resolve(addresses,True)['mode'],'cloudflare')
  self.assertFalse(self.resolve(addresses)['ok'])
 def test_reject_other_and_mixed_addresses(self):
  for addresses in [[],['127.0.0.1'],['203.0.113.1'],[m.PUBLIC_IP,'104.21.80.105'],['104.21.80.105','::1']]:
   self.assertFalse(self.resolve(addresses,True)['ok'])
 def test_dns_failure(self):
  with patch.object(m.socket,'getaddrinfo',side_effect=m.socket.gaierror):
   self.assertFalse(m.check_domain('missing.example.com',True)['ok'])

class NetworkTests(unittest.TestCase):
 def test_cloud_nat_and_detected_interface_are_used(self):
  from unittest.mock import Mock
  state={'clients':[{'name':'fixture','ip':'10.77.0.2','start':20000,'end':20999}]}
  with patch.object(m,'PUBLIC_IF','ens3'),patch.object(m,'BIND_IP','10.0.0.5'),patch.object(m,'PUBLIC_IP','203.0.113.10'),patch.object(m.subprocess,'run',return_value=Mock(returncode=1)),patch.object(m,'run') as run:
   m.apply_rules(state)
  payload=next(call.kwargs['input'] for call in run.call_args_list if 'input' in call.kwargs)
  self.assertIn('-i ens3 -o wg0',payload)
  self.assertIn('--to-source 10.0.0.5',payload)
  self.assertNotIn('eth0',payload)
  self.assertNotIn('--to-source 203.0.113.10',payload)
  commands=[call.args[0] for call in run.call_args_list]
  self.assertTrue(any('-d' in args and '10.0.0.5' in args and 'PREROUTING' in args for args in commands))

class NotFoundPageTests(unittest.TestCase):
 def test_minimal_page_has_pinned_styles_and_no_external_assets(self):
  import base64,re
  css=re.search(r'<style>(.*?)</style>',m.NOT_FOUND_PAGE,re.S)[1]
  digest=base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
  self.assertIn("'sha256-"+digest+"'",m.NOT_FOUND_CSP)
  self.assertNotIn('unsafe-inline',m.NOT_FOUND_CSP)
  self.assertNotIn('<script',m.NOT_FOUND_PAGE)
  self.assertNotIn('href="/',m.NOT_FOUND_PAGE)

 def test_api_index_is_404_without_login(self):
  from unittest.mock import Mock
  for path in ['/api','/api/','/api/?test=1']:
   handler=object.__new__(m.Handler)
   handler.command='GET';handler.path=path
   handler.headers={'Host':m.PUBLIC_IP,'X-Forwarded-Proto':'https'}
   handler.send=Mock()
   with patch.object(m,'load_settings',return_value={'sipDomain':'','panelDomain':''}):
    handler.dispatch()
   status,page,content_type=handler.send.call_args.args
   self.assertEqual(status,404)
   self.assertIn('<h1>404</h1>',page)
   self.assertNotIn('__ASSET_VERSION__',page)
   self.assertEqual(content_type,'text/html; charset=utf-8')

class EndpointTests(unittest.TestCase):
 def test_sip_domain_and_ip_fallback(self):
  self.assertEqual(m.enrollment_endpoint({'sipDomain':'sip.example.com','panelDomain':'panel.example.com'}),'https://sip.example.com/api/connect')
  self.assertEqual(m.enrollment_endpoint({'sipDomain':'','panelDomain':'panel.example.com'}),'https://'+m.PUBLIC_IP+'/api/connect')
 def test_separate_sip_host_only_exposes_enrollment(self):
  config=m.caddy_config('panel.example.com','sip.example.com')
  sip=config.split('sip.example.com {',1)[1]
  self.assertIn('handle /api/connect {',sip)
  self.assertIn('respond 404',sip)
  self.assertIn('panel.example.com {',config)
 def test_shared_domain_is_not_duplicated(self):
  self.assertEqual(m.caddy_config('sip.example.com','sip.example.com').count('sip.example.com {'),1)
 def test_sip_only_and_no_domain(self):
  self.assertIn('sip.example.com {',m.caddy_config('','sip.example.com'))
  self.assertNotIn('handle /api/connect',m.caddy_config('',''))
 def test_sip_browser_requests_only_show_404(self):
  from unittest.mock import Mock
  for path in ['/api/state','/api/connect','/api/connect?test=1']:
   handler=object.__new__(m.Handler);handler.command='GET';handler.path=path
   handler.headers={'Host':'sip.example.com','X-Forwarded-Proto':'https'}
   handler.send=Mock()
   with patch.object(m,'load_settings',return_value={'sipDomain':'sip.example.com','panelDomain':'panel.example.com'}):
    handler.dispatch()
   handler.send.assert_called_once_with(404,m.NOT_FOUND_PAGE,'text/html; charset=utf-8',csp=m.NOT_FOUND_CSP)

class AdministratorTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory()
  self.root=Path(self.temp.name)
  self.patches=[patch.object(m,'ROOT',self.root),patch.object(m,'ADMIN',self.root/'panel-admin.json'),patch.object(m,'SESSION_STORE',self.root/'panel-sessions.json'),patch.object(m,'SESSIONS',{}),patch.object(m,'PROFILE_ATTEMPTS',{})]
  for item in self.patches:item.start()
  self.original='initial-admin-password-123'
  self.service=json.dumps({'username':'admin','password':self.original})
  (self.root/'admin-credentials.json').write_text(self.service)
  m.initialize_admin()
 def tearDown(self):
  for item in reversed(self.patches):item.stop()
  self.temp.cleanup()
 def change(self,**values):
  return m.update_admin({'username':'','currentPassword':self.original,'newPassword':'','confirmPassword':'',**values})
 def test_initial_credentials_preserved_and_hashed(self):
  data=m.load_admin()
  self.assertEqual(data['username'],'admin')
  self.assertTrue(m.password_matches(self.original,data['password']))
  self.assertNotIn(self.original,m.ADMIN.read_text())
  self.assertEqual(m.ADMIN.stat().st_mode&0o777,0o600)
  m.initialize_admin()
  self.assertEqual(data,m.load_admin())
 def test_username_only_and_session_invalidation(self):
  old=m.load_admin();m.SESSIONS['old']={'revision':0}
  result=self.change(username='new-admin')
  self.assertTrue(result['changed'])
  self.assertEqual(m.load_admin()['username'],'new-admin')
  self.assertEqual(m.load_admin()['password'],old['password'])
  self.assertEqual(m.load_admin()['revision'],1)
  self.assertFalse(m.SESSIONS)
  self.assertEqual((self.root/'admin-credentials.json').read_text(),self.service)
 def test_password_only(self):
  password='Abcd1234'
  self.change(newPassword=password,confirmPassword=password)
  data=m.load_admin()
  self.assertEqual(data['username'],'admin')
  self.assertTrue(m.password_matches(password,data['password']))
  self.assertFalse(m.password_matches(self.original,data['password']))
  self.assertEqual((self.root/'admin-credentials.json').read_text(),self.service)
 def test_no_change(self):
  old=m.load_admin()
  self.assertFalse(self.change()['changed'])
  self.assertEqual(old,m.load_admin())
 def test_invalid_changes_preserve_account(self):
  old=m.load_admin()
  for values in [dict(currentPassword='wrong-password'),dict(newPassword='a'*7,confirmPassword='a'*7),dict(newPassword='a'*129,confirmPassword='a'*129),dict(newPassword='a'*15,confirmPassword='b'*15),dict(username='bad name'),dict(currentPassword='')]:
   with self.assertRaises(m.UserError):self.change(**values)
   self.assertEqual(old,m.load_admin())

class SessionTests(unittest.TestCase):
 setUp=AdministratorTests.setUp
 tearDown=AdministratorTests.tearDown
 def remember(self):
  self.sid='c'*43
  m.remember_session(self.sid,{'csrf':'csrf-test','expires':time.time()+3600,'revision':0,'upstream':object()})
 def test_survives_memory_reset(self):
  self.remember()
  self.assertNotIn(self.sid,m.SESSION_STORE.read_text())
  self.assertEqual(m.SESSION_STORE.stat().st_mode&0o777,0o600)
  m.SESSIONS.clear()
  restored=m.restore_session(self.sid,'csrf-test')
  self.assertEqual(restored['csrf'],'csrf-test')
  self.assertIsInstance(restored['upstream'],m.ServiceSession)
 def test_logout_is_persistent(self):
  self.remember();m.forget_session(self.sid);m.SESSIONS.clear()
  with self.assertRaises(m.UserError) as error:m.restore_session(self.sid)
  self.assertEqual(error.exception.status,401)
 def test_expiry_and_csrf(self):
  self.remember()
  with self.assertRaises(m.UserError) as error:m.restore_session(self.sid,'wrong')
  self.assertEqual(error.exception.status,403)
  future=time.time()+86400
  with patch.object(m.time,'time',return_value=future):
   with self.assertRaises(m.UserError) as error:m.restore_session(self.sid)
  self.assertEqual(error.exception.status,401)
 def test_credential_change_revokes_persisted_sessions(self):
  self.remember()
  m.update_admin({'username':'new-admin','currentPassword':self.original})
  self.assertEqual(m.load_sessions(),{})
  with self.assertRaises(m.UserError):m.restore_session(self.sid)
 def test_internal_session_renews_without_panel_logout(self):
  from unittest.mock import Mock
  expired=Mock();expired.call.side_effect=m.UserError('expired',401)
  renewed=Mock();renewed.call.return_value={'ok':True}
  with patch.object(m,'authenticate_service',side_effect=[expired,renewed]) as login:
   self.assertEqual(m.ServiceSession().call('client'),{'ok':True})
   self.assertEqual(login.call_count,2)
 def test_internal_auth_failure_does_not_return_panel_401(self):
  from unittest.mock import Mock
  expired=Mock();expired.call.side_effect=m.UserError('expired',401)
  with patch.object(m,'authenticate_service',return_value=expired):
   with self.assertRaises(m.UserError) as error:m.ServiceSession().call('client')
  self.assertEqual(error.exception.status,503)

if __name__=='__main__':unittest.main()
