#!/usr/bin/env python3
"""Install only project-owned services; retain state by default."""
import getpass
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

SOURCE = Path(__file__).resolve().parents[1]
ROOT = Path('/opt/sip-tunnel')
MARKER = ROOT / '.rykvo-managed.json'
SOURCE_REPLACED = False
SERVICES = ('sip-caddy', 'sip-simple-panel', 'sip-portmap', 'sip-wireguard')
CHAINS = {'nat': ('SIPT_DNAT', 'SIPT_SNAT'), 'filter': ('SIPT_FORWARD', 'SIPT_INPUT')}
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(args, *, check=True, capture=True):
    return subprocess.run(args, check=check, text=True, capture_output=capture, timeout=900)


def write(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    temporary = path.with_name(path.name + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, 'w') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def read_marker():
    if ROOT.is_symlink() or ROOT.resolve() != Path('/opt/sip-tunnel'):
        raise ValueError('安装目录路径异常。')
    if not MARKER.is_file():
        raise ValueError('未发现本项目安装标记；现有目录保持不变。')
    value = json.loads(MARKER.read_text())
    if value.get('project') != 'Rykvo-Voice-SIP' or value.get('version') != 1:
        raise ValueError('安装标记不匹配。')
    return value


def validate_network(public_ip, bind_ip, interface):
    public = ipaddress.IPv4Address(public_ip)
    bind = ipaddress.IPv4Address(bind_ip)
    if not public.is_global or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
        raise ValueError('需要有效的公网 IPv4 和出口网卡。')
    if bind.is_loopback or bind.is_multicast or bind.is_unspecified:
        raise ValueError('出口网卡地址无效。')
    return {'SIP_PUBLIC_IP': str(public), 'SIP_BIND_IP': str(bind), 'SIP_PUBLIC_IF': interface}


def preflight():
    if os.geteuid() != 0:
        raise ValueError('请使用 sudo 执行。')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04':
        raise ValueError('此版本部署脚本支持 Ubuntu 24.04 LTS。')
    if platform.machine() not in ('x86_64', 'aarch64') or not Path('/run/systemd/system').exists():
        raise ValueError('需要 amd64/arm64、systemd 和支持 WireGuard 的云主机。')
    if ROOT.is_symlink():
        raise ValueError('安装目录是符号链接，已停止。')
    if MARKER.exists():
        read_marker()
        print('环境检查通过，将保留已有数据。')
        return
    if ROOT.exists() and any(ROOT.iterdir()):
        raise ValueError('安装目录已有其他部署。请先备份并迁移；脚本不会覆盖。')
    for port, kind in [(80, socket.SOCK_STREAM), (443, socket.SOCK_STREAM),
                       (2019, socket.SOCK_STREAM), (51821, socket.SOCK_STREAM),
                       (51822, socket.SOCK_STREAM), (51820, socket.SOCK_DGRAM)]:
        with socket.socket(socket.AF_INET, kind) as listener:
            try:
                listener.bind(('0.0.0.0', port))
            except OSError as error:
                raise ValueError(f'端口 {port} 已占用；现有业务保持不变。') from error
    if Path('/sys/class/net/wg0').exists():
        raise ValueError('wg0 已存在，选择没有其他 WireGuard 业务的主机。')
    if shutil.which('docker') and run(['docker', 'container', 'inspect', 'sip-wg-easy'], check=False).returncode == 0:
        raise ValueError('sip-wg-easy 容器已存在，已停止以保护现有数据。')
    for service in SERVICES:
        if Path(f'/etc/systemd/system/{service}.service').exists():
            raise ValueError(f'{service} 已存在，已停止以保护现有服务。')
    print('环境检查通过。')


def detect_network():
    routes = json.loads(run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1']).stdout)
    route = routes[0]
    interface, bind_ip = route['dev'], route['prefsrc']
    public_ip = bind_ip
    if not ipaddress.IPv4Address(bind_ip).is_global:
        try:
            with OPENER.open('https://api.ipify.org', timeout=10) as response:
                public_ip = response.read(64).decode().strip()
        except (urllib.error.URLError, TimeoutError):
            public_ip = ''
    entered = input(f'公网 IPv4 [{public_ip}]: ').strip() or public_ip
    settings = validate_network(entered, bind_ip, interface)
    for route in json.loads(run(['ip', '-j', '-4', 'route', 'show']).stdout):
        destination = route.get('dst', 'default')
        if destination != 'default' and ipaddress.ip_network(destination, strict=False).overlaps(ipaddress.ip_network('10.77.0.0/24')):
            raise ValueError('10.77.0.0/24 与现有路由冲突，已停止。')
    return settings


def panel_module(path=None):
    spec = importlib.util.spec_from_file_location('rykvo_panel', path or ROOT / 'app/server.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compose(*args, bootstrap=False):
    command = ['docker', 'compose', '--project-directory', str(ROOT), '-f', str(ROOT / 'compose.yaml')]
    if bootstrap:
        command += ['-f', str(ROOT / 'bootstrap.yaml')]
    return run(command + list(args), capture=False)


def bounded_remove(path):
    if path.is_symlink() or path.resolve().parent not in (ROOT.resolve(), (ROOT / 'backups').resolve()):
        raise ValueError('清理路径超出项目目录。')
    if path.exists():
        shutil.rmtree(path)


def install_source():
    global SOURCE_REPLACED
    # Run tests before stopping the existing app.
    run([sys.executable, '-B', str(SOURCE / 'tests/test_server.py')], capture=False)
    stage = ROOT / 'app-next'
    bounded_remove(stage)
    shutil.copytree(SOURCE / 'app', stage, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for path in stage.rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)
    run(['systemctl', 'stop', 'sip-simple-panel'], check=False)
    old = ROOT / 'app'
    backup = ROOT / 'backups/app-rollback'
    if old.exists():
        bounded_remove(backup)
        old.rename(backup)
    stage.rename(old)
    SOURCE_REPLACED = True


def input_rules():
    prefix = ['iptables', '-w', '10']
    if run(prefix + ['-S', 'SIPT_INPUT'], check=False).returncode:
        run(prefix + ['-N', 'SIPT_INPUT'])
    run(prefix + ['-F', 'SIPT_INPUT'])
    for protocol, ports in [('tcp', '80,443'), ('udp', '51820')]:
        run(prefix + ['-A', 'SIPT_INPUT', '-p', protocol, '-m', 'multiport', '--dports', ports, '-j', 'ACCEPT'])
    run(prefix + ['-A', 'SIPT_INPUT', '-j', 'RETURN'])
    if run(prefix + ['-C', 'INPUT', '-j', 'SIPT_INPUT'], check=False).returncode:
        run(prefix + ['-I', 'INPUT', '1', '-j', 'SIPT_INPUT'])


def initialize_wireguard(panel):
    credentials = ROOT / 'admin-credentials.json'
    if not credentials.exists():
        write(credentials, {'username': 'rykvo-service', 'password': secrets.token_urlsafe(32)})
    account = json.loads(credentials.read_text())
    write(ROOT / 'bootstrap.env', '\n'.join([
        'INIT_ENABLED=true', 'INIT_USERNAME=' + account['username'], 'INIT_PASSWORD=' + account['password'],
        'INIT_HOST=' + panel.PUBLIC_IP, 'INIT_PORT=51820', 'INIT_IPV4_CIDR=10.77.0.0/24',
        'INIT_IPV6_CIDR=fd77:77:77::/64', 'INIT_ALLOWED_IPS=10.77.0.1/32', '']))
    write(ROOT / 'bootstrap.yaml', 'services:\n  wg-easy:\n    env_file:\n      - bootstrap.env\n')
    compose('up', '-d', bootstrap=True)
    for attempt in range(45):
        try:
            upstream = panel.authenticate_service()
            break
        except (panel.UserError, urllib.error.URLError, OSError):
            if attempt == 44:
                raise RuntimeError('WireGuard 管理服务尚未就绪；检查容器日志后重试。')
            time.sleep(2)
    config = upstream.call('admin/userconfig')
    config.update(defaultDns=[], defaultAllowedIps=['10.77.0.1/32'], defaultPersistentKeepalive=25, defaultMtu=1380)
    upstream.call('admin/userconfig', config)
    upstream.call('admin/hooks', dict(preUp='', postUp='', preDown='', postDown=''))
    upstream.call('session', method='DELETE')
    # Remove only wg-easy's first-start broad defaults, never flush shared chains.
    rules = [('nat', ['POSTROUTING', '-s', '10.77.0.0/24', '-o', 'eth0', '-j', 'MASQUERADE']),
             ('filter', ['INPUT', '-p', 'udp', '-m', 'udp', '--dport', '51820', '-j', 'ACCEPT']),
             ('filter', ['FORWARD', '-i', 'wg0', '-j', 'ACCEPT']),
             ('filter', ['FORWARD', '-o', 'wg0', '-j', 'ACCEPT'])]
    for table, rule in rules:
        prefix = ['docker', 'exec', 'sip-wg-easy', 'iptables', '-w', '10', '-t', table]
        while run(prefix + ['-C'] + rule, check=False).returncode == 0:
            run(prefix + ['-D'] + rule)
    compose('up', '-d', '--force-recreate')
    (ROOT / 'bootstrap.env').unlink()
    (ROOT / 'bootstrap.yaml').unlink()


def administrator(panel):
    if panel.ADMIN.exists():
        print('保留现有管理员账号和密码。')
        return
    print('设置管理员账号（仅保存在此服务器）：')
    while True:
        username = input('账号: ').strip()
        password = getpass.getpass('密码（8–128 位）: ')
        confirm = getpass.getpass('确认密码: ')
        if re.fullmatch(r'[\w.@-]{2,48}', username) and 8 <= len(password) <= 128 and password == confirm:
            break
        print('请检查账号格式、密码长度和两次输入。')
    write(panel.ADMIN, {'username': username, 'password': panel.hash_password(password), 'revision': 0})


def write_services():
    common = ('Restart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nProtectSystem=strict\n'
              'ProtectHome=true\nPrivateTmp=true\nUMask=0077\nReadWritePaths=/opt/sip-tunnel\n')
    definitions = {
        'sip-wireguard': ('After=network-online.target docker.service\nRequires=docker.service\n',
                         'Type=oneshot\nRemainAfterExit=yes\nWorkingDirectory=/opt/sip-tunnel\n'
                         'ExecStart=/usr/bin/docker compose up -d\nExecStop=/usr/bin/docker compose down\n'),
        'sip-portmap': ('After=sip-wireguard.service\nRequires=sip-wireguard.service\n',
                        'Type=oneshot\nRemainAfterExit=yes\nEnvironmentFile=/opt/sip-tunnel/runtime.env\n'
                        'Environment=PYTHONDONTWRITEBYTECODE=1\n'
                        'ExecStart=/usr/bin/python3 -B /opt/sip-tunnel/manager.py rules\n'),
        'sip-simple-panel': ('After=sip-portmap.service\nRequires=sip-portmap.service\n',
                             'EnvironmentFile=/opt/sip-tunnel/runtime.env\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n'
                             'ExecStart=/usr/bin/python3 -B /opt/sip-tunnel/app/server.py\n'
                             'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n' + common),
        'sip-caddy': ('After=sip-simple-panel.service\nRequires=sip-simple-panel.service\n',
                     'Environment=XDG_DATA_HOME=/opt/sip-tunnel/caddy-data\n'
                     'Environment=XDG_CONFIG_HOME=/opt/sip-tunnel/caddy-config\n'
                     'ExecStart=/usr/bin/caddy run --config /opt/sip-tunnel/Caddyfile\n'
                     'ExecReload=/usr/bin/caddy reload --config /opt/sip-tunnel/Caddyfile\n'
                     'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n' + common),
    }
    for name, (dependencies, service) in definitions.items():
        write(Path(f'/etc/systemd/system/{name}.service'),
              f'[Unit]\nDescription=Rykvo Voice SIP - {name}\nWants=network-online.target\n{dependencies}\n'
              f'[Service]\n{service}\n[Install]\nWantedBy=multi-user.target\n', 0o644)


def install():
    if MARKER.exists():
        state = read_marker()
    else:
        network = detect_network()
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        state = {'project': 'Rykvo-Voice-SIP', 'version': 1, 'network': network, 'initialized': False,
                 'sysctl': {key: run(['sysctl', '-n', key]).stdout.strip()
                            for key in ('net.ipv4.ip_forward', 'net.ipv4.conf.all.src_valid_mark')}}
        write(MARKER, state)
    ROOT.chmod(0o700)
    for directory in ('data', 'backups', 'caddy-data', 'caddy-config'):
        (ROOT / directory).mkdir(mode=0o700, exist_ok=True)
    os.environ.update(state['network'], SIP_ROOT=str(ROOT))
    write(ROOT / 'runtime.env', 'SIP_ROOT=/opt/sip-tunnel\n' + ''.join(f'{key}={value}\n' for key, value in state['network'].items()))
    write(ROOT / 'compose.yaml', (SOURCE / 'deploy/compose.yaml').read_text())
    compose('pull')
    install_source()
    shutil.copyfile(__file__, ROOT / 'manager.py')
    (ROOT / 'manager.py').chmod(0o600)
    panel = panel_module()
    for name, value in [('clients.json', {'clients': []}), ('settings.json', {'sipDomain': '', 'panelDomain': ''}),
                        ('enrollments.json', {}), ('panel-sessions.json', {})]:
        if not (ROOT / name).exists():
            write(ROOT / name, value)
    write(Path('/etc/sysctl.d/90-rykvo-sip.conf'), 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.src_valid_mark=1\n', 0o644)
    write(Path('/etc/modules-load.d/rykvo-sip.conf'), 'wireguard\n', 0o644)
    run(['sysctl', '-p', '/etc/sysctl.d/90-rykvo-sip.conf'])
    input_rules()
    if not state['initialized']:
        initialize_wireguard(panel)
        state['initialized'] = True
        write(MARKER, state)
    else:
        compose('up', '-d')
    administrator(panel)
    settings = panel.load_settings()
    write(ROOT / 'Caddyfile', panel.caddy_config(settings['panelDomain'], settings['sipDomain']))
    run(['caddy', 'validate', '--config', str(ROOT / 'Caddyfile')])
    write_services()
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', *SERVICES])
    run(['systemctl', 'restart', 'sip-wireguard', 'sip-portmap', 'sip-simple-panel', 'sip-caddy'])
    for attempt in range(30):
        try:
            with OPENER.open('http://127.0.0.1:51822/', timeout=3) as response:
                assert response.status == 200
            panel.authenticate_service().call('session', method='DELETE')
            break
        except (OSError, urllib.error.URLError, panel.UserError):
            if attempt == 29:
                raise RuntimeError('服务启动检查未通过，请检查 systemd 日志。')
            time.sleep(2)
    run(['systemctl', 'is-active', *SERVICES], capture=False)
    print(f'部署完成：https://{settings["panelDomain"] or panel.PUBLIC_IP}/')
    print('HTTPS 证书自动申请；请确保云防火墙已开放 TCP 80/443、UDP 51820 和客户端端口段。')


def remove_rules():
    for table, chains in CHAINS.items():
        prefix = ['iptables', '-w', '10', '-t', table]
        for line in run(prefix + ['-S']).stdout.splitlines():
            rule = shlex.split(line)
            if rule[:1] == ['-A'] and '-j' in rule and rule[rule.index('-j') + 1] in chains:
                run(prefix + ['-D'] + rule[1:])
        for chain in chains:
            if run(prefix + ['-S', chain], check=False).returncode == 0:
                run(prefix + ['-F', chain])
                run(prefix + ['-X', chain])


def uninstall(purge=False):
    state = read_marker()
    if purge and input('将永久删除此项目的账号、密钥、证书和客户端数据。输入 DELETE 确认: ') != 'DELETE':
        print('已取消。')
        return
    if not purge and input('停止并卸载服务，保留数据？[y/N]: ').lower() != 'y':
        print('已取消。')
        return
    run(['systemctl', 'disable', '--now', *SERVICES], check=False)
    if (ROOT / 'compose.yaml').exists():
        compose('down')
    remove_rules()
    for service in SERVICES:
        Path(f'/etc/systemd/system/{service}.service').unlink(missing_ok=True)
    for name in ['/etc/sysctl.d/90-rykvo-sip.conf', '/etc/modules-load.d/rykvo-sip.conf']:
        Path(name).unlink(missing_ok=True)
    other_containers = run(['docker', 'ps', '-q']).stdout.strip()
    other_wireguard = run(['wg', 'show', 'interfaces']).stdout.strip()
    if not other_containers and not other_wireguard:
        for key, value in state['sysctl'].items():
            if run(['sysctl', '-n', key]).stdout.strip() == '1':
                run(['sysctl', '-w', key + '=' + value])
    run(['systemctl', 'daemon-reload'])
    if purge:
        if ROOT.resolve() != Path('/opt/sip-tunnel') or ROOT.is_symlink():
            raise ValueError('删除路径异常。')
        shutil.rmtree(ROOT)
        print('项目服务和数据已删除。Docker、Caddy 等共享依赖保留。')
    else:
        print('服务已卸载，配置、数据和证书保留在 /opt/sip-tunnel。再次安装会复用。')


def main():
    if os.geteuid() != 0:
        raise ValueError('需要 root 权限。')
    command = sys.argv[1]
    if command == 'preflight':
        preflight()
    elif command == 'install':
        was_active = run(['systemctl','is-active','--quiet','sip-simple-panel'],check=False).returncode == 0
        try:
            install()
        except (Exception, KeyboardInterrupt):
            backup = ROOT/'backups/app-rollback'
            if SOURCE_REPLACED and backup.exists():
                run(['systemctl','stop','sip-simple-panel'],check=False)
                bounded_remove(ROOT/'app')
                backup.rename(ROOT/'app')
                if was_active:
                    run(['systemctl','start','sip-simple-panel'],check=False)
            raise
    elif command == 'rules':
        state = read_marker()
        os.environ.update(state['network'], SIP_ROOT=str(ROOT))
        panel = panel_module()
        with panel.mutation():
            panel.apply_rules(panel.load_state())
            input_rules()
    elif command == 'uninstall':
        uninstall('--purge' in sys.argv[2:])
    else:
        raise ValueError('未知操作。')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(f'操作未完成：{error or "已取消"}。已有数据保持保留，请排查后重试。', file=sys.stderr)
        sys.exit(1)
