#!/usr/bin/env python3
"""Offline kernel routing test; run ONLY via root unshare --mount --net --fork.

It mounts a private /run and uses two private network namespaces. No host
interface, host route, real website, browser profile, or account is used.
"""
import argparse
import contextlib
import http.server
import ipaddress
import json
import os
import pathlib
import queue
import select
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

SCRIPT = str(pathlib.Path(__file__).resolve())


def run(*args):
    return subprocess.check_output(list(args), text=True, stderr=subprocess.STDOUT)


def forward(left, right):
    readers = [left, right]
    while readers:
        ready, _, _ = select.select(readers, [], [], 10)
        if not ready:
            continue
        for source in ready:
            target = right if source is left else left
            data = source.recv(65536)
            if not data:
                readers.remove(source)
                with contextlib.suppress(OSError):
                    target.shutdown(socket.SHUT_WR)
            else:
                target.sendall(data)


def read_exact(stream, count):
    data = b''
    while len(data) < count:
        part = stream.recv(count - len(data))
        if not part:
            raise EOFError('unexpected EOF')
        data += part
    return data


class ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Web(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        data = b'ip=203.0.113.10\n' if self.path == '/cdn-cgi/trace' else b'DIRECT'
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        query = self.rfile.read(int(self.headers['Content-Length']))
        end, labels = 12, []
        while query[end]:
            size = query[end]
            labels.append(query[end + 1:end + 1 + size].decode('ascii'))
            end += size + 1
        end += 5
        address = '127.0.0.1' if '.'.join(labels).startswith('private.') else '93.184.215.14'
        answer = (query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
                  + query[12:end] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4)
                  + ipaddress.IPv4Address(address).packed)
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)


class FakeVPN(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request.makefile('rb')
        stream.readline()  # Destination supplied by the private SOCKS fixture.
        while stream.readline() not in (b'\r\n', b'\n', b''):
            pass
        self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nVPN')


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        version, count = read_exact(conn, 2)
        read_exact(conn, count)
        if version != 5:
            return
        conn.sendall(b'\x05\x00')
        version, command, _, kind = read_exact(conn, 4)
        if command != 1:
            return
        if kind == 1:
            host = socket.inet_ntoa(read_exact(conn, 4))
        elif kind == 3:
            host = read_exact(conn, read_exact(conn, 1)[0]).decode()
        else:
            return
        port = struct.unpack('!H', read_exact(conn, 2))[0]
        with socket.create_connection(('9.9.9.9', 18777), timeout=5) as remote:
            remote.sendall(f'{host}:{port}\n'.encode())
            conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            forward(conn, remote)


def peer(cert, key):
    sys.stdin.readline()  # The parent configures this private namespace first.
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    for address in [('93.184.215.14', 80), ('93.184.215.14', 443), ('1.1.1.1', 443), ('8.8.8.8', 443)]:
        server = http.server.ThreadingHTTPServer(address, Web)
        if address[1] == 443:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    vpn = ThreadedTCP(('9.9.9.9', 18777), FakeVPN)
    threading.Thread(target=vpn.serve_forever, daemon=True).start()
    print('PEER_READY', flush=True)
    signal.pause()


def client(uid, request, cert):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(10)
        conn.connect(f'/run/n-orm-steroid-{uid}/direct.sock')
        conn.sendall(json.dumps(request).encode() + b'\n')
        line = b''
        while not line.endswith(b'\n'):
            line += read_exact(conn, 1)
        response = json.loads(line)
        if not response.get('ok', False):
            print('REJECTED', flush=True)
            return
        if request['operation'] == 'rules':
            print('RULES_UPDATED', flush=True)
            return
        active = conn
        if request['operation'] == 'diagnostic':
            active = ssl.create_default_context(cafile=cert).wrap_socket(conn, server_hostname='www.cloudflare.com')
        active.sendall(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n' if request['operation'] == 'diagnostic' else b'GET / HTTP/1.1\r\nHost: site.example.ir\r\nConnection: close\r\n\r\n')
        data = b''
        while True:
            part = active.recv(65536)
            if not part:
                break
            data += part
        print(data.split(b'\r\n\r\n', 1)[1].decode().strip(), flush=True)


def monitored(command, env):
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    lines, received = [], queue.Queue()
    def read():
        for line in process.stdout:
            lines.append(line.strip())
            received.put(line.strip())
    thread = threading.Thread(target=read, daemon=True)
    thread.start()
    return process, lines, received, thread


def wait_ready(process, received):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if received.get(timeout=.2) == 'READY':
                return
        except queue.Empty:
            if process.poll() is not None:
                raise RuntimeError('helper exited: ' + process.stderr.read())
    raise RuntimeError('helper did not become ready')


def stop_helper(process, lines, thread, how='eof'):
    if how == 'signal':
        process.send_signal(signal.SIGTERM)
    else:
        process.stdin.close()
    process.wait(timeout=15)
    thread.join(timeout=2)
    diagnostic = process.stderr.read()
    if process.returncode != 0 or 'CLEAN' not in lines:
        raise RuntimeError(f'helper cleanup failed: {lines}, {diagnostic}')


def assert_clean(uid):
    rules = json.loads(run('ip', '-4', '-json', 'rule', 'show'))
    assert not any(row.get('priority') in (18575, 18576, 18577) for row in rules), rules
    result = subprocess.run(['ip', 'link', 'show', 'fxvpn' + str(uid)], capture_output=True)
    assert result.returncode != 0, 'TUN interface remained after cleanup'
    assert not pathlib.Path(f'/run/n-orm-steroid-{uid}/direct.sock').exists()


def vpn_request():
    with socket.create_connection(('93.184.215.14', 80), timeout=5) as conn:
        conn.sendall(b'GET / HTTP/1.1\r\nHost: site.example.ir\r\nConnection: close\r\n\r\n')
        data = b''
        while True:
            part = conn.recv(65536)
            if not part:
                break
            data += part
        assert data.endswith(b'VPN'), data


def inside(helper, uid):
    assert os.geteuid() == 0, 'requires root inside private namespaces'
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'refusing the host network namespace'
    assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'refusing the host mount namespace'
    assert [row['ifname'] for row in json.loads(run('ip', '-json', 'link', 'show'))] == ['lo'], 'namespace must start empty'
    run('mount', '--make-rprivate', '/')
    run('mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', '/run')
    run('ip', 'link', 'set', 'lo', 'up')
    processes = []
    with tempfile.TemporaryDirectory(prefix='/run/n-orm-netns-') as temporary:
        temp = pathlib.Path(temporary)
        os.chmod(temp, 0o755)
        cert, key = str(temp / 'test-ca.pem'), str(temp / 'test-key.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=N-orm isolated test', '-addext', 'subjectAltName=IP:1.1.1.1,IP:8.8.8.8,DNS:www.cloudflare.com', '-keyout', key, '-out', cert], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        target = pathlib.Path(os.path.realpath('/etc/resolv.conf'))
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.touch()
        resolver = temp / 'resolv.conf'
        resolver.write_text('nameserver 1.1.1.1\n')
        run('mount', '--bind', str(resolver), '/etc/resolv.conf')
        remote = subprocess.Popen(['unshare', '--net', sys.executable, SCRIPT, 'peer', cert, key], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(remote)
        try:
            # Wait for unshare to enter its own netns before moving the veth.
            for _ in range(100):
                if os.readlink(f'/proc/{remote.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                    break
                time.sleep(.01)
            run('ip', 'link', 'add', 'testeth', 'type', 'veth', 'peer', 'name', 'testpeer')
            run('ip', 'link', 'set', 'testpeer', 'netns', str(remote.pid))
            run('ip', 'addr', 'add', '10.42.0.2/24', 'dev', 'testeth')
            run('ip', 'link', 'set', 'testeth', 'up')
            run('ip', 'route', 'add', 'default', 'via', '10.42.0.1')
            def remote_ip(*args):
                return run('nsenter', '-t', str(remote.pid), '-n', 'ip', *args)
            remote_ip('link', 'set', 'lo', 'up')
            remote_ip('addr', 'add', '10.42.0.1/24', 'dev', 'testpeer')
            remote_ip('link', 'set', 'testpeer', 'up')
            for address in ['1.1.1.1', '8.8.8.8', '9.9.9.9', '93.184.215.14']:
                remote_ip('addr', 'add', address + '/32', 'dev', 'lo')
            remote.stdin.write('start\n'); remote.stdin.flush()
            assert remote.stdout.readline().strip() == 'PEER_READY', remote.stderr.read()
            socks = ThreadedTCP(('127.0.0.1', 0), Socks)
            threading.Thread(target=socks.serve_forever, daemon=True).start()
            env = dict(os.environ, PKEXEC_UID=str(uid), SSL_CERT_FILE=cert, SSL_CERT_DIR=str(temp / 'no-system-certs'))
            rules = [{'kind': 'suffix', 'domain': 'ir', 'action': 'direct'}]
            def request(message):
                return run(sys.executable, SCRIPT, 'client', str(uid), json.dumps(message), cert).strip()
            # An occupied priority is never overwritten or deleted by startup.
            run('ip', '-4', 'rule', 'add', 'priority', '18575', 'fwmark', '0x123', 'lookup', 'main')
            blocked, lines, received, thread = monitored([helper, str(socks.server_address[1]), '9.9.9.9'], env)
            processes.append(blocked)
            blocked.stdin.write(json.dumps(rules) + '\n'); blocked.stdin.flush()
            blocked.wait(timeout=10); blocked.stdin.close(); thread.join(timeout=2)
            assert blocked.returncode != 0 and 'READY' not in lines
            assert 'priority 18575 is already in use' in blocked.stderr.read()
            occupied = [row for row in json.loads(run('ip', '-4', '-json', 'rule', 'show')) if row.get('priority') == 18575]
            assert len(occupied) == 1 and str(occupied[0].get('fwmark')) in ('0x123', '291'), occupied
            run('ip', '-4', 'rule', 'del', 'priority', '18575', 'fwmark', '0x123', 'lookup', 'main')
            assert_clean(uid)
            print('PASS: occupied direct-routing priority refused without altering the existing rule', flush=True)
            for stop_method in ['eof', 'signal']:
                process, lines, received, thread = monitored([helper, str(socks.server_address[1]), '9.9.9.9'], env)
                processes.append(process)
                process.stdin.write(json.dumps(rules) + '\n'); process.stdin.flush()
                wait_ready(process, received)
                vpn_request()
                assert request({'operation': 'dial', 'address': 'site.example.ir:80'}) == 'DIRECT'
                assert request({'operation': 'diagnostic', 'address': 'www.cloudflare.com:443'}) == 'ip=203.0.113.10'
                assert request({'operation': 'dial', 'address': 'private.example.ir:80'}) == 'REJECTED'
                assert request({'operation': 'dial', 'address': 'unmatched.com:80'}) == 'REJECTED'
                assert request({'operation': 'rules', 'rules': []}) == 'RULES_UPDATED'
                assert request({'operation': 'dial', 'address': 'site.example.ir:80'}) == 'REJECTED'
                stop_helper(process, lines, thread, stop_method)
                assert_clean(uid)
                print(f'PASS: real TUN capture, marked direct bypass, verified TLS/DoH, public-address checks, live revocation and {stop_method} cleanup', flush=True)
            normal, lines, received, thread = monitored(['/usr/lib/n-orm-proxy/n-orm-helper', str(socks.server_address[1]), '9.9.9.9'], env)
            processes.append(normal)
            wait_ready(normal, received)
            assert not any(row.get('priority') == 18575 for row in json.loads(run('ip', '-4', '-json', 'rule', 'show')))
            vpn_request()
            stop_helper(normal, lines, thread)
            assert_clean(uid)
            print('PASS: original TUN helper still captures traffic independently; no experimental routing rule', flush=True)
            socks.shutdown(); socks.server_close()
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'peer':
        peer(*sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == 'client':
        client(int(sys.argv[2]), json.loads(sys.argv[3]), sys.argv[4])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--helper', required=True)
        parser.add_argument('--uid', required=True, type=int)
        arguments = parser.parse_args()
        inside(str(pathlib.Path(arguments.helper).resolve()), arguments.uid)
