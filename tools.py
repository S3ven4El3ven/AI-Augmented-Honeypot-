import requests
import nmap
import paramiko
import json
import socket
from langchain_core.tools import tool

TARGET = '192.168.100.10'  # Honeypot IP — never change this

# ─────────────────────────────────────────────────────
# TOOL 1: nmap port scanner
# ─────────────────────────────────────────────────────
@tool
def nmap_scan(target: str) -> str:
    '''
    Scan a target IP for open ports and running services.
    Returns a JSON string with port numbers, states, and service names.
    Use this first to discover what attack surface is available.
    '''
    try:
        scanner = nmap.PortScanner()
        scanner.scan(
            hosts=target,
            arguments='-sV -p 22,23,80,443,8080,8443,3306,5432 --open'
        )

        results = []
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    info = scanner[host][proto][port]
                    results.append({
                        'port': port,
                        'state': info['state'],
                        'service': info['name'],
                        'version': info.get('version', 'unknown'),
                        'product': info.get('product', 'unknown')
                    })

        if not results:
            return f'No open ports found on {target}'

        return json.dumps(results, indent=2)

    except Exception as e:
        return f'nmap scan failed: {str(e)}'


# ─────────────────────────────────────────────────────
# TOOL 2: Banner grabber
# ─────────────────────────────────────────────────────
@tool
def grab_banner(target: str, port: int) -> str:
    '''
    Connect to an open port on the target and read the service banner.
    Returns the raw banner text which reveals software name and version.
    Use this after nmap_scan to get more detail about a specific port.
    '''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))

        sock.send(b'\r\n')

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        if banner:
            return f'Banner on port {port}: {banner}'
        return f'Port {port} is open but returned no banner'

    except socket.timeout:
        return f'Port {port}: connection timed out'
    except ConnectionRefusedError:
        return f'Port {port}: connection refused'
    except Exception as e:
        return f'Banner grab failed on port {port}: {str(e)}'
# ─────────────────────────────────────────────────────
# TOOL 3: SSH brute-force
# ─────────────────────────────────────────────────────
@tool
def ssh_brute(target: str, username: str, password: str) -> str:
    '''
    Attempt a single SSH login with the given username and password.
    Returns whether the attempt succeeded or failed.
    Use this after recon to try credentials against an open SSH port.
    '''
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=target,
            port=22,
            username=username,
            password=password,
            timeout=5,
            allow_agent=False,
            look_for_keys=False
        )
        client.close()
        return f'SUCCESS: logged in with {username}:{password}'

    except paramiko.AuthenticationException:
        return f'FAILED: wrong credentials {username}:{password}'
    except Exception as e:
        return f'ERROR: {str(e)}'

# ─────────────────────────────────────────────────────
# TOOL 4: HTTP probe
# ─────────────────────────────────────────────────────
@tool
def http_probe(target: str) -> str:
    '''
    Probe common HTTP paths on the target to discover web endpoints.
    Returns status codes and response sizes for each path checked.
    Use this if port 80 or 8080 is open on the target.
    '''
    paths = [
        '/', '/admin', '/login', '/wp-admin', '/dashboard',
        '/.env', '/config', '/backup', '/phpmyadmin', '/api'
    ]
    
    results = []
    for path in paths:
        try:
            url = f'http://{target}{path}'
            response = requests.get(url, timeout=3, allow_redirects=False)
            results.append({
                'path': path,
                'status': response.status_code,
                'size': len(response.content)
            })
        except requests.exceptions.ConnectionError:
            results.append({'path': path, 'status': 'no web server', 'size': 0})
        except Exception as e:
            results.append({'path': path, 'status': f'error: {str(e)}', 'size': 0})
    
    return json.dumps(results, indent=2)


