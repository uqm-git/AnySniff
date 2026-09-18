import os
import time
import threading
import sys
import socket
import subprocess
from datetime import datetime

from scapy.all import sniff, IP, UDP, TCP
import psutil

IGNORED_PORTS = {443}

PRIVATE = (
    '127.', '192.168.', '10.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
    '169.254.', '0.', '255.',
    '224.', '225.', '226.', '227.', '228.', '229.',
    '230.', '231.', '232.', '233.', '234.', '235.',
    '236.', '237.', '238.', '239.',
    'ff',
)

C = {
    'reset':   '\033[0m',
    'bold':    '\033[1m',
    'dim':     '\033[2m',
    'cyan':    '\033[36m',
    'green':   '\033[32m',
    'yellow':  '\033[33m',
    'red':     '\033[31m',
    'magenta': '\033[35m',
    'blue':    '\033[34m',
}

if os.name == 'nt':
    os.system('')

seen = set()
lock = threading.Lock()
print_lock = threading.Lock()
start_time = time.time()
packet_count = 0
conn_count = 0
relay_count = 0
status_visible = False
rdns_cache = {}
found_event = threading.Event()
found_ip = None
found_port = None
found_proto = None
sniffer = None


def c(color, text, bold=False):
    prefix = C['bold'] if bold else ''
    return f"{prefix}{C[color]}{text}{C['reset']}"


def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE)


def anydesk_pids():
    pids = set()
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if 'anydesk' in (p.info['name'] or '').lower():
                pids.add(p.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return pids


def is_anydesk_relay(ip):
    if ip in rdns_cache:
        return rdns_cache[ip]
    try:
        socket.setdefaulttimeout(0.5)
        hostname, _, _ = socket.gethostbyaddr(ip)
        result = hostname.endswith('.anydesk.com')
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        result = False
    rdns_cache[ip] = result
    return result


def uptime():
    d = int(time.time() - start_time)
    h, r = divmod(d, 3600)
    m, s = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def clear_status():
    global status_visible
    if status_visible:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        status_visible = False


def report(ip, port, proto):
    global conn_count, relay_count, found_ip, found_port, found_proto
    if port in IGNORED_PORTS:
        return
    key = (ip, port, proto)
    with lock:
        if key in seen:
            return
        seen.add(key)
        if is_anydesk_relay(ip):
            relay_count += 1
        conn_count += 1
        if found_event.is_set():
            return
        found_ip, found_port, found_proto = ip, port, proto
        found_event.set()


def stop_sniff():
    global sniffer
    try:
        if sniffer is not None:
            sniffer.stop()
    except Exception:
        pass


def on_packet(pkt):
    global packet_count
    if found_event.is_set():
        return
    if not pkt.haslayer(IP):
        return
    packet_count += 1
    src, dst = pkt[IP].src, pkt[IP].dst

    if not anydesk_pids():
        return

    if pkt.haslayer(UDP):
        proto = 'UDP'
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(TCP):
        proto = 'TCP'
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    else:
        return

    if is_private(dst):
        remote, port = src, sport
    else:
        remote, port = dst, dport

    if is_private(remote):
        return

    if port in IGNORED_PORTS:
        return

    report(remote, port, proto)
    if found_event.is_set():
        stop_sniff()


def poll():
    while not found_event.is_set():
        try:
            pids = anydesk_pids()
            if pids:
                for proto in ('tcp', 'udp'):
                    for conn in psutil.net_connections(kind=proto):
                        if conn.pid in pids and conn.raddr and not is_private(conn.raddr.ip):
                            if conn.raddr.port in IGNORED_PORTS:
                                continue
                            report(conn.raddr.ip, conn.raddr.port, proto.upper())
                            if found_event.is_set():
                                stop_sniff()
                                return
        except Exception:
            pass
        time.sleep(1)


def status_loop():
    global status_visible
    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    i = 0
    while not found_event.is_set():
        pids = anydesk_pids()
        state = c('green', '●') if pids else c('yellow', '○')
        line = (
            f"{c('dim', spinner[i % len(spinner)])} "
            f"{state} "
            f"{c('cyan', uptime())} "
            f"{c('dim', '│')} "
            f"{c('cyan', str(packet_count))} pkt "
            f"{c('dim', '│')} "
            f"{c('green', str(conn_count))} conn "
            f"{c('dim', '│')} "
            f"{c('yellow', str(relay_count))} relay "
            f"{c('dim', '│')} "
            f"{c('magenta', str(len(pids)))} pid"
        )
        with print_lock:
            sys.stdout.write("\r\033[K" + line)
            sys.stdout.flush()
            status_visible = True
        i += 1
        time.sleep(0.1)


def show_result():
    ts = datetime.now().strftime("%H:%M:%S")
    with print_lock:
        clear_status()
        print()
        print(f"{c('dim', '[' + ts + ']')} {c('green', '●', bold=True)} "
              f"{c('bold', found_ip, bold=True)}{c('dim', ':')}"
              f"{c('blue', str(found_port))} {c('cyan', found_proto)}")
        print()
        print(c('green', '  [+] Non-private IP detected. Exiting.', bold=True))
        print()


def main():
    global sniffer
    threading.Thread(target=poll, daemon=True).start()
    threading.Thread(target=status_loop, daemon=True).start()

    try:
        sniffer = sniff(filter="udp or tcp", prn=on_packet, store=0,
                        stop_filter=lambda p: found_event.is_set())
    except PermissionError:
        print("Need admin/root.")
        return
    except KeyboardInterrupt:
        with print_lock:
            clear_status()
        print()
        return

    if found_event.is_set():
        show_result()
        os._exit(0)


if __name__ == '__main__':
    main()
