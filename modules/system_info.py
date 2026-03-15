# modules/system_info.py
import socket
import platform
import uuid

try:
    import netifaces as ni
except ImportError:
    ni = None

def _primary_ip():
    if ni:
        for iface in ni.interfaces():
            if iface.startswith(("lo", "docker", "veth")):
                continue
            addrs = ni.ifaddresses(iface).get(ni.AF_INET, [])
            for a in addrs:
                ip = a.get("addr")
                if ip and not ip.startswith("127."):
                    return ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def collect_system_info():
    return {
        "hostname": socket.gethostname(),
        "ip_address": _primary_ip(),
        "platform": platform.system(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                   for ele in range(0, 8 * 6, 8)][::-1])
    }
