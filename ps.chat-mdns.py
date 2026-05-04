#!/usr/bin/env python3
# ps.chat-mdns.py - Anuncia o servidor PS.Chat na rede local via mDNS (ZeroConf)

from zeroconf import ServiceInfo, Zeroconf
import socket
import time

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def register_service():
    zeroconf = Zeroconf()
    ip = get_ip()
    desc = {
        'path': '/',
        'port': '5000',
        'version': '1.0'
    }
    info = ServiceInfo(
        "_pschat._tcp.local.",
        "PS.Chat._pschat._tcp.local.",
        addresses=[socket.inet_aton(ip)],
        port=5000,
        properties=desc,
        server="pschat.local."
    )
    zeroconf.register_service(info)
    print(f"✅ Servidor PS.Chat anunciado em {ip}:5000 via mDNS")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.unregister_service(info)
        zeroconf.close()

if __name__ == "__main__":
    register_service()