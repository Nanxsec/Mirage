from scapy.all import ARP, Ether, send, sniff, wrpcap, conf, srp, sendp
from core.utils import log
import netifaces


def get_mac(ip):
    """Resolve MAC address for a given IP using ARP."""
    try:
        conf.verb = 0
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=False)[0]
        if result:
            return result[0][1].hwsrc
        return None
    except Exception:
        return None


def get_network_range(iface):
    """Returns the network range in CIDR notation for the given interface."""
    try:
        addrs = netifaces.ifaddresses(iface)
        ip = addrs[netifaces.AF_INET][0]['addr']
        netmask = addrs[netifaces.AF_INET][0]['netmask']

        ip_parts = list(map(int, ip.split('.')))
        mask_parts = list(map(int, netmask.split('.')))
        network = '.'.join(str(ip_parts[i] & mask_parts[i]) for i in range(4))

        cidr = sum(bin(x).count('1') for x in mask_parts)
        return f"{network}/{cidr}"
    except Exception:
        return None


def scan_hosts(iface):
    """Scans the local network and returns a list of active hosts."""
    network = get_network_range(iface)
    if not network:
        log("Não foi possível determinar o range da rede.", "error")
        return []

    log(f"Escaneando rede {network} ...", "info")

    conf.verb = 0
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout=3, verbose=False, iface=iface)[0]
    except Exception as e:
        log(f"Erro ao escanear: {e}", "error")
        return []

    hosts = []
    for _, received in result:
        hosts.append({
            "ip":  received.psrc,
            "mac": received.hwsrc
        })

    return hosts
