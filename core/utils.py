import socket
import struct
import fcntl
import netifaces
from datetime import datetime
from colorama import Fore, Style


BANNER = f"""
{Fore.RED}
███╗   ███╗██╗██████╗  █████╗  ██████╗ ███████╗
████╗ ████║██║██╔══██╗██╔══██╗██╔════╝ ██╔════╝
██╔████╔██║██║██████╔╝███████║██║  ███╗█████╗  
██║╚██╔╝██║██║██╔══██╗██╔══██║██║   ██║██╔══╝  
██║ ╚═╝ ██║██║██║  ██║██║  ██║╚██████╔╝███████╗
╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
    ░▒▓█ MIRAGE █▓▒░
{Fore.YELLOW}
{Style.RESET_ALL}
"""


def log(msg, level="info"):
    now = datetime.now().strftime("%H:%M:%S")
    colors = {
        "info":    Fore.CYAN    + "[*]",
        "success": Fore.GREEN   + "[+]",
        "error":   Fore.RED     + "[!]",
        "warning": Fore.YELLOW  + "[~]",
        "attack":  Fore.MAGENTA + "[>]",
    }
    prefix = colors.get(level, Fore.WHITE + "[?]")
    print(f"{prefix} {Style.RESET_ALL}{Fore.WHITE}[{now}] {msg}{Style.RESET_ALL}")


def save_log(msg, path="loot/session.log"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a") as f:
        f.write(f"[{now}] {msg}\n")


def get_default_interface():
    try:
        gws = netifaces.gateways()
        iface = gws['default'][netifaces.AF_INET][1]
        return iface
    except Exception:
        return None


def get_gateway_ip(iface=None):
    try:
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][0]
    except Exception:
        return None


def get_local_ip(iface):
    try:
        addrs = netifaces.ifaddresses(iface)
        return addrs[netifaces.AF_INET][0]['addr']
    except Exception:
        return None
