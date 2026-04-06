# 🌀 Mirage — ARP Spoofer
### by Nanoxsec

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/ARP-Spoofing-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Multithreading-Enabled-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Use-Authorized%20Pentest%20Only-yellow?style=for-the-badge">
</p>

---

## ⚡ Visão Geral

**Mirage** é uma ferramenta de **ARP Spoofing** desenvolvida do zero para fins de **pentest autorizado e estudo de segurança de redes**.

Ela atua na camada 2 do modelo OSI, manipulando tabelas ARP para posicionar o atacante entre a vítima e o gateway — realizando um ataque **Man-in-the-Middle (MitM)** na rede local.

> **Fluxo do ataque:**
> ```
> Vítima ←→ Mirage (atacante) ←→ Gateway
> ```

---

## 📦 Requisitos

### Sistema

- Linux (Kali, Parrot, Ubuntu ou similar)
- Python 3.8+
- Execução como root

### Dependências

```bash
sudo pip install scapy netifaces colorama --break-system-packages
```

---

## ⚙️ Instalação

```bash
git clone https://github.com/nanoxsec/mirage.git
cd mirage
sudo python3 mirage.py
```

---

## 🧠 Como Funciona

O protocolo ARP (Address Resolution Protocol) é responsável por mapear endereços IP em endereços MAC na rede local. Por design, ele não possui mecanismo de autenticação — qualquer dispositivo pode enviar respostas ARP, e os demais aceitam sem verificação.

O Mirage explora essa característica enviando pacotes ARP forjados continuamente:

- Para a **vítima**: anuncia que o IP do gateway pertence ao MAC do atacante
- Para o **gateway**: anuncia que o IP da vítima pertence ao MAC do atacante

Com isso, todo o tráfego da vítima passa pelo atacante antes de chegar ao destino, permitindo interceptação e análise.

O IP forwarding é ativado para que a vítima mantenha conectividade durante o ataque — sem isso, ela perderia o acesso à internet, o que poderia gerar alertas.

---

## 🖥️ Interface

Menu interativo no terminal com painel de status em tempo real:

```
  ┌─────────────────────────────────────────┐
  │           MIRAGE — ARP SPOOFER          │
  └─────────────────────────────────────────┘

  Interface    : eth0
  Local IP     : 192.168.0.100
  Gateway      : 192.168.0.1
  Alvos ativos : 2
  Captura      : ✅ Ativa
  IP Forward   : ✅ ON
  Pacotes      : 1842  DNS: 34  HTTP: 7

  [1] Escanear hosts na rede
  [2] Adicionar alvo
  [3] Remover alvo
  [4] Listar alvos ativos
  [5] Iniciar captura de tráfego
  [6] Parar captura de tráfego
  [7] Ativar / Desativar IP forwarding
  [8] Encerrar todos os ataques
  [0] Sair
```

---

## 🔧 Features

### 🎯 Ataque

- [x] ARP Spoofing bidirecional (vítima ↔ gateway)
- [x] Múltiplas vítimas simultâneas via multithreading
- [x] Restauração automática das tabelas ARP ao encerrar
- [x] Proteção contra atacar o próprio gateway

### 📡 Rede

- [x] Auto-detecção de interface e gateway
- [x] Scan de hosts ativos na rede local
- [x] Resolução de MAC via ARP request

### 📊 Captura de Tráfego

- [x] Interceptação de tráfego em tempo real
- [x] Interceptação de credênciais em sites sem HTTPS
- [x] Exibição de queries DNS no terminal
- [x] Exibição de requisições HTTP (URL + método)
- [x] Salvamento em `loot/capture.pcap` (compatível com Wireshark)
- [x] Log completo em `loot/session.log`
- [x] URLs HTTP salvas em `loot/urls.txt`

### ⚡ Performance

- [x] Threads independentes por alvo (`ThreadPoolExecutor`)
- [x] Controle de concorrência com `threading.Lock`
- [x] Execução contínua mesmo sob falhas parciais

---

## 🚀 Fluxo de Uso

```bash
1. sudo python3 mirage.py
2. [1] Escanear hosts na rede
3. [7] Ativar IP forwarding
4. [2] Adicionar alvo(s)
5. [5] Iniciar captura de tráfego
6. Monitorar DNS e HTTP em tempo real
7. [8] Encerrar ataques → ARP restaurado automaticamente
```

---

## 📁 Estrutura do Projeto

```
mirage/
├── mirage.py          # Entry point + menu interativo
├── requirements.txt
└── core/
    ├── utils.py       # Banner, logs, helpers
    ├── network.py     # Scan de hosts, resolução de MAC
    └── spoofer.py     # Lógica do ataque, captura, IP forwarding
```

---

## 📁 Estrutura de Saída

```
loot/
├── session.log        # Log completo da sessão
├── capture.pcap       # Captura de pacotes (Wireshark)
└── urls.txt           # URLs HTTP interceptadas
```

---

## 🖥️ Exemplo de Output

### Scan de hosts

```
[*] [19:28:10] Escaneando rede 192.168.0.0/24 ...
[+] [19:28:11] Host ativo → 192.168.0.1
[+] [19:28:11] Host ativo → 192.168.0.104
[+] [19:28:12] Host ativo → 192.168.0.113
```

### Ataque e captura

```
[>] [19:29:05] Ataque iniciado → 192.168.0.104
[*] [19:29:26] DNS  192.168.0.104    → v20.events.data.microsoft.com
[*] [19:29:36] DNS  192.168.0.104    → g.live.com
[+] [19:30:01] HTTP 192.168.0.104    → http://example.com/login
```

### Screenshots 📸

- Interface:
<img width="1198" height="726" alt="imagem" src="https://github.com/user-attachments/assets/8e8b57d9-21db-494d-9687-74378713ef73" />

- Ataque acontecendo com capturas de credenciais:

<img width="1365" height="963" alt="imagem" src="https://github.com/user-attachments/assets/8658acce-cdf7-48fd-98f2-ffe4ec2f9a7e" />

---

---

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida **exclusivamente** para:

- Pentest **devidamente autorizado** por escrito
- Ambientes de laboratório controlados
- Estudo avançado de segurança de redes

> **O uso desta ferramenta contra redes ou dispositivos sem autorização explícita é ilegal e de total responsabilidade do usuário.**
> O autor não se responsabiliza por qualquer uso indevido ou dano causado.

---

## ⭐ Destaques

- [x] Desenvolvida do zero
- [x] Múltiplas vítimas com threads independentes
- [x] Captura e análise de tráfego em tempo real
- [x] Restauração automática do ARP
- [x] Menu interativo estilo hacker
