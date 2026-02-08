# 💀 JAMSTREAPPER v1.0

**Network Intelligence & Deep Packet Reaper**

```
       _                      ____  _                                            
      | | __ _ _ __ ___      / ___|| |_ _ __ ___  __ _ _ __  _ __   ___ _ __ 
   _  | |/ _` | '_ ` _ \     \___ \| __| '__/ _ \/ _` | '_ \| '_ \ / _ \ '__|
  | |_| | (_| | | | | | |     ___) | |_| | |  __/ (_| | |_) | |_) |  __/ |   
   \___/ \__,_|_| |_| |_|    |____/ \__|_|  \___|\__,_| .__/| .__/ \___|_|   
                                                      |_|   |_|              
```

**Framework de Auditoria de Rede e Inspeção Profunda de Pacotes (DPI)**

Desenvolvido por: **Kleber Tiko** aka: **Nightwolf**

---

## ⚠️ AVISO LEGAL (DISCLAIMER)

> [!CAUTION]
> **ESTE SOFTWARE FOI DESENVOLVIDO EXCLUSIVAMENTE PARA FINS DIDÁTICOS E PENTEST.**
>
> O uso do JamStreapper para interceptar tráfego sem autorização expressa é **ILEGAL**. O autor não se responsabiliza por quaisquer danos ou implicações legais decorrentes do mau uso desta ferramenta. Use com ética e apenas em ambientes de laboratório autorizados.

---

## 🛠️ VISÃO TÉCNICA E ARQUITETURA

O **JamStreapper v1.0** opera no "ponto cego" entre as camadas 2 e 7 do modelo OSI, permitindo uma manipulação granular do tráfego de rede sem interromper a conectividade básica do alvo.

### Camadas de Operação

| Componente | Técnica | Objetivo |
|------------|---------|----------|
| **Camada 2 (Data Link)** | `ARP Spoofing` | Realiza o envenenamento do cache ARP para estabelecer uma posição de Man-in-the-Middle (MITM). |
| **Camada 3 (Network)** | `IP Forwarding` | Garante que o tráfego legítimo continue a fluir pela máquina de ataque para evitar a detecção. |
| **Camada 4 (Transport)** | `TCP RST Injection` | Injeta pacotes com a flag `RST` para terminar sessões TCP específicas (Streaming/P2P) de forma cirúrgica. |
| **Camada 7 (Application)** | `DPI Engine` | Analisa o payload em busca de assinaturas de protocolos (BitTorrent) e campos SNI no TLS (HTTPS). |

---

## 🚀 OPERAÇÃO (HACKER LAB MODE)

### 1. Preparação do Ambiente

O script requer **Python 3** e privilégios administrativos para manipular sockets brutos (raw sockets).

```bash
# Instalação das dependências necessárias
pip install scapy rich art
```

### 2. Configuração do Cenário

Antes de iniciar, identifique:

- **Interface de rede**: (ex: `wlan0` ou `eth0`)
- **IP do Alvo**: (ex: o IP do Access Point ou de um dispositivo específico na rede)
- **IP do Gateway**: (ex: o roteador principal da rede)

### 3. Execução

```bash
sudo python jamstreapper.py -i <interface> -t <ip_alvo> -g <ip_gateway>
```

**Exemplo Prático:**

```bash
sudo python jamstreapper.py -i wlan0 -t 192.168.1.50 -g 192.168.1.1
```

---

## 🎯 O QUE O JAMSTREAPPER DETECTA E BLOQUEIA

### Protocolos P2P (Peer-to-Peer)

O JamStreapper identifica e bloqueia tráfego de compartilhamento de arquivos através das seguintes assinaturas:

| Protocolo | Assinaturas Detectadas |
|-----------|------------------------|
| **BitTorrent** | `BitTorrent protocol`, `get_peers`, `announce_peer`, `info_hash`, `peer_id` |
| **eMule/eDonkey** | `eMule`, `eD2k` |
| **DC++** | `DC++` |
| **Gnutella** | `Gnutella`, `KAD`, `Kademlia` |

### Serviços de Streaming

O motor DPI analisa conexões HTTPS através do campo **SNI (Server Name Indication)** para identificar plataformas de streaming:

**Plataformas Bloqueadas:**
- 🎬 **Vídeo**: Netflix, YouTube, Prime Video, Hulu, Disney+, HBO Max, Crunchyroll, DAZN, Paramount+, Peacock, Pluto TV, Tubi, Vimeo, Dailymotion
- 🎵 **Música**: Spotify, Apple Music
- 🎮 **Gaming/Live**: Twitch
- 📺 **Outros**: Stremio, Amazon Video

### Como Funciona a Detecção

1. **Camada de Aplicação (L7)**: Analisa o payload dos pacotes em busca de assinaturas binárias características de protocolos P2P
2. **Inspeção TLS/SNI**: Intercepta o handshake TLS antes da criptografia completa para ler o nome do domínio solicitado
3. **TCP RST Injection**: Ao detectar tráfego proibido, injeta pacotes TCP com flag RST em ambas as direções, forçando o encerramento da conexão

---

## 🛡️ FUNCIONALIDADES DE ELITE

- **`Ghost Cleanup`**: Protocolo de saída segura. Ao encerrar (`Ctrl+C`), o script executa o ARP Healing, enviando 7 pacotes de restauração para limpar o cache das vítimas e evitar instabilidades residuais na rede.

- **`DPI Alerts`**: Interface visual em tempo real. Cada interceptação gera um painel formatado com o dump hexadecimal do payload, permitindo a análise imediata da assinatura capturada.

- **`Anti-Forensics`**: Rotinas de limpeza automática. O script desativa o encaminhamento de IP no kernel e tenta limpar o histórico de comandos da sessão para minimizar rastros de auditoria.

- **`Selective Jamming`**: Diferente de um "Jammer" de RF, o JamStreapper permite que o alvo continue a usar serviços leves (e-mail, DNS, navegação web simples), enquanto bloqueia cirurgicamente o consumo abusivo de banda.

---

## ❓ FAQ (PERGUNTAS FREQUENTES)

**P: Por que o alvo ainda consegue navegar no Google?**

**R:** Porque o JamStreapper faz inspeção cirúrgica. Ele só bloqueia o que está na lista de assinaturas (`signatures list`). Isso torna o ataque muito mais difícil de ser notado e mantém serviços essenciais funcionando (navegação web, e-mail, DNS).

**P: O script funciona em redes 5GHz?**

**R:** Sim. O protocolo ARP opera na Camada 2, sendo independente da frequência ou modulação da Camada Física (Wi-Fi 2.4/5/6GHz).

**P: Como adicionar mais assinaturas?**

**R:** Edite o dicionário `self.signatures` no código:
```python
self.signatures = {
    "P2P": [b"nova_assinatura", b"outra_assinatura"],
    "STREAM": ["novodominio.com", "outroservico"]
}
```

**P: O tráfego HTTPS não é criptografado?**

**R:** Sim, mas o campo SNI (Server Name Indication) no handshake TLS é enviado em texto claro antes da criptografia completa, permitindo a identificação do domínio de destino.

---

## 📜 LICENÇA

Este projeto está sob a licença **MIT**.

---

> *"No sistema, nada se cria, nada se perde, tudo se intercepta."*
