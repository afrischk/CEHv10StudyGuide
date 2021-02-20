# Wireless Network Hacking

- [Wireless Network Hacking](#wireless-network-hacking)
  - [Wireless Basics](#wireless-basics)
    - [Wirless modes](#wirless-modes)
    - [Wireless Standards](#wireless-standards)
    - [Antenna Types](#antenna-types)
    - [Authentication Types](#authentication-types)
      - [Open System](#open-system)
      - [Shared Key Authentication](#shared-key-authentication)
      - [Centralized Authentication](#centralized-authentication)
  - [Wireless Encryption](#wireless-encryption)
    - [Wired Equivalent Privacy (WEP)](#wired-equivalent-privacy-wep)
      - [Initialization Vector (IV)](#initialization-vector-iv)
    - [Wi-Fi Protected Access (WPA or WPA2)](#wi-fi-protected-access-wpa-or-wpa2)
  - [Wireless Hacking](#wireless-hacking)
    - [Threats](#threats)
    - [Network Discovery](#network-discovery)
      - [NetStumbler](#netstumbler)
      - [Kismet](#kismet)
      - [NetSurveyor](#netsurveyor)
      - [WiFi Adapter](#wifi-adapter)
  - [Wireless Attacks](#wireless-attacks)
    - [Ad Hoc Connection Attack](#ad-hoc-connection-attack)
    - [DoS Attack](#dos-attack)
    - [MAC Filter](#mac-filter)
  - [Wireless Encryption Attacks](#wireless-encryption-attacks)
    - [WEP Cracking](#wep-cracking)
      - [Process](#process)
      - [Tools](#tools)
        - [Aircrack-ng](#aircrack-ng)
        - [Cain and Abel](#cain-and-abel)
    - [WPA Cracking](#wpa-cracking)
      - [Key Reinstallation Attack (KRACK)](#key-reinstallation-attack-krack)
  - [Wireless Sniffing](#wireless-sniffing)
    - [Wirless Sniffing Tools](#wirless-sniffing-tools)
      - [AirMagnet WiFi Analyzer Pro](#airmagnet-wifi-analyzer-pro)

## Wireless Basics

- **Orthogonal Frequency-Division Multiplexing** (OFDM) - transmission media is divided into mulltiple frequency bands that dont overlap; each can be used to carry a separate signal
- **Direct-Sequence Spread Spectrum** (DSSS) - combines all available waveforms; the entire frequency bandwith can be used for message delivery
- **Basic Service Area** (BSA) - footprint of an AP
- **Basic Service Set** (BSS) - communication between a single AP and its clients
- **Extended Service Set** (ESS) - add multiple APs to BSS to extend the range of the network
- **roaming** - (re)-association/movement between APs within a ESS
- **Basic Service Set Identifier** (BSSID) - MAC address of the wireless access point
- **Service Set Identifier** (SSID) - a text word (&le 32 char) that identifies network; provides no security; part of the header in every packet
- **Association** is the act of connecting; **authentication** is the act of identifying the client
 
### Wirless modes

- **ad hoc** - wireless systems connect directly to other systems
- **infrastructure mode** - uses an _access point_ (AP) to funnel all wireless connections through
 
### Wireless Standards

- **802.11 Series** - defines the standards for wireless networks
- **802.15.1** - Bluetooth
- **802.15.4** - Zigbee - low power, low data rate, close proximity ad-hoc networks
- **802.16** - WiMAX - broadband wireless metropolitan area networks
- **802.1x** - standard for **port-based Network Access Control** (PNAC); defines a method that uses the **Extensible Authentication Protocol** (EAP) to provide authentication

| Wireless Standard | Operating Speed (Mbps) | Frequency (GHz) | Modulation Type |
|-------------------|------------------------|-----------------|-----------------|
| 802.11a           | 54                     | 5               | OFDM            |
| 802.11b           | 11                     | 2.4             | DSSS            |
| 802.11d           | Variation of a & b     | Global use      |                 |
| 802.11e           | QoS Initiative         | Data and voice  |                 |
| 802.11g           | 54                     | 2.4             | OFDM and DSSS   |
| 802.11i           | WPA/WPA2 Encryption    |                 |                 |
| 802.11n           | 100+                   | 2.4-5           | OFDM            |
| 802.11ac          | 1000                   | 5               | QAM             |

### Antenna Types

- **Spectrum Analyzer** - verifies wireless quality, detects rogue access points and detects attacks
- **(Uni)Directional Antenna** - signals in one direction which greatly increases signal strength and distance; Yagi antenna is a type
- **Omnidirectional Antenna** - signals in all directions; used by most APs
- **Cantenna** - directional antenna built from a can/pringles can
- **Dipole Antenna** -  two signal towers; omnidirectional
- **Parabolic Grid Antenna** - type of directional antenna

### Authentication Types

#### Open System

- client sends a 802.11 authentication frame with SSID to an AP
- AP answers with a verification frame

1. Probe request
2. Probe response (includes security parameters)
3. Authentication request
4. Authentication response
5. Association request (includes security parameters)
6. Association reponse

#### Shared Key Authentication

- client participates in a challenge/request scenario
- AP verifies a decrypted "key" for authentication

1. Authentication request
2. Challenge text
3. Client encrypts challenge and returns
4. Challenge decrypted - if correct, client authenticated
5. Client connects

#### Centralized Authentication

- Shared Key Authentication + Authentication server (e.g. RADIUS)


## Wireless Encryption

### Wired Equivalent Privacy (WEP)

- Weak security for wireless network
- Uses 40-bit, 104-bit or 232-bit keys (64-bit, 128-bit and 256-bit WEP encryption version) in an RC4 encryption algorithm
- Primary weakness lies in its reuse of **initialization vectors** (IV)
- Original intent was to give wireless the same level of protection of an Ethernet hub
 
#### Initialization Vector (IV)

- It calculates a 32-bit **integrity check value** (ICV)
- ICV is appended at the end of the payload
- Then provides a 24-bit IV, which is combined with a key to be input into an RC4 algorithm
- The generated "keystream" from the algorithm is encrypted by XOR and is combined with the ICV to produce encrypted data
- IVs are generally small and are frequently reused
- Sent in clear text as a part of the header
- This combined with RC4 makes it easy to decrypt the WEP key
- An attacker can send disassociate requests to the AP to generate a lot of these


### Wi-Fi Protected Access (WPA or WPA2)

- WPA uses **Temporal Key Integrity Protocol** (TKIP) with a 128-bit key and the client's MAC address
- WPA changes the key every 10,000 packets
- WPA transfers keys back and forth during an **Extensible Authentication Protocol** (EAP) authentication session
- **WPA2 Enterprise** - can tie an EAP or RADIUS server into the authentication, allowing to make use of Kerberos
- **WPA2 Personal** - uses a pre-shared key to authenticate
- WPA2 uses AES for encryption
- WPA2 ensures FIPS 140-2 compliance
- WPA2 implements 802.11i
- WPA2 uses a block cipher instead of stream cipher in WPA
- WPA2 uses **Cipher Block Chaining Message Authentication Protocol** (CCMP) instead of TKIP
- **Message Integrity Codes** (MIC) - hashes used by CCMP to protect integrity
- **Cipher Block Chaining Message Authentication Code** (CBC-MAC) - integrity process of WPA2

| Wireless Standard | Encryption | IV Size (Bits) | Key Length (Bits) | Integrity Check |
|-------------------|------------|----------------|-------------------|-----------------|
| WEP               | RC4        | 24             | 40/104            | CRC-32          |
| WPA               | RC4 + TKIP | 48             | 128               | Michael/CRC-32  |
| WPA2              | AES-CCMP   | 48             | 128               | CBC-MAC (CCMP)  |

## Wireless Hacking

### Threats

- Access Control Attacks
- Integrity Attacks
- Confidentiality Attacks
- Availability Attacks
- Authentication Attacks


### Network Discovery

- Wardriving, warflying, warwalking, etc.
- Tools such as WiFiExplorer (collects info about WAPs), WiFiFoFum, OpenSignalMaps, WiFinder
- **WIGLE** - map for wireless networks

#### NetStumbler

- Find networks
- Identifying poor coverage locations within an ESS
- Detecting interference causes
- finding rough access points in the network
- Windows based
- Compatible with 802.11a, b and g

#### Kismet

- Wireless packet analyzer/sniffer that can be used for discovery
- Linux based
- Detect access points and clients without sending any packets (passively)
- Can detect access points that have not been configured (or beaconing off)
- Determine which type of encryption is used
- Works by channel hopping to discover as many networks as possible
- Ability to sniff packets and save them to  a log file (readable by Wireshark/tcpdump)
- Detects WLANS using __802.11a__, __b__, __g__ and __n__ standards
- Works also as an IDS

#### NetSurveyor

- Tool for Windows that does similar features to NetStumbler and Kismet
- Supports almost all wirless adapters
- Troubleshooting and verifying proper installation of wireless networks
 
#### WiFi Adapter

- AirPcap Usb dongle - captures all data, management and control frames; works with Aircrack-ng; includes AirPcapReplay and software decrypting WEB and WPA frames
- **pcap** - driver library for Windows
- **libpcap** - driver library for Linux


## Wireless Attacks

- **Rogue Access Point** - places an access point controlled by an attacker
- **Evil Twin** (mis-association attack) - a rogue AP with a SSID similar to the name of a popular network
- **Honeyspot** - faking a well-known hotspot with a rogue AP

### Ad Hoc Connection Attack

- Connecting directly to another device via ad-hoc network
- Not very successful as the other user has to accept connection

### DoS Attack

- Either sends de-auth packets to the AP
- Or jam the wireless signal
- Or employ a rogue AP to have legitimate users connect, as a result removing their acces to legitimate networked resources (unauthorized association)
- Jammers are very dangerous as they are illegal

### MAC Filter

- Only allows certain MAC addresses to associate with the AP
- Easily broken because you can sniff out MAC addresses already connected and spoof it
- Tools for spoofing include **SMAC** and **TMAC**

## Wireless Encryption Attacks

### WEP Cracking

- General idea: generating enough packets to guess the encryption key

#### Process

1. Start a compatible wireless adapter with injection and sniffing capabilities
2. Start a sniffer to capture packets
3. Force the creation of thousands of packets (generally with de-auth)
4. Analyze captured packets with a cracking tool

#### Tools

- **KisMAC** - MacOS tool to brute force WEP or WPA passwords
- **WEPAttack**
- **WEPCrack**
- **Portable Penetrator**
- **Elcomsoft's Wireless Security Auditor**
 
##### Aircrack-ng

- Sniffer, wireless network detector, traffic analysis tool and a password cracker
- Runs on Windows and Linux
- Uses dictionary attacks for WEP, WPA and WPA 2
- WEP methods to crack include **PTW**, **FMS**, and **Korek** technique

##### Cain and Abel

- Sniffs packets and cracks passwords (may take longer)
- Relies on statistical measures and the PTW technique to break WEP

### WPA Cracking

- Much more difficult than WEP
- Again force bunch of packets to be sent, store them an run them trough an offline cracker
- Uses a constantly changing temporal key and pre-shared user-defined password
- Most other attacks are simply brute-forcing the password#

#### Key Reinstallation Attack (KRACK)

- Replay attack that uses third handshake of another device's session
- WPA 2 uses a 4-way handshake to establish a nounce (one-time-use shared secret for the communication session)
- The WPA 2 standard allows for disconnects during the handshake (because its wireless)
- WPA 2 allows reconnection using the _same value_ in the 3rd handshake
- WPA 2 does not require a different key in this step (reconnection)
- Attacker could re-send the 3rd handshake of another devices session to manipulate or reset the WPA 2 encryption key
- Each time its reset it causes data to be encrypted using the same values -> over time learn the complete keychain used to encrypt the traffic
 
## Wireless Sniffing

### Wirless Sniffing Tools

- **Wireshark**
- **NetStumbler**
- **Kismet**
- **OmniPeek** - provides data like Wireshark in addition to network activity and monitoring
- **WiFi Pilot**

#### AirMagnet WiFi Analyzer Pro

- Sniffer, traffic analyzer and network-auditing suite
- Used to resolve performance problems and automatically detect security threats and vulnerabilities
- Compliance reporting engine that maps network information to requirements for compliance with policy and industry regulations
