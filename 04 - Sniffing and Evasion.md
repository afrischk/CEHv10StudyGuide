# Sniffing and Evasion

- [Sniffing and Evasion](#sniffing-and-evasion)
  - [Basic Knowledge](#basic-knowledge)
    - [MAC (Media Access Control)](#mac-media-access-control)
    - [Collision Domains](#collision-domains)
  - [Protocols Susceptible to Sniffing](#protocols-susceptible-to-sniffing)
    - [IPv4](#ipv4)
      - [Header](#header)
    - [IPv6](#ipv6)
      - [Header](#header-1)
    - [ARP](#arp)
      - [Tools](#tools)
      - [Commands](#commands)
      - [Gratuitous ARP](#gratuitous-arp)
  - [Active and Passive Sniffing](#active-and-passive-sniffing)
    - [Wiretapping](#wiretapping)
    - [Span port](#span-port)
    - [MAC Flooding](#mac-flooding)
      - [CAM Table](#cam-table)
      - [Tools](#tools-1)
    - [ARP Poisoning](#arp-poisoning)
      - [Countermeasures](#countermeasures)
      - [Tools](#tools-2)
    - [DHCP Starvation](#dhcp-starvation)
      - [DHCP Steps](#dhcp-steps)
      - [Tools](#tools-3)
    - [Spoofing](#spoofing)
      - [Port Security](#port-security)
    - [Sniffing Tools](#sniffing-tools)
      - [Wireshark](#wireshark)
      - [tcpdump](#tcpdump)
      - [tcptrace](#tcptrace)
      - [Other Tools](#other-tools)
  - [Evasion](#evasion)
    - [Intrusion Detection System (IDS)](#intrusion-detection-system-ids)
    - [Snort](#snort)
      - [Config](#config)
      - [Rule syntax](#rule-syntax)
      - [Modes](#modes)
      - [Example output](#example-output)
    - [Firewall](#firewall)
  - [Evasion Techniques](#evasion-techniques)
    - [Tools](#tools-4)
    - [Firewall Evasion](#firewall-evasion)
      - [Tools](#tools-5)
    - [Honeypots](#honeypots)
      - [Examples (low-interaction)](#examples-low-interaction)
      - [Examples (high-interaction)](#examples-high-interaction)

## Basic Knowledge

- **Sniffing** (wiretapping) is capturing packets as they pass on the wire to review for interesting information
- **Network Interface Cards** (NICs) - normally only process signals meant for it
- **Promiscuous mode** - NIC must be in this setting to look at all frames passing on the wire
- **Pcap** - is needed for the NIC to work in promiscuous mode (WinPcap or libpcap)
- **CSMA/CD** (Carrier Sense Multiple Access/Collision Detection) - used over Ethernet to decide who can talk

### MAC (Media Access Control)

- physical or burned-in address
- assigned to NIC for communications at the Data Link layer
- 48 bits long
- Displayed as 12 hex characters separated by colons
- First half of address is the **organizationally unique identifier** -> identifies manufacturer
- Second half ensures no two cards on a subnet will have the same address
- loopback adddress is `FF:FF:FF:FF:FF:FF`

### Collision Domains

- Traffic from your NIC (regardless of mode) can only be seen within the same collision domain
- Hubs by default have one collision domain
- Switches have a collision domain for each port

## Protocols Susceptible to Sniffing

- **SMTP** is sent in plain text and is viewable over the wire.
- **SMTP v3** limits the information you can get, but you can still see it.
- **FTP** sends user ID and password in clear text
- **TFTP** passes everything in clear text
- **IMAP, POP3, NNTP, SNMPv1 and HTTP** all send over clear text data
- **TCP** shows sequence numbers (usable in session hijacking)
- **TCP and UCP** show open ports
- **IP** shows source and destination addresses

### IPv4

#### Header

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field               | Length   | Description                                                              |
| ------------------- | -------- | ------------------------------------------------------------------------ |
| Version             | 4 bits   | IP version 4                                                             |
| IHL                 | 4 bits   | Header Length in 32 bit words                                            |
| Type of Serivce     | 8 bits   | indication of the abstract parameters of the quality of service desired  |
| Total Length        | 16 bits  | length of datagram mesured in octets including header & data (mx. 65535) |
| Identification      | 16 bits  | value assigned by the sender                                             |
| Flags               | 3 bits   | Control Flags                                                            |
| Fragment Offset     | 13 bits  | indicates where in the datagram this fragment belongs                    |
| Time to Live        | 8 bits   | maximum time the datagram is allowed to remain                           |
| Protocol            | 8 bits   | indicates the next level protocol used                                   |
| Header Checksum     | 16 bits  | checksum on the header                                                   |
| Source Address      | 32 bits  |                                                                          |
| Destination Address | 32 bits  |                                                                          |
| Options             | variable |                                                                          |

### IPv6

- Uses 128-bit address
- Has 8 groups of 4 hexadecimal digits
- Sections with all 0s can be shorted to nothing (just has start and end colons)
- leading 0s in a group can be left out
- Double colon can only be used once
- Loopback address is ::1
- Scope applies for multicast and anycast
- Traditional network scanning is **computationally less feasible**

| IPv6 Address Type | Description                                           |
| ----------------- | ----------------------------------------------------- |
| Unicast           | Addressed and intended for one host interface         |
| Multicast         | Addressed for multiple host interfaces                |
| Anycast           | Large number of hosts can receive; nearest host opens |

| IPv6 Scopes | Description                                                             |
| ----------- | ----------------------------------------------------------------------- |
| Link local  | Applies only to hosts on the same subnet (Address block fe80::/10)      |
| Site local  | Applies to hosts within the same organization (Address block FEC0::/10) |
| Global      | Includes everything                                                     |

#### Header
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                         Source Address                        +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                      Destination Address                      +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field               | Length                  | Description                                                                                           |
| ------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------- |
| Version             | 4-bit                   | Internet Protocol version number = 6                                                                  |
| Traffic Class       | 8-bit                   | used by network for traffic management                                                                |
| Flow Label          | 20-bit                  | used by a source to label sequences of packets to be treated in the network as a single flow          |
| Payload Length      | 16-bit unsigned integer | length of the payload i.e. rest following this header                                                 |
| Next Header         | 8-bit selector          | identifies the type of header immediately following the IPv6 header -> points to upper-layer protocol |
| Hop Limit           | 8-bit unsigned integer  | decremented by 1 by each node that forwards the packet                                                |
| Source Address      | 128-bit                 |                                                                                                       |
| Destination Address | 128-bit                 |                                                                                                       |

### ARP

- Stands for Address Resolution Protocol
- Resolves IP address to a MAC address
- Packets are `ARP_REQUEST` and `ARP_REPLY`
- Each computer maintains it's own ARP cache, which can be poisoned
- Works on a broadcast basis - both requests and replies are broadcast to everyone

#### Tools

- **arpwatch** - monitors the ARP cache

#### Commands

`arp -a` - displays current ARP cache
`arp -d *` - clears ARP cache
`arp -s ipaddr macaddr` - sets static ARP table entry

#### Gratuitous ARP

- special packet to update ARP cache even without a request
- it is basically an `ARP_REPLY`
- this is used to poison cache on other machines

## Active and Passive Sniffing

- **Passive sniffing** - watching network traffic without interaction; only works for same collision domain
- **Active sniffing** - uses methods to make a switch send traffic to you even though it isn't destined for your machine
- **Network tap** - any kind of connection that allows to see all traffic passing by

### Wiretapping

- **Lawful interception** - legally intercepting communications between two parties
- **Active** - interjecting something into the communication
- **Passive** - only monitors and records the data
- **PRISM** (Planning Tool for Resource Integration, Synchronization and Management) - system used by NSA to wiretap external data coming into US

### Span port

- Switch configuration that makes the switch send a copy of all frames from other ports to a specific port
- Not all switches have the ability to do this
- Modern switches sometimes don't allow span ports to send data - you can only listen
- **Port mirroring** - another word for span port

### MAC Flooding

- Switches either flood or forward data
- If a switch doesn't know what MAC address is on a port, it will flood the data until it finds out
- This works by sending so many MAC addresses to the CAM table that it can't keep up
- **Switch port stealing** - tries to update information regarding a specific port in a race condition
- MAC Flooding will often destroy the switch before you get anything useful, doesn't last long and it will get you noticed.  Also, most modern switches protect against this.

####  CAM Table 

- the table on a switch that stores which MAC address is on which port
- If table is empty or full, everything is sent to all ports

#### Tools

- Etherflood
- Macof
 
### ARP Poisoning

- Also called ARP spoofing or gratuitous ARP
- This can trigger alerts because of the constant need to keep updating the ARP cache of machines
- Changes the cache of machines so that packets are sent to you instead of the intended target

#### Countermeasures

- Dynamic ARP Inspection using DHCP snooping
- XArp can also watch for this
- Default gateway MAC can also be added permanently into each machine's cache

#### Tools

- Cain and Abel
- WinArpAttacker
- Ufasoft
- dsniff

### DHCP Starvation

- Attempt to exhaust all available addresses from the server
- Attacker sends so many requests that the address space allocated is exhausted
- DHCPv4 packets - `DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, DHCPACK`
- DHCPv6 packets - `Solicit, Advertise, Request (Confirm/Renew), Reply`
- Mitigation is to configure DHCP snooping

**Rogue DHCP Server**
Setup to offer addresses instead of real server.  Can be combined with starvation to real server.

#### DHCP Steps
1. Client sends `DHCPDISCOVER`
2. Server responds with `DHCPOFFER`
3. Client sends request for IP with `DHCPREQUEST`
4. Server sends address and config via `DHCPACK`

#### Tools

- Yersinia
- DHCPstarv

### Spoofing

- **MAC Spoofing** - changes your MAC address.  Benefit is CAM table uses most recent address.
- Port security can slow this down, but doesn't always stop it
- MAC Spoofing makes the switch send all packets to your address instead of the intended one until the CAM table is updated with the real address again
- **IRDP Spoofing** - hacker sends ICMP Router Discovery Protocol messages advertising a malicious gateway
- **DNS Poisoning** - changes where machines get their DNS info from, allowing attacker to redirect to malicious websites

#### Port Security

- Authorizes traffic sent from specific MAC addresses to enter a port
- Only source MAC's are used to determine authorization

### Sniffing Tools

#### Wireshark

- Previously known as Ethereal
- Can be used to follow streams of data
- Can also filter the packets so you can find a specific type or specific source address

| Filter                                  | Description                                             |
| --------------------------------------- | ------------------------------------------------------- |
| `! (arp or icmp or dns)`                | filters out the "noise" from ARP, DNS and ICMP requests |
| `http.request`                          | displays HTTP GET requests                              |
| `tcp contains string`                   | displays TCP segments that contain the word "string"    |
| `ip.addr==172.17.15.12 && tcp.port==23` | displays telnet packets containing that IP              |
| `tcp.flags==0x16`                       | filters TCP requests with ACK flag set                  |


#### tcpdump

- Recent version is WinDump (for Windows)
- `tcpdump flag(s) interface`
- `tcpdump -i eth1` - puts the interface in listening mode

#### tcptrace

- Analyzes files produced by packet capture programs such as Wireshark, tcpdump and Etherpeek

#### Other Tools

- **Ettercap** - also can be used for MITM attacks, ARP poisoning.  Has active and passive sniffing.
- **Capsa Network Analyzer**
- **Snort** - usually discussed as an Intrusion Detection application
- **Sniff-O-Matic**
- **EtherPeek**
- **WinDump**
- **WinSniffer**
- **Airsnarf** - sniffing passwords and authentication traffic

## Evasion

### Intrusion Detection System (IDS)

- hardware or software devices that examine streams of packets for malicious behavior
- **Signature based** - compares packets against a list of known traffic patterns
- **Anomaly based** - makes decisions on alerts based on learned behavior and "normal" patterns
- **False negative** - case where traffic was malicious, but the IDS did not pick it up
- **HIDS** (Host-based intrusion detection system) - IDS that is host-based
- **NIDS** (Network-based intrusion detection system) - IDS that scans network traffic

### Snort

- a widely deployed IDS that is open source
- Includes a sniffer, traffic logger and a protocol analyzer
- Configuration is in `/etc/snort` on Linux and `c:\snort\etc` in Windows

```
snort -l c:\snort\log -c c:\snort\etc\snort.config
```

| Options | Description                                                                                                      |
| ------- | ---------------------------------------------------------------------------------------------------------------- |
| -v      | Sniffer mode                                                                                                     |
| -c      | Use the config file                                                                                              |
| -b      | Log packets in binary/tcpdump format                                                                             |
| -A fast | Alert mode fast; log only timestamps, alert message, source IP address and port, destination IP address and port |

#### Config

```
var HOME_NET 192.168.1.0/24
* sets home network (local subnet)
var EXTERNAL_NET any
* sets external network to any
var SQL_SERVERS $HOME_NET
* tells snort to watch out for SQL attacks on any device in the network defined as home
var RULE_PATH c:\etc\snort\rules
* tells snort where to find the rule sets
include $RULE_PATH/telnet.rules
* tells snort  to compare packets to the rule set named telnet.rules and alert on anything it finds
``` 
`var EXTERNAL_NET !$HOME_NET` ignores packates generated by the home network  
`var HTTP_SERVERS`, `var SMTP_SERVERS`, `var SQL_SERVERS` and `DNS_SERVERS` are more options

#### Rule syntax

- alert, log, pass (ignore packet) are snort rule actions
- Rule evaluation: Pass, Drop, Alert, Log
- `msg:` can have options like `flags:` (TCP flags to look for) or `content:` (string in payload to look for)

`alert tcp !HOME_NET any -> $HOME_NET 31337 (msg : "BACKDOOR ATTEMPT-Backorifice")`
This alerts about traffic coming not from my home network using any source port to my home network on port 31337.

#### Modes

- **Sniffer** - watches packets in real time
- **Packet logger** - saves packets to disk for review at a later time
- **NIDS** - analyzes network traffic against various rule sets

#### Example output

```
10/19-14:48:38.543734(1) 0:48:542:2A:67 -> 0:10:B5:3C:34:C4(2) type:0x800 len:0x5EA (3)
1.2.3.4:123 -> 5.6.7.8:443(4) TCP TTL:64 TOS:0x0 ID:18112 IpLen:20 DgmLen:1500 DF
******S*(5) Seq: 0xA153BD Ack: 0x0(6) Win: 0x2000 TcpLen: 28
```

1. timestamp
2. mac addresses
3. type & length of ethernet frame
4. ip addresses
5. SYN Flag set
6. sequence and acknowledgement numbers

### Firewall

- An appliance within a network that protects internal resources from unauthorized access
- Only uses rules that **implicitly denies** traffic unless it is allowed
- Oftentimes uses **network address translation** (NAT) which can apply a one-to-one or one-to-many relationship between external and internal IP addresses
- **NAT overload** (port address mapping) - implementation of one-to-many with port numbers
- **Screened subnet** (public zone of DMZ) - hosts all public-facing servers and services
- **Bastion hosts** - hosts on the screened subnet designed to protect internal resources
- **Private zone** - hosts internal hosts that only respond to requests from within that zone
- **Multi-homed** - firewall that has two or more interfaces (network connections)
- **Packet-filtering** - firewalls that only looked at headers
- **Stateful (multilayer) inspection** - firewalls that track the entire status of a connection (Layer 3 and 4)
- **Circuit-level gateway** - firewall that works on Layer 5 (Session layer)
- **Application-level gateway** - firewall that works like a proxy, allowing specific services in and out

## Evasion Techniques

- **Slow down** - faster scanning such as using nmap's `-T5` switch will get you caught. Pros use `-T1` switch to get better results
- **Flood the network** - trigger alerts that aren't your intended attack so that you confuse firewalls/IDS and network admins
- **Fragmentation** (session splicing) -  splits up packets so that the IDS can't detect the real intent
- **Unicode encoding** - works with web requests - using Unicode characters instead of ascii can sometimes get past

### Tools

- **Nessus** - also a vulnerability scanner
- **ADMmutate** - creates scripts not recognizable by signature files
- **NIDSbench** - older tool for fragmenting bits
- **Inundator** - flooding tool

### Firewall Evasion

- `ICMP Type 3 Code 13` will show that traffic is being blocked by firewall
- `ICMP Type 3 Code 3` tells you the client itself has the port closed
- Firewall type can be discerned by banner grabbing
- **Firewalking** - going through every port on a firewall to determine what is open
- The best way around a firewall will always be a compromised internal machine

#### Tools

- CovertTCP
- ICMP Shell
- 007 Shell
- TCP-over-DNS - combines special DNS server and client to covert messaging

### Honeypots

- A system setup as a decoy to entice attackers
- Should not include too many open services or look too easy to attack
- **High interaction** - simulates all services and applications and is designed to be completely compromised
- **Low interaction** - simulates a number of services and cannot be completely compromised

#### Examples (low-interaction)

- Specter
- Honeyd
- KFSensor

#### Examples (high-interaction)

- Symantec
- Decoy Server
- Honynets
