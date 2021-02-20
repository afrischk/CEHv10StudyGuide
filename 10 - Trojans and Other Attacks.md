# Trojans and Other Attacks

- [Trojans and Other Attacks](#trojans-and-other-attacks)
  - [Malware Basics](#malware-basics)
    - [Malware](#malware)
    - [Definitions](#definitions)
    - [Exploit Kits](#exploit-kits)
  - [Trojans](#trojans)
    - [Types](#types)
    - [Netcat](#netcat)
    - [Trojan Port Numbers](#trojan-port-numbers)
    - [Microsoft tools (Sysinternals)](#microsoft-tools-sysinternals)
      - [SIGVERIF](#sigverif)
  - [Viruses and Worms](#viruses-and-worms)
    - [Virus Types](#virus-types)
      - [Boot Sector Virus/System Virus](#boot-sector-virussystem-virus)
      - [Ransomware](#ransomware)
    - [Virus Makers](#virus-makers)
    - [Worm](#worm)
      - [Worms To Know](#worms-to-know)
  - [Analyzing Malware](#analyzing-malware)
    - [Analysis](#analysis)
    - [Counter measures](#counter-measures)
    - [Sheepdip](#sheepdip)
  - [Denial of Service Attacks (DoS)](#denial-of-service-attacks-dos)
    - [Basic Categories](#basic-categories)
    - [Attacks](#attacks)
    - [Tools](#tools)
    - [Countermeasures](#countermeasures)
  - [Session Hijacking](#session-hijacking)
    - [Steps](#steps)
    - [Tools](#tools-1)
    - [Countermeasures](#countermeasures-1)
      - [IPSec](#ipsec)
        - [Architecture Protocols](#architecture-protocols)
  - [Other Attacks](#other-attacks)
    - [Advanced Persistent Threat (APT)](#advanced-persistent-threat-apt)
      - [Tools](#tools-2)
  - [Malewares](#malewares)

## Malware Basics

### Malware

- Software designed to harm or secretly access a computer system without informed consent
- Also is defined as **computer contaminant**
- Most is downloaded from the Internet with or without the user's knowledge
- Infections on visiting sites through compromised sites
- Drive-by downloading e.g. delivered through an ad stream via Java vulnerability
- Through hijacked web application or peer-topeer application features
- IRC channel
- Sending via e-mail, file sharing or browser

### Definitions

- **Malvertising** - embedding malware into ad networks to throw malware across many legitimate sites
- **Overt Channels** - legitimate communication channels used by programs
- **Covert Channels** - used to transport data in unintended ways
- **Wrappers** - programs that allow you to bind an executable (Trojan) to an innocent file (e.g. EliteWrap)
- **Crypters** - use a combination of encryption, obfuscation and code manipulation to render malware undetectable to security programs
- **Packers** - use compression to pack the executable which helps evage signature based detection

### Exploit Kits

- help deliver exploits and payloads
- Infinity
- Bleeding Life
- Crimepack
- Blackhole Exploit Kit

## Trojans

- Software that appears to perform a desirable function but instead steals information or harms the system (data)
- To hackers, it is a method to gain and maintain access to a system
- Trojans are means of delivery whereas a backdoor provides the open access


### Types

- **Defacement trojan**
- **Proxy server trojan** - allows attacker to use the target system as a proxy
- **Botnet trojan** - Chewbacca, Skynet
- **Remote access trojans** - RAT, MoSucker, Optix Pro, Blackhole
- **E-banking trojans** - Zeus, Spyeye
- **Command Shell Trojan** - Provides a backdoor to connect through command-line access (Netcat)
- **Covert Channel Tunneling Trojan** (CCTT) - a remote access trojan; creates data transfer channels in previously authorized data streams

### Netcat

- "Swiss army knife" of tcp/ip hacking
- Provides all sorts of control over a remote shell on a target
- Can connect (inbound or outbound) over TCP or UDP, from any port
- Offers DNS forwarding, port mapping and forwarding and proxying
- Works with STDIN and STDOUT only
- Basic syntax: `nc [options] [target ip] [port]`
- Command-line access to target machine via `nc -e [ip address] [port]`
- On target machine `nc -l -p 5555` opens a listening port on 5555; connect from attackers machine via `nc [ip address] -p 5555`
- `nc -L 8080 -t -e cmd.exe` - open command shell on port 8080 (Windows only)

| Option | Description                                                    |
| ------ | -------------------------------------------------------------- |
| -l     | listen mode; accept inbound connections                        |
| -L     | listen mode; restart listening after disconnect (windows only) |
| -t     | telnet negotiation                                             |
| -e #   | execute program #                                              |
| -u     | UDP mode                                                       |
| -p #   | use port #                                                     |

### Trojan Port Numbers

| Trojan Name       | Port    |
| ----------------- | ------- |
| Death             | 2       |
| Senna Spy         | 20      |
| Hackers Paradise  | 31,456  |
| TCP Wrappers      | 421     |
| Doom, Santaz Back | 666     |
| Silencer, WebEx   | 1001    |
| RAT               | 1095-98 |
| SubSeven          | 1243    |
| Shiva-Burka       | 1600    |
| Trojan Cow        | 2001    |
| Deep Throat       | 6670-71 |
| Tini              | 7777    |
| NetBus            | 12345-6 |
| Whack a Mole      | 12361-3 |
| Back Orifice      | 31337-8 |

### Microsoft tools (Sysinternals)

- Windows runs everything located in __Run__, __RunServices__, __RunOnce__ and __RunServicesOnce__ automatically
- Settings from **HKEY_LOCAL_MACHINE** are important
- **Process Explorer** - Microsoft tool that shows you everything about running processes
- **AutoRuns** - shows applications running on startup
- **Registry Monitoring Tools** - SysAnalyzer, Tiny Watcher, Active Registry Monitor, Regshot
- **Malewarebytes** - displays questionable registry settings
- **Msconfig** - Windows program that shows startup settings
- **Tripwire** - Integrity verifier that can act as a HIDS in protection against trojans

#### SIGVERIF

- Build into Windows to verify the integrity of the system
- Log  file can be found at `c:\windows\system32\sigverif.txt`
- Look for drivers that are not signed

## Viruses and Worms

- **Virus** - self-replicating program that reproduces by attaching copies of itself into other executable code
- **Fake Antivirus/Virus hoax** - tries to convince a user has a virus and have them download an AV that is a virus itself
- Usually get installed via file attachments, user clocks on embedded e-mails or installation of pirated software
- Spreads slower than worms, because they rely on human interaction 

### Virus Types

- **Shell Virus** - wraps  around an application's code, inserting itself before the application's
- **Cluster Virus** - modifies directory table entries so every time a file or folder is opened, the virus runs
- **Multipartite Virus** - attempts to infect both boot sector and files; generally refers to viruses with multiple infection methods
- **Macro Virus** - written in VBA; infects template files - mostly Word and Excel (e.g. Melissa)
- **Polymorphic Code Virus** - mutates its code by using a polymorphic engine; difficult to find because it's signature is always changing
- **Encryption Virus** - uses  encryption to hide the code from antivirus
- **Metamorphic Virus** - rewrites itself every time it infects a new file
- **Stealth Virus/Tunneling Virus** - attempts to evade AVs by intercepting their requests to the OS, alters them and send them back to AV as uninfected
- **Cavity Virus** - overwrite portions of host files as to not increase the actual size of the file; uses null content sections
- **Sparse Infector Virus** - only infects occasionally (e.g. every 10th time)
- **File Extension Virus** - changes the file extensions of files to take advantage of most people having them turned off (`readme.txt.vbs` shows as `readme.txt`)

#### Boot Sector Virus/System Virus

- Moves boot sector to another location and then inserts its code int he original location
- Virus is executed first
- Most impossible to get rid of
- Counter measures: re-create boot record with `fdisk` or `mbr`

#### Ransomware

- Malicious software designed to deny access to a computer until a price is paid; usually spread through email
- **WannaCry** - famous ransomware; within 24 hours had 230,000 victims; exploited unpatched SMB vulnerability; used the External Blue exploit
- **Petya** - spread using the Windows Management Instrumentation command line; used the External Blue exploit; overwrote Master Boot Record
- **Locky** - spread via spam e-mail with a malicious Microsoft Word document attached
- **Other Examples**- Cryptorbit, CryptoLocker, CryptoDefense, police-themed

### Virus Makers

- Sonic Bat
- PoisonVirus Maker
- Sam's Virus Generator
- JPS Virus Maker

### Worm

- Self-replicating malware that sends itself to other computers without human intervention
- Usually doesn't infect files - just resides in active memory
- Often used in creation of botnets
- **Ghost Eye Worm** - hacking tool that uses random messaging on Facebook and other sites to perform malicious actions

#### Worms To Know

- **Code Red** - exploited indexing software on IIS servers in 2001; used a buffer overflow
- **Darlloz** - IoT Linux-based worm targets ARM, MIPS and PowerPC architectures (routers, set-top boxes and security cameras)
- **SQL Slammer** - DoS worm using a buffer overflow weakness in MS-SQL Services; spread using UDP; small size
- **Nimda** - file infection worm that modified nearly all web content on a machine; spread quickly through e-mail, open network shares and websites
- **Bug Bear** - spread over open network shares and e-mail; terminated AV and set up a backdoor for later use
- **Pretty Park** - spread via e-mail and took advantage of IRC to propagate stolen passwords

## Analyzing Malware

### Analysis

1. Make sure you have a good test bed - use a VM with NIC in host-only mode and no open shares
2. Analyze the malware on the isolated VM in a static state - **binText** and **UPX** help examine the binary, compression and packaging technique
3. Run the malware and check out processes - use **Process Monitor**, etc. to look at processes and **NetResident**, **TCPview** or **Wireshark** to look at network activity
4. Check and see what files were added, changed, or deleted; check processes spawn and changes to registry - **IDA Pro**, **VirusTotal**, **Anubis**, **Threat Analyzer**

### Counter measures

- Know what is running and used by your system
- Check ports in use - TCPView, CurrPorts and netstat
- Check processes in use - Process Monitor, Process Explorer
- Check registry changes - Regscanner
- Check system files and folders - SIGVERIF and Tripwire
- Keep AV up-to-date

### Sheepdip

- System that is used to check physical media, device drivers and other files for virus before introducing to network
- Isolated from other computers
- Not connected to network
- Configured with a couple of VV, port monitors, registry monitors and file integrity verifiers
  

## Denial of Service Attacks (DoS)

- **DoS** - seeks to take down a system or deny access to it by authorized users
- **DDoS** - attack comes from many systems and are usually part of a botnet
- **Botnet** - network of zombie computers a hacker uses to start a distributed attack; controlled over HTTP, HTTPS, IRC, or ICQ; botnet software/Trojans are Shark and Poison Ivy
- **DRDoS** - Distributed reflection denial of service attack (or just __botnet__) also known as **spoof attack**; uses multiple intermediary machines to pull of DoS; the secondary machines send the attack; attacker remains hidden

### Basic Categories

  - **Fragmentation attacks** - attacks take advantage of the system's ability to reconstruct fragmented packets
  - **Volumetric attacks** - bandwidth attacks; consume all bandwidth for the system or service
  - **Application attacks** - consume the resources necessary for the application to run (VS application-level attacks)
  - **TCP state-exhaustion attacks** - go after load balancers, firewalls and application servers by attempting to consume their connection state tables

### Attacks      

  - **SYN attack** - sends thousands of SYN packets to the machine with a false source address; eventually engages all resources and exhausts the machine
  - **SYN flood** - sends thousands of SYN packets; does not spoof IP but doesn't respond to the SYN/ACK packets; eventually bogs down the machine, runs out of resources
  - **ICMP flood** - sends ICMP Echo packets with a spoofed address; eventually reaches limit of packets per second sent
  - **Smurf** - large number of pings to the broadcast address of the subnet with source IP spoofed to the target; entire subnet responds exhausting the target
  - **Fraggle** - same as smurf but with UDP packets
  - **Ping of Death** - fragments ICMP messages; after reassembled, the ICMP packet is larger than the maximum size and crashes the system
  - **Teardrop** - send a large number of garbled IP fragments with oversized and overlapping payload; takes advantage of weakness in fragmentation assembly in older systems; causes crash or reboot
  - **Peer to peer** - clients of peer-to-peer file-sharing hub are disconnected and directed to connect to the target system
  - **Phlashing** - a DoS attack that causes permanent damage to a system; also called __bricking__ a system
  - **LAND attack** - sends a SYN packet to the target with a spoofed IP the same as the target IP; if vulnerable, target loops endlessly and crashes

### Tools

- **Low Orbit Ion Cannon** (LOIC) - DDoS tool that floods a target with TCP, UDP or HTTP requests
- **High Orbit Ion Cannon** (HOIC) - advaced version of LOIC; attacks up to 256 websites simulatneously
- **Stacheldraht** - performs UDP, ICMP, TCP SYN floods and Smurf attacks; combines features of **Trinoo** and **Tribe Flood Network** (TFN); adds encryption between attackers and botnet
- **Trinity** - Linux based DDoS tool
- **Tribe Flood Network** - uses voluntary botnet systems to launch massive flood attacks
- **R-U-Dead-Yet** (RUDY) - DoS with HTTP POST via long-form field submissions; starves a webserver by keeping sessions open as long as possible

### Countermeasures

- Disable unnecessary services
- Using a good firewall policy
- Keep security patches and upgrades up to date
- Use a good NIDS
- Strong security-conscious code
- Tools like Skydance to detect and prevent DoS attacks 
- Network ingress filtering
- Answer to a true DDoS is involvement of ISP (blocks traffic)

## Session Hijacking

- Attacker waits for a session to begin and after the victim authenticates, steals the session for himself

### Steps

1. Sniff the traffic between the client and server
2. Monitor the traffic and predict the sequence numbering
3. Desynchronize the session with the client
4. Predict the session token and take over the session
5. Inject packets to the target server


- Sequence numbers increment on **acknowledgement**; e.g. an acknowledgement number of 105 with a window size of 200 means you could expect sequence numbering from 105 to 305
- Predicting session IDs can be done by knowing the window size and the packet sequence numbers
- Can be done via brute force, calculation or stealing
- Send preconfigured session ID to the target; if clicked, wait for authentication and jump in
- **window size** tells the sender how many outstanding bytes it can have on the network without expecting response

### Tools

- **Ettercap** - man-in-the-middel tool and packet sniffer on steroids
- **Hunt** - sniff, hijack and reset connections
- **T-Sight** - easily hijack sessions and monitor network connections
- **Zaproxy**
- **Paros**
- **Burp Suite**
- **Juggernaut**
- **Hamster**
- **Ferret**

### Countermeasures

- Using unpredictable session IDs (protects against hijacking)
- Limiting incoming connections
- Minimizing remote access
- Regenerating the session key after authentication is complete
- Use IPSec to encrypt

#### IPSec

- Secure IP communication by providing encryption and authentication services to each packet 
- **Transport Mode** - payload and ESP trailer are encrypted; IP header is not; can be used with NAT
- **Tunnel mode** - everything is encrypted; cannot be used with NAT

##### Architecture Protocols

- **Authentication Header** - guarantees the integrity and authentication of IP packet sender; does not provide confidentiality
- **Encapsulating Security Payload** (ESP) - provides origin authenticity and integrity as well as confidentiality; in transport mode integrity and authentication is not provided for the entire IP packet -> headers are not encrypted
- **Internet Key Exchange** (IKE) - produces the keys for the encryption process
- **Oakley** - uses Diffie-Hellman to create master and session keys
- **Internet Security Association Key Management Protocol** (ISAKMP) - software that facilitates encrypted communication between two endpoints

## Other Attacks

- **Watering hole** - goal is to gain access to a machine of one of the target group's members; infecting multiple sites the group members visit to inject members' machines and use that to attack the rest of the group
- **Shellshock** (Bashdoor) - cause Bash to execute arbitary commands and gain unauthorized access to Internet-facing services
- **Wrapping attack** - messaging with SOAP and replaying them as legitimate
- **Logic Bomb** - malware triggered by a programmed condition

### Advanced Persistent Threat (APT)

- is a stealthy threat actor, typically a nation state or state-sponsored group, which gains unauthorized access to a computer network and remains undetected for an extended period

#### Tools

- **THOR** - scanner for APT (Windows only); detects hacking tools and activity
- **SPARK** - like THOR but with less functionality (all platforms)
- **ASGARD** - Linux based management center for THOR and SPARK

## Malewares

- **VAWTRAK** - maleware distributed through spam mails; goal is to steal login credentials (most significantly, for online banking portals) 
