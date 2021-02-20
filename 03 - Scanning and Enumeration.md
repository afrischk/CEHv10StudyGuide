# Scanning and Enumeration

- [Scanning and Enumeration](#scanning-and-enumeration)
  - [Basics](#basics)
  - [UDP](#udp)
  - [TCP](#tcp)
    - [TCP Header](#tcp-header)
    - [TCP Flags](#tcp-flags)
  - [Port Numbers](#port-numbers)
    - [Netstat](#netstat)
    - [TCPView](#tcpview)
  - [Subnetting](#subnetting)
    - [IPv4 Main Address Types](#ipv4-main-address-types)
    - [Subnet mask](#subnet-mask)
    - [Private IP Address Ranges](#private-ip-address-ranges)
  - [Scanning Methodology](#scanning-methodology)
    - [Identifying Targets](#identifying-targets)
      - [Types](#types)
      - [Message Types and Returns](#message-types-and-returns)
      - [Ping scanning tools](#ping-scanning-tools)
    - [Port Scan Types](#port-scan-types)
      - [Full connect](#full-connect)
      - [Stealth](#stealth)
      - [Inverse TCP flag](#inverse-tcp-flag)
      - [Xmas](#xmas)
      - [ACK flag probe](#ack-flag-probe)
      - [IDLE Scan](#idle-scan)
    - [Nmap](#nmap)
    - [Hping](#hping)
    - [Ping (Windows only)](#ping-windows-only)
  - [Evasion](#evasion)
    - [Proxy Chains Tools](#proxy-chains-tools)
    - [Anonymizer Tools](#anonymizer-tools)
    - [OS Fingerprinting](#os-fingerprinting)
      - [Tools](#tools)
    - [IP Address Decoy](#ip-address-decoy)
  - [Vulnerability Scanning](#vulnerability-scanning)
    - [More Tools](#more-tools)
  - [Enumeration](#enumeration)
    - [Windows System Basics](#windows-system-basics)
      - [SID](#sid)
    - [Linux System Basics](#linux-system-basics)
      - [Linux Enumeration Commands](#linux-enumeration-commands)
    - [Banner Grabbing](#banner-grabbing)
    - [NetBIOS Enumeration](#netbios-enumeration)
      - [Command on Windows](#command-on-windows)
      - [Other Tools](#other-tools)
    - [SNMP Enumeration](#snmp-enumeration)
      - [Types of managed objects](#types-of-managed-objects)
      - [Tools](#tools-1)
    - [LDAP Enumeration](#ldap-enumeration)
      - [Tools](#tools-2)
    - [NTP Enumeration](#ntp-enumeration)
      - [Tools](#tools-3)
    - [SMTP Enumerations](#smtp-enumerations)

## Basics

- **Scanning** - Discovering systems on the network and looking at what ports are open as well as applications that may be running
- **Connectionless Communication** - UDP packets are sent without creating a connection.  Examples are TFTP, DNS (lookups only) and DHCP
- **Connection-Oriented Communication** - TCP packets require a connection due to the size of the data being transmitted and to ensure deliverability

## UDP

```
0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|                 |                 |
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|
|          data octets ...
+---------------- ...
```

- Length is the length in octets including header and data (min. 8)

## TCP

### TCP Header

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field                 | Length   | Description                                                                                                                                    |
| --------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Source Port           | 16 bits  | -                                                                                                                                              |
| Destination Port      | 16 bits  | -                                                                                                                                              |
| Sequence Number (SN)  | 32 bits  | SN of the first data octet in this segment. If SYN is set the SN is the ISN and the first data octet is ISN + 1                                |
| Acknowledgment Number | 32 bits  | If ACK is set this field contains the value of the next SN the sender of the segment is expecting. Always sent in established connection       |
| Data Offset           | 4 bits   | The number of 32 bit words in the TCP header. Indicates where the data begins                                                                  |
| Reserved              | 6 bits   | Must be zero                                                                                                                                   |
| Control Bits          | 6 bits   | Flags                                                                                                                                          |
| Window                | 16 bits  | The number of data octets beginning with the one  indicated in the acknowledgement field which the sender of this segment is willing to accept |
| Checksum              | 16 bits  | One's complement checksum of all 16 bit words in header and text                                                                               |
| Urgent Pointer        | 16 bits  | The urgent pointer points to the SN of the octet following the urgent data. Only interpreted if URG is set                                     |
| Options               | variable |                                                                                                                                                |


### TCP Flags

| Flag | Name           | Function                                                                          |
| ---- | -------------- | --------------------------------------------------------------------------------- |
| SYN  | Synchronize    | Set during initial communication.  Negotiating of parameters and sequence numbers |
| ACK  | Acknowledgment | Set as an acknowledgement to the SYN flag.  Always set after initial SYN          |
| RST  | Reset          | Forces the termination of a connection (in both directions)                       |
| FIN  | Finish         | Ordered close to communications                                                   |
| PSH  | Push           | Forces the delivery of data without concern for buffering                         |
| URG  | Urgent         | Data inside is being sent out of band.  Example is cancelling a message           |

## Port Numbers

- **Internet Assigned Numbers Authority** (IANA) - maintains Service Name and Transport Protocol Port Number Registry which lists all port number reservations

| Port Number | Protocol | Transport Protocol |
|-------------|----------|--------------------|
| 20/21       | FTP      | TCP                |
| 22          | SSH      | TCP                |
| 23          | Telnet   | TCP                |
| 25          | SMTP     | TCP                |
| 53          | DNS      | TCP/UDP            |
| 67          | DHCP     | UDP                |
| 69          | TFTP     | UDP                |
| 80          | HTTP     | TCP                |
| 88          | Kerberos |                    |
| 110         | POP3     | TCP                |
| 135         | RPC      | TCP                |
| 137-139     | NetBIOS  | TCP/UDP            |
| 143         | IMAP     | TCP                |
| 161/162     | SNMP     | UDP                |
| 389         | LDAP     | TCP/UDP            |
| 443         | HTTPS    | TCP                |
| 445         | SMB      | TCP                |
| 514         | SYSLOG   | UDP                |
| 631         | IPP/CUPS | TCP/TCP and UDP    |

- **Well-known ports** - 0 - 1023
- **Registered ports** - 1024 - 49,151
- **Dynamic ports** - 49,152 - 65,535
- A service is said to be **listening** for a port when it has that specific port open
- Once a service has made a connection, the port is in an **established** state
- SMB also uses 137 and 138 in UDP and 137 and 139 in TCP

### Netstat

- Shows all connections in one of several states
- `netstat -an` display all (connected) sockets and don't resolve names (numerical form)
- `netstat -b` displays all active connections and the processes using them
- Alternatives: Fport, TCPView and IceSword

### TCPView

- Displays list of active connteions (TCP/UDP)
- `tcpvcon` is the command-line variant
- Updates every second by default
- Windows only

## Subnetting

### IPv4 Main Address Types

- **Unicast** - acted on by a single recipient
- **Multicast** - acted on by members of a specific group
- **Broadcast** - acted on by everyone on the network
  - **Limited** - delivered to every system in the domain (255.255.255.255)
  - **Directed** - delivered to all devices on a subnet and use that broadcast address

### Subnet mask

- Determines how many address available on a specific subnet
- Represented by three methods
  - **Decimal** - 255.240.0.0
  - **Binary** - 11111111.11110000.00000000.00000000
  - **CIDR** - x.x.x.x/12   (where x.x.x.x is an ip address on that range)
- If all the bits in the host field are 1s, the address is the broadcast
- If they are all 0s, it's the network address (subnet address)
- Any other combination indicates an address in the range
- ![img](https://s3.amazonaws.com/prealliance-thumbnails.oneclass.com/thumbnails/001/751/775/original/stringio.txt?1513221790)

### Private IP Address Ranges

- Private IP address ranges are not routable over the internet
- 10.0.0.0 - 10.255.255.255
- 172.16.0.0 - 172.31.255.255
- 192.168.0.0. - 192.168.255.2555

## Scanning Methodology

1. **Check for live systems** - ping or other type of way to determine live hosts
2. **Check for open ports** - once you know live host IPs, scan them for listening ports
3. **Scan beyond IDS** - if needed, use methods to scan  beyond the detection systems
4. **Perform banner grabbing** - grab from servers as well as perform OS fingerprinting
5. **Scan for vulnerabilities** - use tools to look at the vulnerabilities of open systems
6. **Draw network diagrams** - shows logical and physical pathways into networks
7. **Prepare proxies** - obscures efforts to keep you hidden

### Identifying Targets

- The easiest way to scan for live systems is through ICMP
- It has it's shortcomings and is sometimes blocked on hosts that are actually live.
- Payload of an ICMP message can be anything; RFC never set what it was supposed to be.  Allows for covert channels
- An ICMP return of type 3 with a code of 13 indicates a poorly configured firewall
- Nmap virtually always does a ping sweep with scans unless you turn it off

#### Types

- **Internet Key Exchange Scan** (IKE-Scan) - fingerprint VPN servers
- **Ping sweep** - easiest method to identify hosts
- **ICMP Echo scanning** - sending an ICMP Echo Request to the network IP address
- **List scan** - reverse DNS lookup on all IPs in the subnet (machines that where live at some time)

#### Message Types and Returns


| ICMP Message Type           | Description and Codes                                                                                                                                                                                                                                                                                            |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0:  Echo Reply              | Answer to a Type 8 Echo Request                                                                                                                                                                                                                                                                                  |
| 3:  Destination Unreachable | Error message followed by these codes:<br />0 - Destination network unreachable<br />1 - Destination host unreachable<br />6 - Network unknown<br />7 - Host unknown<br />9 - Network administratively prohibited<br />10 - Host administratively prohibited<br />13 - Communication administratively prohibited |
| 4: Source Quench            | A congestion control message                                                                                                                                                                                                                                                                                     |
| 5: Redirect                 | Sent when there are two or more gateways available for the sender to use and the best route available to the destination is not hte configured default gateway.  Followed by these codes:<br />0 - Redirect datagram for the network<br />1 - Redirect datagram for the host                                                                                                                           |
| 8:  Echo Request            | A ping message, requesting an echo reply                                                                                                                                                                                                                                                                         |
| 11:  Time Exceeded          | Packet took too long to be routed (code 0 is TTL expired)                                                                                                                                                                                                                                                        |

#### Ping scanning tools

- Nmap
- Angry IP Scanner
- Solar-Winds Engineer Toolkit
- Advanced IP Scanner
- Pinkie

### Port Scan Types

| Scan Type   | Initial Flags Set             | Open Port Response | Closed Port Response | Notes                                                                                      |
| ----------- | ----------------------------- | ------------------ | -------------------- | ------------------------------------------------------------------------------------------ |
| Full        | SYN                           | SYN/ACK            | RST                  | Noisiest but most reliable                                                                 |
| Stealth     | SYN                           | SYN/ACK            | RST                  | No completion of 3-way handshake; designed for stealth but may be picked up on IDS sensors |
| XMAS        | FIN, URG and PSH              | No response        | RST                  | Doesn't work on Windows machines                                                           |
| Inverse TCP | FIN, URG or PSH (or no flags) | No response        | RST/ACK              | Doesn't work on Windows machines                                                           |

#### Full connect

- TCP connect or full open scan
- full connection and then tears down with RST
- Easiest to detect, but most reliable
- `nmap -sT`

#### Stealth

- half-open scan or SYN scan
- only SYN packets sent
- responses same as full.
- Useful for hiding efforts and evading firewalls
- `nmap -sS`  

#### Inverse TCP flag

- Uses FIN, URG or PSH flag
- Open gives no response
- Closed gives RST/ACK
- `nmap -sN` (Null scan)
- `nmap -sF` (FIN scan)

#### Xmas

- So named because all flags are turned on so it's "lit up" like a Christmas tree
- Responses are same as Inverse TCP scan
- Do not work against Windows machines
- `nmap -sX`

#### ACK flag probe

- Multiple methods
- **TTL version** - if TTL of RST packet &lt 64, port is open
- **Window version** - if the Window on the RST packet is anything other than 0, port open
- Can be used to check filtering.  If ACK is sent and no response, stateful firewall present.
- `nmap -sA (ACK scan)`
- `nmap -sW (Window scan)`

#### IDLE Scan

- uses a third party to check if a port is open
- Looks at the IPID to see if there is a response
- Only works if third party isn't transmitting data
- Sends a request to the third party to check IPID id; then sends a spoofed packet to the target with a return of the third party; sends a request to the third party again to check if IPID increased.
  - IPID increase of 1 indicates port closed
  - IPID increase of 2 indicates port open
  - IPID increase of anything greater indicates the third party was not idle
- `nmap -sI <zombie host>`

### Nmap

- Nmap runs by default at a T3 level
- **Fingerprinting** - another word for port sweeping and enumeration
- Nmap script **http-methods** finds out what options are supported by an HTTP server by sending an OPTIONS request
- `nmap <scan options> <target>`
- `nmap [host]` - returns TCP port information; scans 1000 TCP ports

| Switch                        | Description                                                     |
| ----------------------------- | --------------------------------------------------------------- |
| -sA                           | ACK scan                                                        |
| -sF                           | FIN scan                                                        |
| -sI                           | IDLE scan                                                       |
| -sL                           | DNS scan (list scan)                                            |
| -sN                           | NULL scan                                                       |
| -sO                           | Protocol scan (tests which IP protocols respond)                |
| -sP                           | Ping scan                                                       |
| -sR                           | RPC scan                                                        |
| -sS                           | SYN scan                                                        |
| -sT                           | TCP connect scan                                                |
| -sW                           | Window scan                                                     |
| -sX                           | XMAS scan                                                       |
| -sC                           | Same as `--script=default`                                      |
| -p                            | Scan specific ports `-p T:21,80-85`                             |
| -A or -sV -sC -O --traceroute | OS detection, version detection, script scanning and traceroute |
| -PI                           | ICMP ping                                                       |
| -Pn                           | No ping (-PN, -P0 in previous versions)                         |
| -PS                           | SYN ping                                                        |
| -PT                           | TCP ping                                                        |
| -oN                           | Normal output                                                   |
| -oX                           | XML output                                                      |
| -T0 through -T2               | Serial scans.  T0 is slowest                                    |
| -T3 through -T5               | Parallel scans.  T3 is slowest                                  |

### Hping

- Another powerful ping sweep and port scanning tool
- Also can craft packets
- `hping3 -1 IPaddress`

| Switch  | Description                                                         |
| ------- | ------------------------------------------------------------------- |
| -1      | Sets ICMP mode                                                      |
| -2      | Sets UDP mode                                                       |
| -8      | Sets scan mode.  Expects port range without -p flag                 |
| -9      | Listen mode.  Expects signature (e.g. HTTP) and interface (-I eth0) |
| -c      | Count packets                                                       |
| --flood | Sends packets as fast as possible without showing incoming replies  |
| -Q      | Collects sequence numbers generated by the host                     |
| -p      | Sets port number                                                    |
| -F      | Sets the FIN flag                                                   |
| -S      | Sets the SYN flag                                                   |
| -R      | Sets the RST flag                                                   |
| -P      | Sets the PSH flag                                                   |
| -A      | Sets the ACK flag                                                   |
| -U      | Sets the URG flag                                                   |
| -X      | Sets the XMAS scan flags                                            |

### Ping (Windows only)

| Switch | Description                                                   |
|--------|---------------------------------------------------------------|
| -l     | set the size of the echo request packet (32 bytes is default) |
| -s     | timestamp for count hops                                      |
| -a     | resolve addresses to hostnames                                |
| -t     | continue ping until stop                                      |

## Evasion

- To evade IDS, sometimes you need to change the way you scan
- One method is to fragment packets (`nmap -f` switch)
- **Spoofing** - can only be used when you don't expect a response back to your machine
- **Source routing** - specifies the path a packet should take on the network; most systems don't allow this anymore
- **Proxy** - hides true identity by filtering through another computer.  Also can be used for other purposes such as content blocking evasion, etc.
- **Proxy chains** - chaining multiple proxies together
- **Tor** - a specific type of proxy that uses multiple hops to a destination; endpoints are peer computers
- **Anonymizers** - hides identity on HTTP traffic (port 80) via proxy

### Proxy Chains Tools

- Proxy Switcher
- Proxy Workbench
- ProxyChains

### Anonymizer Tools

- Guardster
- Ultrasurf
- Psiphon
- Tails (live OS)

### OS Fingerprinting

- **Active**  - sending crafted packets to the target
- **Passive** - sniffing network traffic for things such as __TTL fields__, __TCP window sizes__, __Don't Fragment (DF) flags__ and __Type of Service (ToS) fields__

#### Tools

- **pOf** - passive OS fingerprinting tool

### IP Address Decoy

- sends packets from your IP as well as multiple other decoys to confuse the IDS/Firewall as to where the attack is really coming from
- `nmap -D RND:10 x.x.x.x`
- `nmap -D decoyIP1,decoyIP2....,sourceIP,.... [target]`


## Vulnerability Scanning

- Can be complex or simple tools run against a target to determine vulnerabilities
- Industry standard is Tenable's Nessus

### More Tools

  - GFI LanGuard
  - Qualys
  - FreeScan - best known for testing websites and applications
  - OpenVAS - best competitor to Nessus and is free

## Enumeration

- Defined as listing the items that are found within a specific target
- Always is active in nature

### Windows System Basics

- Everything runs within context of an account
- **Security Context** - user identity and authentication information
- **Security Identifier** (SID) - identifies a user, group or computer account
- **Resource Identifier** (RID) - portion of the SID identifying a specific user, group or computer
- **SAM Database** - file where all local passwords are stored (encrypted). Location: `C:\Windows\System 32\Config\SAM`

#### SID

- SIDs are composed of an S, followed by a revision number, an authority value, a domain or a computer indicator and a RID
- Example SID: S-1-5-21-3874928736-367528774-1298337465-**500**
- **Administrator Account** - RID of 500
- **Guest Account** - RID of 501
- **Regular Accounts** - start with a RID of 1000

### Linux System Basics

**Linux Systems** used user IDs (UID) and group IDs (GID).  Location: `/etc/passwd`

#### Linux Enumeration Commands

- **finger** - info on user and host machine
- **rpcinfo and rpcclient** - info on RPC in the environment
- **showmount** - displays all shared directories on the machine
  

### Banner Grabbing

- **Active** - sending specially crafted packets and comparing responses to determine OS
- **Passive** - reading error messages, sniffing traffic or looking at page extensions
- Easy way to banner grab is connect via telnet on port (e.g. 80 for web server) `telnet <IPaddress> <port number>`
- Telnet request: `Method Request-Uri Http-Version CRLF`
- **Netcat** can also be used to banner grab `nc <IPaddress or FQDN> <port number>`
- Can be used to get information about OS or specific server info (such as web server, mail server, etc.)

### NetBIOS Enumeration

- Network Basic Input/Output System
- NetBIOS provides name servicing, connectionless communication and some session layer stuff
- The browser service in Windows is designed to host information about all machines within domain or TCP/IP network segment
- NetBIOS name is a **16-character ASCII string** used to identify devices
- NetBIOS name resolution doesn't work on IPv6

| Code | Type   | Meaning                   |
| ---- | ------ | ------------------------- |
| <1B> | UNIQUE | Domain master browser     |
| <1C> | UNIQUE | Domain controller         |
| <1D> | GROUP  | Master browser for subnet |
| <00> | UNIQUE | Hostname                  |
| <00> | GROUP  | Domain name               |
| <03> | UNIQUE | Service running on system |
| <20> | UNIQUE | Server service running    |


#### Command on Windows

```
nbtstat (gives your own info)
nbtstat -n (gives local table)
nbtstat -A IPADDRESS (gives remote information)
nbtstat -c (gives cache information)
```

 
#### Other Tools

- SuperScan
- Hyena
- NetBIOS Enumerator
- NSAuditor

### SNMP Enumeration

- Desgined to manage IP-enabled devices across network
- Works like dispatch center and consists of manager and agents
- **Management Information Base** (MIB) - database that stores information
- **Object Identifiers** (OID) - identifiers for information stored in MIB
- **SNMP GET** - gets information about the system
- **SNMP SET** - sets information about the system
- MIB entries identify the device, the OS installed and usage statistics
- SNMP uses **community strings** which function as passwords
- There is a _read-only_ and a _read-write_ version
- Default read-only string is **public** and default read-write is **private**
- These are sent in cleartext unless using SNMP v3

#### Types of managed objects

- **Scalar** - single object
- **Tabular** - multiple related objects that can be grouped together
 
#### Tools

- Engineer's Toolset
- SNMPScanner
- OpUtils 5
- SNScan


### LDAP Enumeration

- Lightweight Directory Access Protocol (LDAP)
- Connects on port 389 to a **Directory System Agent** (DSA)
- Returns information such as valid user names, domain information, addresses, telephone numbers, system data, organization structure and other items using **Basic Encoding Rules** (BER)

#### Tools

- Softerra
- JXplorer
- Lex
- LDAP Admin Tool

### NTP Enumeration

- Network Time Protocol (NTP) sets time across network
- Runs on UDP with port 123
- Querying can give you list of systems connected to the server (name and IP)
- **Commands** include `ntptrace`, `ntpdc` and `ntpq`

#### Tools

- NTP Server Scanner
- AtomSync
- Can also use Nmap and Wireshark

### SMTP Enumerations

- Simple Mail Transfer Protocol (SMTP)
- `VRFY` validates user
- `EXPN` provides actual delivery address of mailing list and aliases
- `RCPT TO` defines recipients
- servers respond different to theses commands
- responses can tell us which are valid and invalid user names
