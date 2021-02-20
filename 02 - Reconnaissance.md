# Reconnaissance

- [Reconnaissance](#reconnaissance)
  - [Footprinting](#footprinting)
    - [Types](#types)
    - [Four Main Focuses](#four-main-focuses)
  - [Methods and Tools](#methods-and-tools)
    - [Search Engines](#search-engines)
    - [Website Footprinting](#website-footprinting)
      - [Webmirroring Tools](#webmirroring-tools)
    - [Email Footprinting](#email-footprinting)
    - [DNS Footprinting](#dns-footprinting)
      - [DNS Ports](#dns-ports)
      - [DNS Record Types](#dns-record-types)
      - [SOA Reord Fields](#soa-reord-fields)
      - [IP Address Management](#ip-address-management)
      - [DNS Tools](#dns-tools)
        - [nslookup](#nslookup)
        - [Dig](#dig)
    - [Network Footprinting](#network-footprinting)
      - [Network Foorprinting Tools](#network-foorprinting-tools)
    - [Other Tools](#other-tools)
      - [OSRFramework](#osrframework)
      - [Web Spiders](#web-spiders)
      - [Shodan](#shodan)
      - [Competitive Intelligence Tools](#competitive-intelligence-tools)
      - [Social Engineering Tools](#social-engineering-tools)
      - [Deepmagic Information Gathering Tool (DMitry)](#deepmagic-information-gathering-tool-dmitry)

## Footprinting

- Looking for high-level information on a target.
- **Competitive Intelligence**- Information gathered by businesses about competitors

### Types

- **Anonymous** - information gathering without revealing anything about yourself
- **Pseudonymous** - making someone else take the blame for your actions
- **Active** - requires attacker to touch the device or network (Social engineering and other communication that requires interaction with target)
- **Passive** - measures to collect information from publicly available sources (Websites, DNS records, business information databases)

### Four Main Focuses

- Know the security posture
- Reduce the focus area
- Identify vulnerabilities
- Draw a network map

## Methods and Tools

- **Alexa.com** - Resource for statistics about websites

### Search Engines

- **NetCraft** - information about website, restricted URLs and possibly OS info
- **Job Search Sites** - information about technologies can be gleaned from job postings
- **Metagoofil** - uses Google hacks to search for public available documents and extracts metadata from it
- **Google** 

| **Google Operators** |                                              |
| -------------------- | -------------------------------------------- |
| filetype             | looks for file types                         |
| index of             | directory listings                           |
| info                 | contains Google's information about the page |
| intitle              | string in title                              |
| inurl                | string in url                                |
| link                 | finds linked pages                           |
| related              | finds similar pages                          |
| site                 | finds pages specific to that site            |

### Website Footprinting

- **Archive.org** - Provides cached websites from various dates which possibly have sensitive information that has been now removed
- **Web mirroring** - Allows for discrete testing offline

#### Webmirroring Tools

- HTTrack
- Black Widow
- Wget
- WebRipper
- Teleport Pro
- Backstreet Browser


### Email Footprinting

- **Email  header** - May show servers and where the location of those servers are
- **Email tracking** - Services can track various bits of information including the IP address of where it was opened, where it went, etc.

### DNS Footprinting

- **Zone transfer** - replicates all records
- **Name resolvers** - answer requests
- **Authoritative Servers** - hold all records for a namespace
- **DNS Poisoning/DNS Spoofing** - changes cache on a machine to redirect requests to a malicious server
- **DNSSEC** - helps prevent DNS poisoning by encrypting records

#### DNS Ports

- **Name lookup** - UDP 53
- **Zone transfer** - TCP 53

####  DNS Record Types

| Name  | Description        | Purpose                                                                 |
| ----- | ------------------ | ----------------------------------------------------------------------- |
| SRV   | Service            | Defines Hostname and port number of servers providing specific services |
| SOA   | Start of Authority | Indicates the authoritative NS for a namespace                          |
| PTR   | Pointer            | Maps an IP to a hostname (reverse lookups)                              |
| NS    | Nameserver         | Lists the nameservers for a namespace                                   |
| MX    | Mail Exchange      | Lists email servers                                                     |
| CNAME | Canonical Name     | Maps a name to an A reccord                                             |
| A     | Address            | Maps an hostname to an IP address                                       |

#### SOA Reord Fields

- **Source Host** - hostname of the primary DNS
- **Contact Email** - email for the person responsible for the zone file
- **Serial Number** - revision number that increments with each change
- **Refresh Time** - time in which an update should occur (default: 3600 sec)
- **Retry Time** - time that a NS should wait on a failure (default: 600s sec)
- **Expire Time** - time in which a zone transfer is allowed to complete (default: 86400 sec)
- **TTL** - minimum TTL for records within the zone (default: 3600 sec)

#### IP Address Management

- **ARIN** - North America
- **APNIC** - Asia Pacific
- **RIPE** - Europe, Middle East
- **LACNIC** - Latin America
- **AfriNIC** - Africa

#### DNS Tools

- **Whois** - Obtains registration information for the domain

##### nslookup

Performs DNS queries.

| Option               | Description                                                   |
| -------------------- | ------------------------------------------------------------- |
| ls -d or ls -t ANY   | Initiates a zone transfer                                     |
| ls -a or ls -t CNAME | Lists aliases of computers in the DNS domain                  |
| ls -h or ls -t HINFO | Lists CPU and operating system information for the DNS domain |
| ls -s or ls -t WKS   | Lists well-known services of computers in the DNS domain      |

```sh
nslookup [ - options ] [ hostname ]
```
Interactive zone transfer:

```sh
nslookup
server <IP Address>
set type = any
ls -d domainname.com
```
DNS cache snooping:

```sh
nslookup - norecursive example.com
```

##### Dig  

Unix-based command like nslookup.

```sh
dig @server name type
```

### Network Footprinting

IP address range including the technical point of contact (POC) can be obtained from regional registrar (ARIN here).

#### Network Foorprinting Tools

- NeoTrace
- VisualRoute
- Trout
- Magic NetTrace
- Network Pinger
- GEO Spider
- Ping Plotter

**traceroute/tracert**

- Use `traceroute` to find intermediary servers, route path and transit times
- Time-to-live (TTL) on each paket is inceremeted by one after each hop
- Returns name and IP address
- Time outs because of firewall
  - Type 11, Code 0 (TTL expired)
  - Type 3, Code 13 (Administratively Blocked)
- Linux Command - `traceroute` uses UDP datagrams
- Windows command - `tracert` uses ICMP echo

### Other Tools

#### OSRFramework  

Set of libraries used to perform open source intelligence to get information about target. Data to find: user name, domain, phone number, DNS lookups, information leaks research, deep web search, etc...

- **usufy.py** - verifies if a username/profile exists in up to 306 different platforms
- **mailfy.py** - checks if a username(e-mail) has been registered in up to 22 e-mail providers
- **searchfy.py** - looks for profile using full names and other info in 7 platforms. Queries the OSRFramework platforms itself
- **domainfy.py** - verifies the existence of a given domain in up to 1567 different registries
- **phonefy.py** - checks the existence of phone numbers
- **entify.py** - looks for regular expressions

#### Web Spiders  
Obtain information from the website such as pages, etc.

#### Shodan  
Search engine that shows devices connected to the Internet

#### Competitive Intelligence Tools

- Google Alterts
- Yahoo! Site Explorer
- SEO for Firefox
- SpyFu
- Quarkbase
- DomainTools.com
  
#### Social Engineering Tools

- **Maltego** - Open source intelligence and forensics application
- **Social Engineering Framework (SEF)** - Has ties into Metasploit. Automates extracting emails and preperation for social engineering attacks.



#### Deepmagic Information Gathering Tool (DMitry)

- A Unix/Linux command-line network scanner
- Able to gather possible subdomains, email addresses, uptime information, tcp port scan, whois lookups, and more