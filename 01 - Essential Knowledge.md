# Essential Knowledge

- [Essential Knowledge](#essential-knowledge)
  - [The OSI Reference Model](#the-osi-reference-model)
  - [TCP/IP Model](#tcpip-model)
  - [TCP Handshake](#tcp-handshake)
  - [Ethernet frame](#ethernet-frame)
  - [Protocols](#protocols)
    - [Network Time Protocol (NTP)](#network-time-protocol-ntp)
    - [Border Gateway Protocol (BOP)](#border-gateway-protocol-bop)
  - [Network Address Translation (NAT)](#network-address-translation-nat)
  - [Network Security Zones](#network-security-zones)
  - [Vulnerabilities](#vulnerabilities)
    - [Categories](#categories)
    - [Vulnerability Management Tools](#vulnerability-management-tools)
  - [Terms to Know](#terms-to-know)
  - [Threat Modeling](#threat-modeling)
  - [Risk Management](#risk-management)
    - [Risk Equation](#risk-equation)
  - [Incident Handling](#incident-handling)
  - [Security Development Lifecycle (SDL)](#security-development-lifecycle-sdl)
  - [Security Controls](#security-controls)
    - [Categories](#categories-1)
  - [Business Analysis](#business-analysis)
  - [CIA Triad](#cia-triad)
  - [Access Control Types](#access-control-types)
  - [Document Types](#document-types)
  - [Policies](#policies)
    - [Types](#types)
    - [Categories](#categories-2)
  - [The Hackers](#the-hackers)
    - [The Hats](#the-hats)
  - [Attack Types](#attack-types)
  - [Hacking Phases](#hacking-phases)
    - [Types of Reconnaissance](#types-of-reconnaissance)
  - [Security Incident and Event Management (SIEM)](#security-incident-and-event-management-siem)
  - [Penetration Test](#penetration-test)
    - [Phases](#phases)
    - [Types](#types-1)
  - [Laws and Standards](#laws-and-standards)
    - [NIST-800-53](#nist-800-53)
      - [Steps](#steps)
    - [NIST SP 800-30](#nist-sp-800-30)
      - [Steps](#steps-1)
    - [ISO 27002 (ISO 17799)](#iso-27002-iso-17799)
    - [ISO 27001](#iso-27001)
    - [FISMA](#fisma)
    - [FITARA](#fitara)
    - [HIPAA](#hipaa)
    - [PCI-DSS](#pci-dss)
      - [Requirements](#requirements)
    - [COBIT](#cobit)
    - [SOX](#sox)
    - [GLBA](#glba)
    - [ITIL](#itil)
    - [TCSEC](#tcsec)
    - [TNIEG](#tnieg)
  - [OSSTM](#osstm)
    - [Compliance Types](#compliance-types)
    - [OSSTM Class A - Interactive Controls](#osstm-class-a---interactive-controls)
    - [OSSTM Class B - Process Controls](#osstm-class-b---process-controls)
  - [Common Criterial for Information Technology Security Evaluation](#common-criterial-for-information-technology-security-evaluation)

## The OSI Reference Model

| Layer | Description  | Technologies    | Data Unit |
| ----- | ------------ | --------------- | --------- |
| 1     | Physical     | USB, Bluetooth  | Bit       |
| 2     | Data Link    | ARP, PPP, STP   | Frame     |
| 3     | Network      | IP              | Packet    |
| 4     | Transport    | TCP             | Segment   |
| 5     | Session      | X255, SCP, SOCKS| Data      |
| 6     | Presentation | AFP, MIME       | Data      |
| 7     | Application  | FTP, HTTP, SMTP | Data      |

## TCP/IP Model

| Layer | Description    | OSI Layer Equivalent |
| ----- | -------------- | -------------------- |
| 1     | Network Access | 1 & 2                |
| 2     | Internet       | 3                    |
| 3     | Transport      | 4                    |
| 4     | Application    | 5 - 7                |

## TCP Handshake

SYN -> SYN-ACK -> ACK

1. SYN=1, ACK=0, ISN=2000
2. SYN=1, ACK=1, ISN=5000, ACK NO=2001
3. SYN=0, ACK=1, SEQ NO=2001, ACK NO=5001

## Ethernet frame

```
0                   1                   2                            
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 . . . . . . . .0 1 2 3 4
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-||-+-+-+-+-+-+-+-+
|  Preamble   |S| Dest Addr | Src Addr  |L/T|    Da || ta   |   FCS  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-||-+-+-+-+-+-+-+-+
```

| Field                       | Length          |
| --------------------------- | --------------- |
| Preamble                    | 7 Bytes         |
| Start Frame Delimiter (SFD) | 1 Byte          |
| Destionation Address        | 6 Bytes         |
| Source Address              | 6 Bytes         |
| Length/Type                 | 2 Bytes         |
| Data                        | 46 - 1500 Bytes |
| Frame Check Sequence (FCS)  | 4 Bytes         |

## Protocols

- **Spanning Tree Protocol** (STP) - a network protocol that builds a loop-free logical topology for Ethernet networks

### Network Time Protocol (NTP)

- A networking protocol for clock synchronization between computer systems over packet-switched, variable-latency data networks
- NTPv3 supports DES encryption for message integrity and authentication

### Border Gateway Protocol (BOP)

- Routing protocol
- Transports routed protocol and determines the best path to a destination network
- Exterior Gateway Protocol which connects router to on or more ISPs
- Others are: EIGRP, RIP, IS-IS and OSPF

## Network Address Translation (NAT)

- **dynamic NAT** - many-to-many mapping; a pool of public IP addresses is assigned to private IP addresses on a as-needed basis
- **static NAT** - one-to-one mapping
- **NAT overload** - also called **Port Address Transalation** PAT; many-to-one (one public IP) mapping over ports

## Network Security Zones

 - **Internet** - uncontrollable
 - **Internet DMZ** - controlled buffer network; web servers often placed here
 - **Production Network Zone** - very restricted; controls direct access from uncontrolled zones; has no users
 - **Intranet Zone** - controlled; has little to no heavy restriction
 - **Management Network Zone** - might find VLANs and IPSEC; highly secured; strict policies

## Vulnerabilities

- **Common Vulnerability Scoring System** (CVSS) - places numerical score based on severity
- **National Vulnerability Database** (NVD) - US government repository of vulnerabilities

### Categories

- **Misconfiguration** - improperly configuring a service or application
- **Default installation** - failure to change settings in an application that come by default
- **Buffer overflow** - code execution flaw
- **Missing patches** - systems that have not been patched
- **Design flaws** - flaws inherent to system design such as encryption and data validation
- **Operating System Flaws** - flaws specific to each OS
- **Default passwords** - leaving default passwords that come with system/application

### Vulnerability Management Tools

- Nessus
- Qualys
- GFI Languard
- Nikto
- OpenVAS
- Retina CS

## Terms to Know

- **Hack value** - perceived value or worth of a target as seen by the attacker
- **Zero-day attack** - attack that occurs before a vendor knows or is able to patch a flaw
- **Doxing** - searching for and publishing information about an individual usually with a malicious intent
- **Enterprise Information Security Architecture** (EISA) - process that determines how systems work within an organization
- **Incident management** - deals with specific incidents to mitigate the attack
- **Daisy-chaining** - gaining access to a network/computer to get options to gain access to multiple networks/computers
- **User Behavior Analysis** (UBA) - tracking users and extrapolating data in light of malicious activity
- **Bit flipping** - is an example of an <u>integrity</u> attack.  The outcome is not to gain information - it is to obscure the data from the actual user.
- **Infowar** - the use of offensive and defensive techniques to create an advantage
- **Computer Security Incident Response Team** (CSIRT) - point of contact for all incident response services for associates of the DHS

## Threat Modeling

1. Identify security objectives
2. Application Overview
3. Decompose application
4. Identify threats
5. Identify vulnerabilities

## Risk Management

1. Risk identification
2. Risk assessment
3. Risk treatment
4. Risk tracking
5. Risk review

Uses risk analysis matrix to determine threat level (X: Impact, Y: Probability)

### Risk Equation

```
Risk = Threat x Vulnerability x Cost
```

- **Threat** - rate of potential negative event
- **Vulnerability** - the likelihood that a vulnerability will be exploited and a threat will succeed against an organization’s defenses
- **Cost** - measure of the total financial impact of a security incident

## Incident Handling

1. Identification (discovery)
2. Containment (limitation)
3. Eradication (get rid of inicdent)
4. Recovery
5. Lessons learned

## Security Development Lifecycle (SDL)

1. Training (security training for developers)
2. Requirements (set level of security desired)
3. Design
4. Implementation
5. Verification (dynamic analysis, fuzz testing, attack surface reviews, etc...)
6. Release
7. Response

## Security Controls

### Categories

- **Physical** -  Guards, lights, cameras
- **Technical**(logical) -  Encryption, smart cards, access control lists
- **Administrative** -  Training awareness, policies

| Types        | Example                                                               | Description                                                                         |
| ------------ | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Preventative | authentication, alarm bells, encryption                               | used to stop potential attacks by preventing users from performing specific actions |
| Detective    | audits, backups, IDS's, CCTV                                          | used to monitor and alert on malicious or unauthorized activity                     |
| Corrective   | restore operations, AntiVirus, IPS (detective AND corrective)         | used to repair damage caused by malicious events                                    |
| Directive    | security policies, operations plans, guidelines                       | used to deal with company procedures (procedural control)                           |
| Deterrent    | signs that warn possible attackers about alarm systems and monitoring | used to dissuade potential attackers                                                |
| Compensating | admin reviewing logs for violations of policy                         | used to supplement directive controls                                               |
| Recovery     |                                                                       |                                                                                     |

## Business Analysis

- Business Impact Analysis (BIA)
  - Maximum Tolerable Downtime (MTD)
- Business Continuity Plan (BCP)
  - Disaster Recovery Plan (DRP)
- Annualized Loss Expectancy (ALE)
  - Annual Rate of Occurrence (ARO)
  - Single Loss Expectancy (SLE)
```
ALE = SLE * ARO
```

## CIA Triad

- **Confidentiality** - passwords, encryption
- **Integrity** - hashing, digital signatures
- **Availability** - anti-dos solutions

## Access Control Types

- **Mandatory** (MAC) - access is set by an administrator
- **Discretionary** (DAC) - allows users to give access to resources that they own and control

## Document Types

- **Policy** - document describing the security controls implemented
- **Standards** - mandatory rules to achieve consistency
- **Baselines** - provide the minimum security necessary
- **Guidelines** - flexible or recommended actions
- **Procedures** - step by step instructions

## Policies

### Types

- **Access Control** - what resources are protected and who can access them
- **Information Security** - what can systems be used for
- **Information Protection** - defines data sensitivity levels
- **Password** - all things about passwords (how long, characters required, etc.)
- **E-Mail** - proper and allowable use of email systems
- **Information Audit** - defines the framework used for auditing

### Categories

- **Promiscuous** - wide open
- **Permissive** - blocks only known dangerous things
- **Prudent** - blocks most and only allows things for business purposes
- **Paranoid** - locks everything down

## The Hackers

- **Hacktivist** - someone who hacks for a cause
- **Suicide Hackers** - do not case about any impunity to themselves; hack to get the job done
- **Cyberterrorist** - motivated by religious or political beliefs to create fear or disruption
- **State-Sponsored Hacker** - hacker that is hired by a government
- **Script Kiddie** - uneducated in security methods, but uses tools that are freely available to perform malicious activities
- **Phreaker** - manipulates telephone systems
- **Ethical** - employs tools that hackers use with permission only; always obtains an agreement from the client with specific objectives <u>before</u>
- **Cracker** - uses tools for personal gain or destructive purpose

### The Hats

- **White Hat** -  ethical hackers
- **Black Hat** -  hackers that seek to perform malicious activities
- **Gray Hat** -  hackers that perform good or bad activities but do not have the permission of the organization they are hacking against

## Attack Types

- **Operating System** (OS) - attacks targeting OS flaws or security issues inside such as guest accounts or default passwords
- **Application Level** - attacks on programming code and software logic
- **Shrink-Wrap Code** - attack takes advantage of built-in code or scripts
- **Misconfiguration** - attack takes advantage of systems that are misconfigured due to improper configuration or default configuration

## Hacking Phases

1. **Reconnaissance** (footprinting) - gathering evidence about targets
2. **Scanning & Enumeration** - obtaining more in-depth information about targets
3. **Gaining Access** - attacks are leveled in order to gain access to a system
4. **Maintaining Access** - items put in place to ensure future access
5. **Covering Tracks** - steps taken to conceal success and intrusion

### Types of Reconnaissance

- **Passive** - gathering information about the target without their knowledge
- **Active** - uses tools and techniques that may or may not be discovered

## Security Incident and Event Management (SIEM)

- Functions related to a **Security Operations Center** (SOC): Identifying, Monitoring, Recording, Auditing, Analyzing

## Penetration Test

Clearly defined, full scale test of security controls.

### Phases

- **Preparation** - contracts and team determined
- **Assessment** - all hacking phases (reconnaissance, scanning, attacks, etc.)
- **Post-Assessment** - reports & conclusions

### Types
- **Black Box** - done without any knowledge of the system or network
- **White Box** - complete knowledge of the system
- **Gray Box** - has some knowledge of the system and/or network

## Laws and Standards

| Categories   |                                                                     |
| ------------ | ------------------------------------------------------------------- |
| **Criminal** | laws that protect public safety and usually have jail time attached |
| **Civil**    | private rights and remedies                                         |
| **Common**   | laws that are based on societal customs                             |


### NIST-800-53  

- Catalogs security and privacy controls for federal information systems, created to help implementation of FISMA; except those related to national security
- Defines nine steps in risk assessments

#### Steps

1. Purpose, scope and source identification
2. Threat identification
3. Vulnerability identification
4. Control analysis
5. Likelihood determination
6. Impact analysis
7. Risk determination
8. Sharing risk assessment information
9. Maintaining the risk assessment Step 3 determines whether any flaws exist in a company's systems or policies

### NIST SP 800-30

- provides guidance for conducting risk assessments of federal information systems and organizations

#### Steps

1. Purpose/Scope
2. Threat identification
3. Vulnerability identification
4. Likelihood determination
5. Impact analysis
6. Risk determination
7. Communicating and sharing risk assessment information
8. Maintain the risk assessment


### ISO 27002 (ISO 17799)

Based on 1st part of BS7799 but focuses on security objectives and provides security controls based on industry best practice

### ISO 27001

- Security standard based on the 2nd part of BS7799 and is focused on security governance
- Governance is the process of directing and controlling IT security
- Defines a standard for creating an **Information Security Management System** (ISMS)

### FISMA

- Federal Information Security Modernization Act Of 2002
- A law updated in 2014 to codify the authority of the **Department of Homeland Security** (DHS) with regard to implementation of information security policies

### FITARA

 - Federal Information Technology Acquisition Reform Act
 - A 2013 bill that was intended to change the framework that determines how the US GOV purchases technology

### HIPAA

- Health Insurance Portability and Accountability Act
- A law that set's privacy standards to protect patient medical records and health information shared between doctors, hospitals and insurance providers

### PCI-DSS

- Payment Card Industry Data Security Standard
- Standard for organizations handling Credit Cards, ATM cards and other POS cards
- Pen testing once a year and after any significant change
- Weekly file integrity scans
- Quarterly vunerability scans

#### Requirements

1. Install and maintain a firewall configuration to protect cardholder data
2. Do not use vendor supplied defaults for system passwords and other security parameters
3. Protect stored cardholder data
4. Encrypt transmission of cardholder data across open pulbic networks
5. Use and regulary update antivirus software and programms
6. Develop and maintain secure systems and software
7. Restrict access to cardholder data by business need to know
8. Assign a unique ID to each person with computer access
9. Restrict physical access to cardholder data
10. Track and monitor all access to network resources and cardholder data
11. Regulary test security systems and processes
12. Maintain a policy that addresses information security for all personnel

### COBIT

- Control Object for Information and Related Technology
- IT Governance framework and toolset, created by ISACA and ITGI
- Enables clear policy development, good practice and emphasizes regulatory compliance.

### SOX

- Sarbanes-Oxley Act
- Law that requires publicly traded companies to submit to independent audits and to properly disclose financial information
- It was created to make corporate disclosures more accurate and reliable in order to protect the public and investors from shady behavior.

### GLBA

- U.S Gramm-Leach-Bliley Act
- Law that protects the confidentiality and integrity of personal information that is collected by financial institutions.

### ITIL

- Information Technology Infrastructure Library
- An operational framework developed in the '80s that standardizes IT management procedures

### TCSEC

- Trusted Computer System Evaluation Criteria
- Security evaluation standard was created by the DoD to define types of access controls
- Guidance on evaluating the effectiveness of computer security controls

### TNIEG

- Trusted Network Interpretation Environments Guideline
- Outlines minimum security protections required in network environments

## OSSTM

- Open Source Security Testing Methodology Manual
- Maintained by ISECOM , defines three types of compliance.

### Compliance Types

- **Legislative** - Deals with government regulations (Such as SOX and HIPAA)
- **Contractual** - Deals with industry / group requirements (Such as PCI DSS)
- **Standards based** - Deals with practices that must be followed by members of a given group/organization (Such as ITIL, ISO and OSSTMM itself)

### OSSTM Class A - Interactive Controls

- **Authentication** - Provides for identification and authorization based on credentials
- **Indemnification** - Provided contractual protection against loss or damages
- **Subjugation** - Ensures that interactions occur according to processes defined by the asset owner
- **Continuity** - Maintains interactivity with assets if corruption of failure occurs
- **Resilience** - Protects assets from corruption and failure

### OSSTM Class B - Process Controls

- **Non-repudiation** - Prevents participants from denying its actions
- **Confidentiality** - Ensures that only participants know of an asset
- **Privacy** - Ensures that only participants have access to the asset
- **Integrity** - Ensures that only participants know when assets and processes change
- **Alarm** - Notifies participants when interactions occur

## Common Criterial for Information Technology Security Evaluation

- Routinely called "Common Criteria" (CC)
- International standard of evaluation of Information Technology
- Helps to remove vulnerabilities in products before they are released
- **Evaluation Assurance Level** (EAL) - the numerical rating describing the depth and rigor of an evaluation; goes from level 1 - 7
- **Target of Evaluation** (TOE) - system that is the subject of the evaluation
- **Security Target** (ST) - the document that identifies the security properties of the TOE; the TOE is evaluated against the SFRs established in its ST
- **Protection Profile** (PP) - a document that identifies security requirements for a class of security devices
- **Security Assurance Requirements** (SAR) - descriptions of the measures taken during development and evaluation of the product to assure compliance with the claimed security functionality
- **Security Functional Requirements** (SFR) - specify individual security functions which may be provided by a product