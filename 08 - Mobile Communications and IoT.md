# Mobile Communications and IoT

- [Mobile Communications and IoT](#mobile-communications-and-iot)
  - [Mobile Platform Hacking](#mobile-platform-hacking)
    - [Three Main Avenues of Attack](#three-main-avenues-of-attack)
    - [OWASP Top 10 Mobile Risks](#owasp-top-10-mobile-risks)
  - [Mobile Platforms](#mobile-platforms)
    - [Android](#android)
      - [Rooting Tools](#rooting-tools)
    - [iOS](#ios)
      - [Jailbreaking Tools](#jailbreaking-tools)
      - [Jailbreaking Techniques](#jailbreaking-techniques)
      - [Jailbreaking Types](#jailbreaking-types)
        - [Userland exploit](#userland-exploit)
        - [iBoot exploit](#iboot-exploit)
        - [BootROM exploit](#bootrom-exploit)
    - [Mobile Device Management (MDM)](#mobile-device-management-mdm)
    - [Bluetooth](#bluetooth)
      - [Discovery mode](#discovery-mode)
      - [Pairing mode](#pairing-mode)
  - [Mobile Attacks](#mobile-attacks)
    - [SMS Phishing](#sms-phishing)
    - [Trojans Available to Send](#trojans-available-to-send)
    - [Spyware](#spyware)
    - [Mobile Attack Platforms](#mobile-attack-platforms)
      - [Tools](#tools)
    - [Bluetooth Attacks](#bluetooth-attacks)
      - [Tools](#tools-1)
  - [IoT Architecture](#iot-architecture)
    - [Three Basic Components](#three-basic-components)
    - [Operating Systems](#operating-systems)
    - [Methods of Communicating](#methods-of-communicating)
    - [Architecture Levels](#architecture-levels)
  - [IoT Vulnerabilities and Attacks](#iot-vulnerabilities-and-attacks)
  - [IoT Hacking Methodology](#iot-hacking-methodology)
    - [1. Information Gathering](#1-information-gathering)
      - [Tools](#tools-2)
    - [2. Vulnerability Scanning](#2-vulnerability-scanning)
      - [Tools](#tools-3)
    - [3. Launching Attacks](#3-launching-attacks)
      - [Tools](#tools-4)
    - [4. Gaining Access](#4-gaining-access)
    - [5. Maintaining Access](#5-maintaining-access)
  - [IoT Maleware](#iot-maleware)

## Mobile Platform Hacking

### Three Main Avenues of Attack

- **Device Attacks** - browser based (pishing), SMS, application attacks, rooted/jailbroken devices
- **Network Attacks** - DNS cache poisoning, rogue APs, packet sniffing
- **Data Center (Cloud) Attacks** - databases, photos, etc.

### OWASP Top 10 Mobile Risks

- **M1 - Improper Platform Usage** - misuse of features or security controls (Android intents, TouchID, Keychain)
- **M2 - Insecure Data Storage** - insecure stored data and unintended data leakage
- **M3 - Insecure Communication** - poor handshaking, incorrect SSL versions, clear-text communication, weak negotiation
- **M4 - Insecure Authentication** - failing or missing authentication of end user or bad session management
- **M5 - Insufficient Cryptography** - code that applies cryptography to an asset, but is insufficient (does NOT include SSL/TLS)
- **M6 - Insecure Authorization** - failures in authorization (access rights)
- **M7 - Client Code Quality** - catchall for code-level implementation problems (buffer overflow, format string vulnerabilities, etc ...)
- **M8 - Code Tampering** - binary patching, resource modification, dynamic memory modification, replace system APIs, change contents of memory dynamically
- **M9 - Reverse Engineering** - analysis of core binary to determine source code, libraries, algorithms used to exploit and reveal information
- **M10 - Extraneous Functionality** - catchall for backdoors that were inadvertently placed by coders

## Mobile Platforms

### Android

- built by Google
- contains OS, middleware and suit of built-in applications
- **Android Device Administration API** - provides system level device administration that that can be used to build security-aware apps
- **Rooting** - perform some action that grants root access on an Android device

#### Rooting Tools

- KingoRoot
- TunesGo
- OneClickRoot
- MTK Droid
- SuperOneClick

### iOS

- OS built by Apple
- **Jailbreaking** - different levels of rooting an iOS device

#### Jailbreaking Tools

- evasi0n7
- GeekSn0w
- Pangu
- Redsn0w
- Absinthe
- Cydia

#### Jailbreaking Techniques

- **Untethered** - kernel remains patched after reboot, with or without a system connection
- **Semi-Tethered** - reboot no longer retains kernel patch; must use installed jailbreak software if admin priviledges are required again
- **Tethered** - reboot removes all jailbreaking patches; phone may get in boot loop requiring a system conntection (USB) to repair

#### Jailbreaking Types


##### Userland exploit

- Found in the system itself to gain root access, modify the fstab and patch the kernel
- Does _not_ provide admin
- Can be patched by Apple
- Can not be tethered, because nothing can cause recovery mode loop
- Is OS level

##### iBoot exploit

- Found in bootloader called iBoot (others are SecureROM & LLB)
- Uses vulnerability to turn codesign off
- Can be semi-tethered
- Can be patched

##### BootROM exploit

- Allows access to file system, iBoot and custom boot logos
- Found in device's first bootloader SecureROM
- Can be untethered
- Cannot be patched - its hardware, not software

### Mobile Device Management (MDM)

- **Bring Your Own Device** (BYOD) - dangerous for organizations because not all phones can be locked down by default
- MDM is an effort zo add some control - like group policy on Windows
- helps enforce security and deploy apps from enterprise as well as monitoring of mobile devices
- MDM solutions offer: passcodes for device, unlocking, remote locking, remote wipe, root or jailbreak detection, polica enforcement, inventory and monitoring/reporting
- MDM solutions include XenMobile, IBM, MaaS360, AirWatch and MobiControl

### Bluetooth

- If a mobile device can be connected too easily, it can fall prey to Bluetooth attacks
- Has a weak encryption cipher
- Has 2 modes **discovery mode** and **pairing mode**
- Bluetooth 2.0 with **Enhanced Data Rate** (EDR) uses 8DPSK (3 mbps) and Pi/4-DQPSK (2mbps)
  
#### Discovery mode

- How the device reacts to inquiries from other devices; has 3 actions
- **Discoverable** - answers all inquiries
- **Limited Discoverable** - restricts the action discoverable
- **Nondiscoverable** - ignores all inquiries
  
#### Pairing mode

- How the device deals with pairing requests
- **Pairable** - accepts all requests
- **Nonpairable** - rejects all connection requests

## Mobile Attacks

- **App Store attacks** - since some App stores are not vetted, malicious apps can be placed there
- **Phishing attacks** - mobile phones have more data to be stolen and are just as vulnerable as desktops
- **Social engineering attacks** - merciless
- Mobile platform features such as **Find my iPhone**, **Where is my Droid** and **AndroidLost** can be hacked to find devices, etc.

### SMS Phishing

- Sending texts with malicious links
- People tend to trust these more because they happen less
  
### Trojans Available to Send

- Obad
- Fakedefender
- TRAMPS
- ZitMo


### Spyware

- Mobile Spy
- Spyera


### Mobile Attack Platforms

- Tools that allow you to attack from your phone

#### Tools

- **Network Spoofer** - to control how websites appear on a desktop/laptop
- **DroidSheep** - to perform sidejacking by listening to wireless packets and pulling session IDs
- **Nmap**
- **NetCut** - identify systems on your wifi and cut them off

### Bluetooth Attacks

- **Bluesmacking** - denial of service against device; relies on oversized Logical Link Control and Adaption Layer Protocol (L2CAP) ping message
- **Bluejacking** - sending unsolicited messages
- **Bluesniffing** - attempt to discover Bluetooth-enabled devices
- **Bluebugging** - remotely using a device's features
- **Bluesnarfing** - theft of data from a device
- **Blueprinting** - collecting device information over Bluetooth (footprinting for Bluetooth)

#### Tools

- **BBProxy** - Blackberry-centric tool useful in an attack called blackjacking
- **BlueScanner** - finds devices around you
- **BT Browser** - another tool for finding and enumerating devices
- **Bluesniff** and **btCrawler** - finding and enumerating devices and services
- **Bloover** - can perform Bluebugging
- **PhoneSnoop** - good spyware option for Blackberry
- **Super Bluetooth Hack** - all-in-one package that allows you to do almost anything

## IoT Architecture

- **Definition** - a collection of devices using sensors, software, storage and electronics to collect, analyze, store and share data
- **Thing** - defined as any device implanted somewhere with the ability of communicating on the network

### Three Basic Components

- Sensing Technology
- IoT gateways
- The cloud
 
### Operating Systems

- **RIOT OS** - embedded systems, actuator boards, sensors; is energy efficient; has very small resource requirement
- **ARM mbed OS** - mostly used on wearables and other low-powered devices
- **RealSense OS X** - Intel's depth sensing version; mostly found in cameras and other sensors
- **Nucleus RTOS** - used in aerospace, medical and industrial applications
- **Brillo** - Android-based OS; generally found in thermostats
- **Contiki** - OS made for low-power devices; found mostly in street lighting and sound monitoring
- **Zephyr** - option for low-power devices and devices without many resources
- **Ubuntu Core** - used in robots and drones; known as "snappy"
- **Integrity RTOS** - found in aerospace, medical, defense, industrial and automotive sensors
- **Apache Mynewt** - used in devices using Bluetooth Low Energy Protocol

### Methods of Communicating

- **Device to Device** - communicates directly with other IoT devices
- **Device to Cloud** - communicates directly to a cloud service
- **Device to Gateway** - communicates with a gateway before sending to the cloud (Bluethooth or 802.11 for gateway communication; HTTP, CoAP, DTLS and TLS for device connectivity)
- **Back-End Data Sharing** - like device to cloud but adds abilities for 3rd-parties to collect and use the data (CoAP, HTTP, or other protocol for cloud communication; may use gateway internally)
- **Constraint Application Protocol** (CoAP) - Internet Application Protocol for constrained devices
- **Datagram Transport Layer Security** (DTLS) - communications protocol that provides security for datagram-based applications by allowing them to communicate in a way that is designed to prevent eavesdropping, tampering, or message forgery.
- **Vehicle Ad Hoc Network** (VANET) - communications network used by our vehicles and refers to spontaneous creation of a wireless network for vehicle-to-vehicle (V2V) data exchange 

### Architecture Levels

- **Edge Technology Layer** - consists of sensors, RFID tags, readers and the devices
- **Access Gateway Layer** - first data handling, message identification and routing
- **Internet Layer** - crucial layer which serves as main component to allow communication
- **Middleware Layer** - sits between application and hardware layers; handles data and device management, data analysis and aggregation
- **Application Layer** - responsible for delivery of services and data to the user

## IoT Vulnerabilities and Attacks

- **I1 - Insecure Web Interface** - problems such as account enumeration, weak credentials, and no account lockout; prevalent on internal networks; easy to discover manullay or automated testing
- **I2 - Insufficient Authentication/Authorization** - assumes interfaces will only be exposed on internal networks and thus is a flaw; easy to discover manually or automated testing
- **I3 - Insecure Network Services** - may be susceptible to buffer overflow or DoS attacks; detected by automated tools like port scanners and fuzzers
- **I4 - Lack of Transport Encryption/Integrity Verification** - data transported without encryption; prevalent on local networks
- **I5 - Privacy Concerns** - due to collection of personal data in addition to lack of proper protection; discover by reviewing data
- **I6 - Insecure Cloud Interface** - easy-to-guess credentials used or account enumeration is possible; discover by checking if SSL is in use or by using the password reset mechanism to identify valid accounts
- **I7 - Insecure Mobile Interface** - easy-to-guess credentials used or account enumeration is possible; discover by checking if SSL is in use or by using the password reset mechanism to identify valid accounts
- **I8 - Insufficient Security Configurability** - users cannot change security controls which causes default passwords and configuration (user permissions, forcing strong passwords, etc); discover by reviewing the web interface and options
- **I9 - Insecure Software/Firmware** - lack of a device to be updated, firware files and network are not protected or firmwre contains hardcoded sensitive data
- **I10 - Poor Physical Security** - disassemble a device to access storage medium or use external ports to access the device using features intended for configuration or maintenance

- **Sybil Attack** - uses multiple forged identities to create the illusion of traffic, affecting network communication
- **HVAC Attacks** - attacks on HVAC systems (air conditioning services) to perform further attacks on the target network
- **Rolling Code** - jam and sniff the signal of a key fob to get the code transferred to the car (use hardware: HackRF One)
- **BlueBorne Attack** - amalgamation of techniques and attacks against Bluetooth vulnerabilities
- **DDoS** - Miari malware interjects itself into devices and propagates to create a botnet
- Other attacks already enumerated in other sections still apply such as MITM, ransomware, side channel

## IoT Hacking Methodology

### 1. Information Gathering

- Gathering information about the devices
  
#### Tools

- **Shodan** - search engine for IoT devices
- **Foren6** - IoT traffic sniffer
- **Z-Wave** - IoT traffic sniffer
- **CloudShark** - IoT traffic sniffer
- Censys
- Thingful

### 2. Vulnerability Scanning

- same as normal methodology - looks for vulnerabilities

#### Tools

- Nmap
- RIoT Vulnerability Scanner
- beSTORM
- IoTsploit
- IoT Inspector

### 3. Launching Attacks

#### Tools

- **Firmalyzer** - perform active security assessments on IoT devices
- **Attify Zigbee Framework** - suite of tools for testing Zigbee devices
- KillerBee
- JTAGulator
  
### 4. Gaining Access

- same objectives as normal methodology
- **Telnet** often leveraged in IoT devices and provides easy means to gain access
- Install backdoors, maleware or force firmware updates

### 5. Maintaining Access

## IoT Maleware

- **Mirai** - infected IoT devices disrupting DNS service's ability to respond to resolution requests (2016, dyn attack)

- same objectives as normal methodology
