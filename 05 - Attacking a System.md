# Attacking a System

- [Attacking a System](#attacking-a-system)
  - [Windows Security Architecture](#windows-security-architecture)
    - [LM Hashes](#lm-hashes)
    - [Ntds.dit](#ntdsdit)
    - [Kerberos](#kerberos)
      - [Tools](#tools)
    - [Registry](#registry)
      - [Type of values](#type-of-values)
      - [Root level keys](#root-level-keys)
      - [Important Locations](#important-locations)
    - [MMC](#mmc)
    - [Windows Commands](#windows-commands)
    - [Windows Tools](#windows-tools)
  - [Linux Security Architecture](#linux-security-architecture)
    - [Logs](#logs)
    - [Important locations](#important-locations-1)
    - [Linux Commands](#linux-commands)
      - [chmod](#chmod)
      - [grep](#grep)
    - [IP Masquearding](#ip-masquearding)
      - [iptables](#iptables)
  - [System Hacking Goals](#system-hacking-goals)
    - [Gaining Access](#gaining-access)
    - [Covering Tracks](#covering-tracks)
  - [Authentication and Passwords](#authentication-and-passwords)
    - [Types](#types)
      - [Something You Are](#something-you-are)
      - [Something You Have](#something-you-have)
      - [Something You Know](#something-you-know)
    - [Strength of passwords](#strength-of-passwords)
  - [Password Attacks](#password-attacks)
    - [Non-electronic](#non-electronic)
    - [Active online](#active-online)
      - [LLMNR/NBT-NS](#llmnrnbt-ns)
        - [Tools](#tools-1)
    - [Passive online](#passive-online)
      - [Tools](#tools-2)
    - [Offline](#offline)
      - [Tools](#tools-3)
  - [Privilege Escalation and Executing Applications](#privilege-escalation-and-executing-applications)
    - [Four Methods](#four-methods)
    - [Executing Applications Tools](#executing-applications-tools)
  - [Hiding Files and Covering Tracks](#hiding-files-and-covering-tracks)
    - [Alternate Data Stream](#alternate-data-stream)
      - [Tools](#tools-4)
    - [Hide By Attributes](#hide-by-attributes)
    - [Stenography](#stenography)
      - [Tools](#tools-5)
    - [Clear Logs](#clear-logs)
      - [Tools](#tools-6)
  - [Rootkits](#rootkits)
    - [Detecting Rootkits](#detecting-rootkits)
    - [Tools](#tools-7)
  - [Package Crafting Tools](#package-crafting-tools)

## Windows Security Architecture

- Authentication credentials stored in SAM file
- File is located at `C:\windows\system32\config`
- Older systems use LM hashing.  Current uses NTLM v2 (MD5)
- Windows authentication protocol/method is Kerberos
- Windows drops ICMP Echo Requests sent to broadcast address

### LM Hashes

- Splits the password up.  If it's over 7 characters, it is encoded in two sections.
- If one section is blank, the hash will be `AAD3B435B51404EE`
- Easy to break if password is 7 characters or under because you can split the hash
- SAM file presents as `UserName : SID : LM_Hash : NTLM_Hash : : :`

### Ntds.dit

- Database file on a domain controller that stores passwords
- Located in `%SystemRoot%\NTDS\Ntds.dit` or `%SystemRoot%System32\Ntds.dit`
- Includes the entire Active Directory


### Kerberos

**Key Distribution Center** (KDC) holds the **Authentication Service** (AS) and the **Ticket Granting Service** (TGS).

1. Client asks KDC for a ticket. Sent in clear text.
2. Server responds with TGT. This is a secret key which is hashed by the password copy stored on the server.
3. If client can decrypt it, the TGT is sent back to the server requesting a TGS service ticket.
4. Server sends TGS service ticket which client uses to access resources.

#### Tools

- KerbSniff
- KerbCrack
- Both take a long time to crack

### Registry

- Collection of all settings and configurations that make the system run
- Made up of keys and values
- Executables to edit are `regedit.exe` and `regedt32.exe` (preferred by Microsoft)

#### Type of values

- **REG_SZ** - character string
- **REG_EXPAND_SZ** - expandable string value
- **REG_BINARY** - a binary value
- **REG_DWORD** - 32-bit unsigned integer
- **REG_LINK** - symbolic link to another key
- **REG_MULTI_SZ** - a multistring value

#### Root level keys

- **HKEY_LOCAL_MACHINE** (HKLM) - information on hardware (processor type, bus architecture, etc...) and software (os, drivers, services, etc...)
- **HKEY_CLASSES_ROOT** (HKCR) - information on file associates and Object Linking and Embedding (OLE) classes
- **HKEY_CURRENT_USER** (HKCU) - profile information for the current user including user preferences for the OS and applications
- **HKEY_USERS** (HKU) - specific user configuration information  for all currently active users
- **HKEY_CURRENT_CONFIG** (HKCC) - pointer to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Hardware Profiles\Current`

#### Important Locations

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`

### MMC

- Microsoft Management Console - used by Windows to administer system
- Has "snap-ins" that allow you to modify sets (such as Group Policy Editor)

### Windows Commands

- `sc.exe [<servername>] query [<servicename>] [type= {driver | service | all}] [state= {active | inactive | all}]` - Obtains and displays information about the specified service, driver, type of service, or type of driver; `service` and `active` is the default
- `compmgmt.msc` -  opens Computer Management
- `route add [network address] mask [subnet mask] [gateway address]` - adds routes
- `route add 0.0.0.0 mask 0.0.0.0 192.168.1.1` - creates a default route; default route is a route to a gateway if the traffic is destined for a location not in routing table

### Windows Tools

- **Microsoft Baseline Security Analyzer** (MBSA) - uses the **Windows Update Agent** (WUA) to remotely scan the security state of computers on a network

## Linux Security Architecture

- Adding an `&` after a process name indicates it should run in the background.
- Use the `nohup` if you wish the process to remain after user logout
- Root has UID and GID of 0
- First user has UID and GID of 500
- Passwords are stored in `/etc/shadow` for most current systems
- `/etc/passwd` stores passwords in hashes.
- `/etc/shadow` stores passwords encrypted (hashed and salted) and is only accessible by root

### Logs

- **utmp**, **btmp** and **wtmp** are files that keep track of logins and logouts to the system; read log by `last` command
- **/var/run/utmp** -  contains current status of the system like boot time, user logins, logouts, system events, etc...
- **/var/log/btmp** - contains failed login attempts
- **/var/log/wtmp** - historical utmp
- **/var/log/auth** - contains system auth info like user logins and auth mechanism 

### Important locations

- **/** - root directory
- **/bin** - basic Linux commands
- **/dev** - contains pointer locations to various storage and input/output systems
- **/etc** - all administration files and passwords.  Both password and shadow files are here
- **/home** - holds the user home directories
- **/mnt** - holds the access locations you've mounted
- **/sbin** - system binaries folder which holds more administrative commands
- **/usr** - holds almost all of the information, commands and files unique to the users

### Linux Commands

| Command  | Description                                                                      |
| -------- | -------------------------------------------------------------------------------- |
| adduser  | Adds a user to the system                                                        |
| cat      | Displays contents of file                                                        |
| cp       | Copies                                                                           |
| ifconfig | Displays network configuration information                                       |
| kill     | Kills a running process                                                          |
| ls       | Displays the contents of a folder.  -l option provides most information.         |
| man      | Displays the manual page for a command                                           |
| passwd   | Used to change password                                                          |
| ps       | Process status.  -ef option shows all processes                                  |
| rm       | Removes files.  -r option recursively removes all directories and subdirectories |
| su       | Allows you to perform functions as another user (super user)                     |
| pwd      | displays current directory                                                       |
| chmod    | changes the permissions of a folder or file                                      |

#### chmod

- Read is 4, write is 2 and execute is 1
- First number is user, second is group, third is others
- Example - 755 is everything for users, read/execute for group, and read/execute for others

#### grep

| Option | Description                                |
| ------ | ------------------------------------------ |
| -l     | Lists only files that contain the term     |
| -L     | Lists only files that not contain the term |
| -r     | recursive search                           |

### IP Masquearding

- `ipchains`, `ipwadm` or `iptables`
  
#### iptables

| Option                        | Description    |
| ----------------------------- | -------------- |
| -t [filter, nat, mangle, raw] | Table to use   |
| -L                            | List all rules |

## System Hacking Goals

- **Gaining Access** - uses information gathered to exploit the system
- **Escalating Privileges** - granting the account you've hacked admin or pivoting to an admin account
- **Executing Applications** - putting back doors into the system so that you can maintain access
- **Hiding Files** - making sure the files you leave behind are not discoverable
- **Covering Tracks** - cleaning up everything else (log files, etc.)

| System attack phases |                                               |
| -------------------- | --------------------------------------------- |
| Reconnaissance       | Reconnaissance                                |
| Scanning             | Disovery and Port Scanning <br> Enumeration   |
| Gaining Access       | Cracking Passwords <br> Escalating Privileges |
| Maintaining Access   | Executing Applications <br> Hiding Files      |
| Clearing Tracks      | Clearing Logs                                 |

### Gaining Access

- includes cracking passwords, escalating priviledges

### Covering Tracks

- **clearev** - meterpreter (metasploit) shell command to clear log files
- Clear Most Recently Used (MRU) list in Windows (`HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER`)
- In Linux, append a dot in front of a file to hide it

## Authentication and Passwords

### Types

- **Two-Factor** - when you have two types of authentication such as something you know (password) and something you have (access card)
- **Default passwords** - always should be changed and never left what they came with.  Databases such as cirt.net, default-password.info and open-sez.me all have databases of these

#### Something You Are

- uses biometrics to validate identity (retina, fingerprint, etc.)
- Downside is there can be lots of false negatives
- **False acceptance rate** (FAR) - rate that a system accepts access for people that shouldn't have it
- **False rejection rate** (FRR) - rate that a system rejects access for someone who should have it
- **Crossover error rate** (CER) - combination of the two; the lower the CER, the better the system
- **Active** - requires interaction (retina scan or fingerprint scanner)
- **Passive** - requires no interaction (iris scan)

#### Something You Have

- usually consists of a token of some kind (swipe badge, ATM card, etc.)
- This type usually requires something alongside it (such as a PIN for an ATM card)
- Some tokens are single-factor (such as a plug-and-play authentication)

#### Something You Know

- better known as a password
- Most systems use this because it is universal and well-known

### Strength of passwords

- determined by length and complexity
- ECC says that both should be combined for the best outcome
- Complexity is defined by number of character sets used (lower case, upper case, numbers, symbols, etc.)

## Password Attacks

### Non-electronic

- social engineering attacks - most effective.
- Includes shoulder surfing and dumpster diving

### Active online

- done by directly communicating with the victim's machine
- Includes dictionary and brute-force attacks, rule-based attacks (dictionary/brute-force attacks with better information), hash injections, phishing, Trojans, spyware, keyloggers and password guessing
- **Keylogging** - process of using a hardware device or software application to capture keystrokes of a user
- Active online attacks are easier to detect and take a longer time
- Can combine "net" commands with a tool such as **NetBIOS Auditing tool** (NAT) or **Legion** to automate the testing of user IDs and passwords  
  `net view /domain:domainname` Shows all systems in the domain name provided  
  `net view \\systemname` Provides a list of open shares on the system name  
  `net use \\target\ipc$ "" /u"` Sets up a null session  
  `net use` Shows list of connected shared resources and logged in user accounts  
  `net use Z:\\somename\fileshare /persistent:yes` Mounts the folder _fileshare_ on the remote machine _somename_. Stays after reboot.

#### LLMNR/NBT-NS

- Link-Local Mutlicast Name Resolution / NetBIOS Name Service
- Attack based off Windows technologies that caches DNS locally
- LLMNR based on DNS format and allows host on the same subnet/local link to performa name resolution for other hosts
- NBT-NS identifies systems on a local network by their NetBIOS name
- Responding to these poisons the local cache
- If an NTLM v2 hash is sent over, it can be sniffed out and then cracked
- LLMNR uses UDP 5355, uses link-scope multicast IP address (`224.0.0.252` and `FF02:0:0:0:0:0:1:3`), check `HKLM\Software\Policies\Microsoft\Windows\NT\DNSClient` _EnableMulticast_ (`0` means LLMNR is disabled)
- NBT-NS uses UDP 137

##### Tools

- NBNSpoof
- Pupy
- Metasploit
- Responder

### Passive online

- sniffing the wire in hopes of intercepting a password in clear text or attempting a replay attack or man-in-the-middle attack

#### Tools

- **Cain and Abel** - can poison ARP and then monitor the victim's traffic; extracting voice from VoIP captures; Cain is for cracking and Abel for remote tasks like launch a system shell on a remote machine
- **Ettercap** - works very similar to Cain and Abel.  However, can also help against SSL encryption
- **KerbCrack** - built-in sniffer and password cracker looking for port 88 Kerberos traffic
- **ScoopLM** - specifically looks for Windows authentication traffic on the wire and has a password cracker


### Offline

- when the hacker steals a copy of the password file and does the cracking on a separate system
- **Dictionary Attack** - uses a word list to attack the password. Fastest method of attacking
- **Brute force attack** - tries every combination of characters to crack a password. Can be faster if you know parameters (such as at least 7 characters, should have a special character, etc.)
- **Hybrid attack** - takes a dictionary attack and replaces characters (such as a 0 for an o) or adding numbers to the end
- **Rainbow tables** - uses pre-hashed passwords to compare against a password hash. Is faster because the hashes are already computed.

#### Tools

- Cain
- KerbCrack
- Legion
- John the Ripper
- THC Hydra
- LC5

## Privilege Escalation and Executing Applications

- **Vertical** - lower-level user executes code at a higher privilege level
- **Horizontal** - executing code at the same user level but from a location that would be protected from that access
- ECC refers executing applications as "owning" a system
- **Executing applications** - starting things such as keyloggers, spyware, back doors and crackers

### Four Methods

1. Crack the password of an admin - primary aim
2. Take advantage of an OS/application vulnerability. **DLL/DYLIB Hijacking** - replacing a DLL in the application directory with your own version which gives you the access you need
3. Use a tool that will provide you the access such as Metasploit
4. Social engineering a user to run an application

### Executing Applications Tools

- RemoteExec
- PDQ Deploy
- Dameware remote Support

## Hiding Files and Covering Tracks

### Alternate Data Stream

- In Windows, ADS can hide files
- Hides a file from directory listing on an **New Technology File System** (NTFS) file system
- `type badfile.exe > readme.txt:badfile.exe`
- Can be run by `start readme.txt:badfile.exe`
- You can also create a link to this and make it look real (e.g. `mklink innocent.exe readme.txt:badfile.exe`)
- Every forensic kit looks for this, however
- To show ADS, `dir /r` does the trick
- You can also blow away all ADS by copying files to a FAT partition

#### Tools

- LNS
- Sfind

### Hide By Attributes

- In Windows:  attrib +h filename
- In Linux, simply add a . to the beginning of the filename


### Stenography

- hides files in plain sight, buried as part of an image, video or other file
- **visual semagram** - uses an everyday object to convey a message (e.g. item layout on desk) 
- **text semagram** - obscures a message in text by using font, size, type, spacing etc...

#### Tools

- ImageHide
- Snow
- Mp3Stego
- Blindside
- S-tools
- wbStego
- Stealth

### Clear Logs

- In Windows, you need to clear application, system and security logs
- Don't just delete; key sign that an attack has happened
- Option is to corrupt a log file - this happens all the time
- Best option is be selective and delete the entries pertaining to your actions.
- Can also disable auditing ahead of time to prevent logs from being captured
- logfiles default path is `%systemroot%\System32\Config` with `.evt`extension; location can be changed by editing `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog`
- disable event logs on older systems by `auditpol \\targetIPaddress /disable`
- _Control Panel_ -> _Administrative Tools_ -> _Local Security Policy_ : setup and change audit policy
- more settings under _Local Polices_ -> _Audit Policy_ And _Advaned Audit Policy Configuration_

#### Tools

- elsave
- WinZapper
- Evidence Eliminator
- Autitpol

## Rootkits

- Software put in place by attacker to obscure system compromise
- Hides processes and files
- Also allows for future access
- **Hypervisor level** - rootkits that modify the boot sequence of a host system to load a VM as the host OS
- **Hardware** - hide malware in devices or firmware
- **Boot loader level** - replace boot loader with one controlled by hacker
- **Application level** - directed to replace valid application files with Trojans
- **Kernel level** - attack boot sectors and kernel level replacing kernel code with back-door code; most dangerous
- **Library level** - use system-level calls to hide themselves
- Ring 0 -> kernel
- Ring 1 -> drivers
- Ring 2 -> libraries
- Ring 3 -> applications/user mode
- Reloading from a clean backup is the only real recovery method

### Detecting Rootkits

1. Run `dir /s /b /ah` and `dir /s /b /a-h` on infected OS to map all files; save the results
2. Boot a clean CD version of the OS and run the same commands on the the drive again
3. Compare the results

### Tools

- Horsepill - Linus kernel rootkit inside _initrd_ (klibc-horsepill.patch, horsepill_setopt, hrsepill_infect)
- Grayfish - Windows rootkit that injects in boot record and creates own virtual file system
- Sirefef - multi-component family of malware
- Azazel
- Avatar
- Necurs
- ZeroAccess


## Package Crafting Tools

- **packETH** - Linux-based tool to send TCP/IP packets
- **Nemesis** - command-line tool to generate ARP, Ethernet, TCP and UDP packets; inject packets at layer 2 and 3; Linux and Windows