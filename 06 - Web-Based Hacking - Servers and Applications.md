# Web-Based Hacking - Servers and Applications

- [Web-Based Hacking - Servers and Applications](#web-based-hacking---servers-and-applications)
  - [Web Organizations](#web-organizations)
  - [OWASP Web Top 10](#owasp-web-top-10)
  - [Web Server Attack Methodology](#web-server-attack-methodology)
    - [Information Gathering](#information-gathering)
    - [Web  Server Footprinting](#web--server-footprinting)
      - [Tools](#tools)
    - [Website Mirroring](#website-mirroring)
      - [Tools](#tools-1)
    - [Vulnerability Scanning](#vulnerability-scanning)
      - [Tools](#tools-2)
    - [Session Hijacking](#session-hijacking)
    - [Web Server Password Cracking](#web-server-password-cracking)
  - [Web Server Architecture](#web-server-architecture)
    - [HTML Entities](#html-entities)
    - [HTTP Request Methods](#http-request-methods)
    - [HTTP Error Messages](#http-error-messages)
  - [Web Server Attacks](#web-server-attacks)
    - [Tools](#tools-3)
      - [Metasploit](#metasploit)
  - [Web Application Attacks](#web-application-attacks)
    - [Tools for Identifying Entry Points](#tools-for-identifying-entry-points)
    - [Injection Attacks (not named SQL)](#injection-attacks-not-named-sql)
      - [LDAP Injection](#ldap-injection)
      - [SOAP Injection](#soap-injection)
    - [Buffer Overflow (Smashing the stack)](#buffer-overflow-smashing-the-stack)
      - [Counter Measures](#counter-measures)
      - [Canary Words](#canary-words)
        - [Tools](#tools-4)
    - [XSS (Cross-site scripting)](#xss-cross-site-scripting)
    - [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
    - [Session Fixation](#session-fixation)
    - [Cookies](#cookies)
    - [SQL Injection](#sql-injection)
      - [In-band SQL injection](#in-band-sql-injection)
      - [Out-of-band SQL injection](#out-of-band-sql-injection)
      - [Blind/inferential](#blindinferential)
      - [Tools](#tools-5)
    - [HTTP Response Splitting](#http-response-splitting)
  - [Countermeasures](#countermeasures)

## Web Organizations

- **Internet Engineering Task Force** (IETF) - creates engineering documents to help make the Internet work better
- **World Wide Web Consortium** (W3C) - a standards-developing community
- **Open Web Application Security Project** (OWASP) - organization focused on improving the security of software

## OWASP Web Top 10

- **A1 - Injection Flaws** - SQL, OS and LDAP injection
- **A2 - Broken Authentication and Session Management** - functions related to authentication and session management that aren't implemented correctly
- **A3 - Sensitive Data Exposure** - not properly protecting sensitive data (SSN, CC  numbers, etc.)
- **A4 - XML External  Entities (XXE)** - exploiting XML  processors by uploading hostile content in an XML document
- **A5 - Broken Access Control** - having improper controls on areas that should be protected
- **A6 - Security Misconfiguration** - across all parts of the server and application
- **A7 - Cross-Site Scripting (XSS)** - taking untrusted data and sending it without input validation
- **A8 - Insecure Deserialization** - improperly de-serializing data
- **A9 - Using Components with Known Vulnerabilities** - libraries and frameworks that have known security holes
- **A10 - Insufficient Logging and Monitoring** - not having enough logging to detect attacks

**WebGoat** - project maintained by OWASP which is an insecure web application meant to be tested

## Web Server Attack Methodology

### Information Gathering

Internet searches, whois, reviewing `robots.txt`

### Web  Server Footprinting

Banner grabbing

#### Tools

- Netcraft
- HTTPRecon
- ID Serve
- HTTPrint
- nmap  
  `nmap --script http-trace -p80 localhost` (detects vulnerable TRACE method)  
  `nmap --script http-google-email <host>` (lists email addresses)  
  `nmap --script hostmap-* <host>` (discovers virtual hosts on the IP address you are trying to footprint; * is replaced by online db such as  IP2Hosts)  
  `nmap --script http-enum -p80 <host>` (enumerates common web  apps)  
  `nmap -p80 --script http-robots.txt <host>` (grabs the robots.txt file)  

### Website Mirroring

Brings the site to your own machine to examine structure, etc.

#### Tools

- Wget
- BlackWidow
- HTTrack
- WebCopier Pro
- Web Ripper
- SurfOffline

### Vulnerability Scanning

Scans web server for vulnerabilities

#### Tools

- **Nessus**
- **Nikto** - Open Source vulnerability scanner that scans webservers for dangerous files/CGIs, outdated server software and other problems; noisy like Nessus

### Session Hijacking

### Web Server Password Cracking

## Web Server Architecture

- **Most Popular Servers** - Apache, IIS and Nginx
- Apache configuration done as a part of a module within special files (http.conf, etc.)
- IIS runs in the context of LOCAL_SYSTEM and spawns shells accordingly
- IIS 5 had a ton of bugs - easy to get into
- **N-Tier Architecture** - distributes processes across multiple servers; normally as three-tier: Presentation (web), logic (application) and data (database)
- **Error Reporting** - should not be showing errors in production; easy to glean information
- **HTML** - markup language used to display web pages
- Misconfiguration resulting in vulnerabilitites are error messages, default passwords, SSL certificates, scripts, remote administrative functions, configuration files and services on the machine.

### HTML Entities

Is a way of telling the browser to display those characters instead of interpreting them.

| Reserved Character in HTML | HTML Entity Version |
| -------------------------- | ------------------- |
|                            | \&nbsp;             |
| "                          | \&quot;             |
| '                          | \&apos;             |
| &                          | \&amp;              |
| <                          | \&lt;               |
| >                          | \&gt;               |


### HTTP Request Methods

- **GET** - retrieves whatever information is in the URL; sending data is done in URL
- **HEAD** - requests headers and metadata; works like GET without body
- **POST** - sends data via body - data not shown in URL or in history
- **PUT** - requests data be stored at the URL
- **DELETE** - requests origin server delete resource
- **TRACE** - requests application layer loopback of message
- **CONNECT** - reserved for use with proxy (SSL tunneling)
- Both POST and GET can be manipulated by a web proxy


### HTTP Error Messages

- **1xx: Informational** - request received, continuing
- **2xx: Success** - action received, understood and accepted
- **3xx: Redirection** - further action must be taken to complete the request
- **4xx: Client Error** - request contains bad syntax or cannot be fulfilled
- **5xx: Server Error** - server failed to fulfill an apparently valid request

## Web Server Attacks

- **DNS Amplification** - uses recursive DNS to DoS a target; amplifies DNS answers to target using a botnet until it can't do anything
- **Directory Transversal** (`../` or dot-dot-slash, backtracking, directory climbing) - requests file that should not be accessible from web server  
 Example: `http://www.example.com/../../../../etc/password`
 Can use Unicode to possibly evade IDS - `%2e` for dot and `%sf` for slash (unicode or unvalidated input attack)
- **Parameter Tampering** (URL Tampering) - manipulating parameters within URL to achieve escalation of priviledges or other changes
- **Hidden Field Tampering** - modifying hidden form fields producing unintended results
- **Web Cache Poisoning** - replacing the cache on a box with a malicious version of it
- **WFETCH** - Microsoft tool that allows you to craft HTTP requests to see response data
- **Misconfiguration Attack** - same as before - improper configuration of a web server
- **Password Attack** - attempting to crack passwords related to web resources
- **Connection String Parameter Pollution** (CSPP) - injection attack that uses semicolons to take advantage of databases that use this separation method
- **Web Defacement** - simply modifying a web page to say something else
- **Shellshock** (Bashdoor) - causes Bash to unintentionally execute commands when commands are concatenated on the end of function definitions stored in the values of environment varibales
 
### Tools

- **Brutus** - brute force web passwords of HTTP
- **THC-Hydra** - network login cracker
 
#### Metasploit  

- Basic working is Libraries use Interfaces and Modules to send attacks to services
- Framework base accepts inputs from plug-ins, interfaces, security tools, webservices and modules
- **Exploits** (module) hold the actual exploit  
- **Payload** (module) contains the arbitrary code executed if exploit is successful  
- **Auxiliary** (module) used for one-off actions (like a scan)  
- **NOPS** (module) used for buffer-overflow type operations  
- **REX** (library) handling sockets, protocols and text transformations

1. Select exploit
2. Configure options within the exploit
3. Select a target
4. Select the payload
5. Launch the Exploit

## Web Application Attacks

- **Web 2.0** - dynamic applications; have a larger attack surface due to simultaneous communication
- Most often hacked because of inherent weaknesses built into the program
- First step is to identify entry points (POST data, URL parameters, cookies, headers, encoding or encryption measures etc.)

### Tools for Identifying Entry Points

- WebScarab
- HTTPPrint
- BurpSuite

### Injection Attacks (not named SQL)

- pass exploit code to the server through poorly designed input validation
- **File Injection** - attacker injects a pointer in a web form to an exploit hosted elsewhere
- **Command Injection** - attacker injects commands into the form fields
- **Shell Injection** - attacker gains shell access using Java or similar
 
#### LDAP Injection

- exploits applications that construct LDAP statements
- Format for LDAP injection includes `)(&)`
- `&` ends a LDAP query
```
(& (USER=Brad) (PASSWORD=Test!))
(& (USER=Brad) (&) (PASSWORD=Any))
```

#### SOAP Injection

- Simple Object Access Protocol (SOAP)
- SOAP is compatible with HTTP and SMTP
- Inject query strings in order to bypass authentication or access the database
- SOAP uses XML to format information
- Messages are "one way" in nature


### Buffer Overflow (Smashing the stack)

- Attempts to write data into application's buffer area to overwrite adjacent memory, execute code or crash a system
- Inputs more data than the buffer is allocated to hold
- Includes stack, heap, NOP sleds and more
 
#### Counter Measures

- Canary words
- Address Space Layout Randomization (ASLR)
- Data Execution Prevention (DEP)

#### Canary Words

- Known values placed between buffer and control data
- If they are changed, they indicate a buffer overflow has occurred

##### Tools

- StackGuard (uses canary words)

### XSS (Cross-site scripting)

- Injection of a script into a web form that alters what the page does
- `http://IPADDRESS/";!--"<XSS>=&{()}` Instead of the URL passing to an existing page internally, it passes to the script behind the forward slash
- Can be mitigated by setting **HttpOnly** flag for cookies
- **Stored XSS** (persistent XSS or Type-I XSS) - stores the injected script permanently into the database, message forum, visitor log, etc...
- Can be used to upload malicious code to users connected to the server
- Can be used to access `document.cookie` and send it to a remote host
- Can be sent via email
- Can be used to send pop-up messages to users
- Can be used to steal a session
- Can be used to pull of a DoS attack


### Cross-Site Request Forgery (CSRF) 

- Forces an end user to execute unwanted actions on an app they're already authenticated on
- Inherits identity and privileges of victim to perform an undesired function on victim's behalf
- Captures the session and sends a request based off the logged in user's credentials
- Can be mitigated by sending **random challenge tokens**


### Session Fixation

- Attacker logs into a legitimate site and pulls a session ID;
- Sends link with session ID to victim
- Once victim logs in, attacker can now log in and run with user's credentials

### Cookies

- Small text-based files stored that contains information like preferences, session details or shopping cart contents
- Can be manipulated to change functionality (e.g. changing a cookie that says `ADMIN=no` to `ADMIN=yes`)
- Sometimes, but rarely, can also contain passwords
- Are sent in the header of an HTTP response from a web server

### SQL Injection

- Structured Query Language 
- Most injection attacks are within DML
- Injecting SQL commands into input fields to produce output
- Data Handling - Definition (DDL), manipulation (DML) and control (DCL)
- Input `' OR 1 = 1 --` into a login field - basically tells the server if `1 = 1` (always true) to allow the login
- Double dash `--` tells the server to ignore the rest of the query (in this example, the password check)
- Basic test to see if SQL injection is possible is just inserting a single quote `'` and look at the error message received (if any)
- **Fuzzing** - inputting random data into a target to see what will happen

#### In-band SQL injection

- Uses same communication channel to perform attack  
- **Union Query Attacks** - `SELECt fname, lname FROM users WHERE id=$id UNION ALL SELECT password, 1 FROM secrettable;`
- **Error-Based** - enter poorly constructed statements to get the db respond with table names in error messages
- **Tautology** - using true statements to sneak by, because "true" measure often allows access (e.g. `1 = 1`)
- **end of line/inline comments**
- **piggybacking** - add malicious request on the back of a legitimate one

#### Out-of-band SQL injection

- Uses different communication channels (e.g. export results to file on web server)

#### Blind/inferential

- Error messages and screen returns don't occur; usually have to guess whether command work or use timing to know

#### Tools

- Sqlmap
- sqlninja
- Havij
- SQLBrute
- Pangolin
- SQLExec
- Absinthe
- BobCat

### HTTP Response Splitting

- Adds header response data to an input field so server splits the response
- Hacker controls the content of the second header
- Can be used to redirect a user to a malicious site
- Is not an attack in and of itself - must be combined with another attack

## Countermeasures

- Correct placement of servers
- Strong patch management
- Turn off unnecessary services, ports and protocols
- Remove outdated, unused accounts and properly configure default accounts
- Set up appropriate file and folder permissions
- Disable directory listing
- Ensure you have means to detect attacks
- Input scrubbing for injection
- SQL parameterization for SQL injection
- Remove **Internet Services Application Programming Interface**(ISAPI) filters from webserver to increase security (IIS)
