# The Pen Test:  Putting It All Together

* [Security Assessment](#security-assessment)
  * [Categories](#categories)
  * [Penetration Test](#penetration-test)
    * [Automated Testing Tools](#automated-testing-tools)
    * [Phases of Pen Test](#phases-of-pen-test)
* [Security Assessment Deliverables](#security-assessment-deliverables)
  * [Comprehensive Report Parts](#comprehensive-report-parts)
* [Terminology](#terminology)
  * [Types of Insiders](#types-of-insiders)

## Security Assessment

- Test performed in order to assess the level of security on a network or system

### Categories

- **Security Audit** - policy and procedure focused; tests whether organization is following specific standards and policies
- **Vulnerability Assessment** - scans and tests for vulnerabilities but does not intentionally exploit them; simply points out vulnerabilities to the client
- **Penetration Test** - looks for vulnerabilities and seeks to exploit them

### Penetration Test 

- Agreement signed before testing begins - covers limitations, constraints and lieabilities
- **Internal Assessment** - performed from within the organization, from various network access points
- **External Assessment** - analyzes publicity available information; network scanning, enumeration and testing from the network perimeter (internet)
- **Red Team** - pen test team that is doing the attacking (no knowledge)
- **Blue Team** - pen test team that is doing the defending (white-box knowledge)
- **Purple Team** - pen test team that is doing both attacking and defending (attack and identify issues AND repair and advise)

#### Automated Testing Tools

- Susceptible to false positives and false negatives
- Can save money
- Don't care about agreements
- Manual testing is still the best choice
- **Codenomicon** - utilizes fuzz testing that learns the tested system automatically; allows for pen testers to enter new domains such as VoIP assessment, etc.
- **Core Impact Pro** - best known, all-inclusive automated testing framework; tests everything from web applications and individual systems to network devices and wireless
- **Metasploit** - framework for developing and executing code against a remote target machine; autopawn module can automate exploitation phase
- **CANVAS** - hundreds of exploits, automated exploitation system and extensive exploit development framework

#### Phases of Pen Test

- **Pre-Attack Phase** - reconnaissance and data-gathering; e.g. competitive intelligence, identifying network ranges, checking network filters for open ports, nmap scans, whois, DNS enumeration, finding IP address range , etc...
- **Attack Phase** - attempts to penetrate the network and execute attacks; e.g. use covert tunnels, XSS, buffer overflows, injections, password cracking, privilege escalation, etc...
- **Post-Attack Phase** - Cleanup to return a system to the pre-attack condition and deliver reports; e.g. delete created files, folders, maleware, backdoors, clean registry, create a report, etc...

## Security Assessment Deliverables

- Usually begins with a brief to management
- Provides information about your team and the overview of the original agreement
- Explain what tests were done and the results of them
- Emergency phone number
- Example reports and methodology can be found in the **Open Source Testing Methodology Manual** (OSSTMM)

### Comprehensive Report Parts

- Executive summary of the organization's security posture (tailored to a standard)
- Names of all participants and dates of tests
- List of all findings, presented in order of risk
- Analysis of each finding and recommended mitigation steps
- Log files and other evidence (screenshots, etc.)
 
## Terminology

### Types of Insiders

- **Pure Insider** - employee with all rights and access associated with being an employee (privileges are often assigned at a higher level than actually required)
- **Elevated Pure Insider** - employee who has admin privileges
- **Insider Associate** - someone with limited authorized access such as a contractor, guard or cleaning service person (physical access)
- **Insider Affiliate** - spouse, friend or client of an employee who uses the employee's credentials to gain access (credentials belonging to a pure insider)
- **Outside Affiliate** - someone outside the organization who uses an open access channel to gain access to an organization's resources
