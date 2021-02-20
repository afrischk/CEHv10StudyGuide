# Low Tech: Social Engineering and Physical Security

* [Social Engineering](#social-engineering)
  * [Phases](#phases)
  * [Reasons Why This Works](#reasons-why-this-works)
  * [Factors Why Whis Works](#factors-why-whis-works)
  * [Categories](#categories)
* [Human-Based Attacks](#human-based-attacks)
  * [Dumpster Diving](#dumpster-diving)
  * [Impersonation](#impersonation)
  * [Shoulder Surfing](#shoulder-surfing)
  * [Eavesdropping](#eavesdropping)
  * [Tailgating](#tailgating)
  * [Piggybacking](#piggybacking)
  * [RFID Identity Theft (RFID skimming)](#rfid-identity-theft-(rfid-skimming))
  * [Reverse Social Engineering](#reverse-social-engineering)
  * [Insider Attack](#insider-attack)
  * [Good To Know](#good-to-know)
* [Computer-Based Attacks](#computer-based-attacks)
  * [Phishing](#phishing)
    * [Spear Phishing](#spear-phishing)
    * [Ways to Avoid Phishing](#ways-to-avoid-phishing)
  * [Other & Phishing Variants](#other-&-phishing-variants)
* [Social Engineering Mitigation](#social-engineering-mitigation)
* [Mobile-Based Attacks](#mobile-based-attacks)
  * [ZitMo (ZeuS-in-the-Mobile)](#zitmo-(zeus-in-the-mobile))
  * [Attack Categories](#attack-categories)
* [Physical Security Basics](#physical-security-basics)
  * [Biometrics](#biometrics)

## Social Engineering

- The art of manipulating a person or group into providing information or a service they would otherwise not have given
- Nontechnical method of attacking systems; not limited to people with technical know-how

### Phases

1. Research (dumpster dive, visit websites, tour the company, etc.)
2. Select the victim (identify frustrated employee or other target)
3. Develop a relationship
4. Exploit the relationship (collect sensitive information)

### Reasons Why This Works

- Human nature (trusting others)
- Ignorance of social engineering efforts
- Fear (of consequences of not providing the information)
- Greed (promised gain for providing requested information)
- A sense of moral obligation

### Factors Why Whis Works

- Insufficient Training
- Unregulated information (or physical) access
- Complex organizational structure
- Lack of security policies

### Categories

- Human based - uses interaction in conversation or other circumstances between people to gather useful information
- Computer based
- Mobile based

## Human-Based Attacks

### Dumpster Diving

- Looking for sensitive information in the trash
- Shredded papers can sometimes indicate sensitive info
- Also called **trashint** or **trashintelligence**

### Impersonation

- Pretending to be someone you're not
- Can be anything from a help desk person up to an authoritative figure (FBI agent)
- Posing as a tech support professional can really quickly gain trust with a person
- Get physical access to an restricted area
- Get physical access to sensible information
- Using a phone during a social engineering effort is known as **vishing** (voice phishing)
- **Authority support** - tricking a help desk person into resetting a password

### Shoulder Surfing

- Looking over someone's shoulder to get info
- Can be done long distance with binoculars, etc.

### Eavesdropping

- Listening in on conversations about sensitive information

### Tailgating

- Attacker has a fake badge and walks in behind someone who has a valid one

### Piggybacking

- Attacker pretends they lost their badge and asks someone to hold the door
- Difference between Tailgating and Piggybacking is the presence of a fake ID badge (tailgaters have them)

### RFID Identity Theft (RFID skimming)

- Stealing an RFID card signature with a specialized device

### Reverse Social Engineering

- Getting someone to call you and give information
- Often happens with tech support - an email is sent to user stating they need them to call back (due to technical issue) and the user calls back
- Can also be combined with a DoS attack to cause a problem that the user would need to call about

### Insider Attack

- An attack from an employee, generally disgruntled
- Sometimes subclassified (negligent insider, professional insider)

### Good To Know

- **Rebecca** or **Jessica** - targets for social engineering
- Always be pleasant - it gets more information

## Computer-Based Attacks

- Carried out by the use of a computer
- Attacks include: specially crafted pop-up windows, hoax e-mails, chain letters, instant messaging, spam and phishing
- Social networking and spoofing sites or access points are also related

### Phishing

- Crafting an email that appears legitimate but contains links to fake websites or to download malicious content
- Often involves mass-emailing in hopes of snagging some unsuspecting reader
- Tools to mitigate phishing: **Netcraft Toolbar** and **PhishTank Toolbar**a - they can identify risky sites and phishing behavior
- **sign in seal** - email protection method that uses a secret message (kept locally) that can be referenced on any official communication

#### Spear Phishing

- Targeting a person or a group with a phishing attack
- Result of reconnaissance work

#### Ways to Avoid Phishing

- Beware unknown, unexpected or suspicious originators
- Beware of who the email is addressed to
- Verify phone numbers
- Beware bad spelling or grammar
- Always check links (Fake AV or Rogue Security)

### Other & Phishing Variants

- **Whaling** - going after CEOs or other C-level executives (spear phishing high-level targets)
- **Pharming** - use of malicious code that redirects a user's traffic
- **Spimming** - sending spam over instant message
- **Fave Antivirus** - very prevalent attack; pretends to be an anti-virus but is a malicious tool

## Social Engineering Mitigation

- Setting up multiple layers of defense
- Change-management procedures
- Strong authentication measures
- User education

## Mobile-Based Attacks

- Take advantages of applications or services in mobile devices

### ZitMo (ZeuS-in-the-Mobile)

- Banking malware that was ported to Android
- Exploits an already owned PC to take control of a phone
- Target donwloads app (maleware) to receive security messages
- Steals credentials and two-factor codes to get access to the bank account
- Other types of maleware activate SMS messages that was sent to request premium service

### Attack Categories

- Publishing malicious apps - looks like a legitimate app
- Repackaging legitimate apps - modification of legitimate app and uploading to third party app store
- Fake security applications - attacker infects a pc and then offers a security app to get rid of maleware
- SMS (**smishing**) - crafted to appear as legitimate security notifications

## Physical Security Basics

- **Physical measures** - everything you can touch, taste, smell or get shocked by; lighting, locks, fences, guards with Teasers
- **Technical measures** - measures taken with technology in mind to protect at the physical level; smartcards and biometrics
- **Operational measures** - policies and procedures you set up to enforce a security-minded operation; background checks on employees, risk assessments on devices, policies regarding key management and storage
- **Access controls** - physical measures designed to prevent access to controlled areas; biometric controls, identification/entry cards, door locks, mantraps
- **Mantrap** - physical access control; two doors are used to create a small space to hold a person until appropriate authentication has occurred (biometric, token with PIN, password, etc...)

### Biometrics

- Measures taken for authentication that come from the "something you are" concept
- **False rejection rate** (FRR) - when a biometric rejects a valid user
- **False acceptance rate** (FAR) - when a biometric accepts an invalid user
- **Crossover error rate** (CER) - combination of the two; determines how good a system is; the lower the better
- Even though hackers normally don't worry about environmental disasters, this is something to think of from a pen test standpoint (hurricanes, tornadoes, floods, etc.)
