# Cryptography 101

- [Cryptography 101](#cryptography-101)
  - [Cryptograph Basics](#cryptograph-basics)
  - [Encryption Algorithms and Techniques](#encryption-algorithms-and-techniques)
    - [Steam Cipher](#steam-cipher)
    - [Block Cipher](#block-cipher)
    - [XOR](#xor)
  - [Symmetric Encryption](#symmetric-encryption)
    - [Algorithms](#algorithms)
  - [Asymmetric Encryption](#asymmetric-encryption)
    - [Algorithms](#algorithms-1)
      - [Diffie-Hellman](#diffie-hellman)
  - [Hash Algorithms](#hash-algorithms)
    - [Algorithms](#algorithms-2)
    - [Attacks](#attacks)
    - [Tools](#tools)
  - [Steganography](#steganography)
    - [Ways to Identify](#ways-to-identify)
    - [Methods](#methods)
    - [Tools](#tools-1)
  - [PKI System](#pki-system)
    - [Trust Model Types](#trust-model-types)
  - [Digital Certificates](#digital-certificates)
    - [Contents of a Digital Certificate](#contents-of-a-digital-certificate)
  - [Digital Signatures](#digital-signatures)
  - [Data at Rest (DAR)](#data-at-rest-dar)
    - [Tools](#tools-2)
  - [Encrypted Communication](#encrypted-communication)
    - [SSL Connection Step](#ssl-connection-step)
    - [OpenSSL Tool](#openssl-tool)
    - [Heartbleed](#heartbleed)
    - [FREAK (Factoring Attack on RSA-EXPORT Keys)](#freak-factoring-attack-on-rsa-export-keys)
    - [POODLE (Paddling Oracle On Downgraded Legacy Encryption)](#poodle-paddling-oracle-on-downgraded-legacy-encryption)
      - [Mitigation](#mitigation)
    - [DROWN (Decrypting RSA with Obsolete and Weakened eNcyption)](#drown-decrypting-rsa-with-obsolete-and-weakened-encyption)
      - [Mitigation](#mitigation-1)
  - [Cryptography Attacks](#cryptography-attacks)
    - [Known plain-text attack](#known-plain-text-attack)
    - [Chosen plain-text attack](#chosen-plain-text-attack)
    - [Adaptive chosen plain-text attack](#adaptive-chosen-plain-text-attack)
    - [Cipher-text-only attack](#cipher-text-only-attack)
    - [Replay attack](#replay-attack)
    - [Chosen Cipher Attack](#chosen-cipher-attack)
    - [Side-Channel Attack](#side-channel-attack)
    - [Inference attack](#inference-attack)
    - [Tools](#tools-3)
    - [Additional Information](#additional-information)

## Cryptograph Basics

- **Cryptography** - science or study of protecting information whether in transit or at rest; renders the information unusable to anyone who can't decrypt it
- Encrypting data provides confidentiality
- Integrity can be provided by hashing algorithms
- **Cryptanalysis** - study and methods used to crack encrypted communications
- **Nonrepudiation** - means by which a recipient can ensure the identity of the sender and neither party can deny having sent the message
- **Linear Cryptanalysis** - works best on block ciphers; take blocks of known text and compare them to blocks of encrypted text
- **Differential Cryptanalysis** - applies to symmetric key algorithms; compares differences in inputs to how each one affects the outcome
- **Integral Cryptanalysis** - input vs output comparison same as differential; runs multiple computations of the same block size input

## Encryption Algorithms and Techniques

- Encryption of bits takes two forms:
  - **Substitution** - bits are replaced by other bits
  - **Transposition** - doesn't replace; changes order
- **Product Cipher** - uses substitution and transposition

### Steam Cipher

- Bits of data are encrypted one at a time in a continuous stream
- Usually done by an XOR operation
- Work at a high rate of speed
 
### Block Cipher

- Data bits are combined into blocks and fed into the cipher
- Each block of data (usually 64 bits) encrypted with key and algorithm
- Are simpler and slower than stream ciphers

### XOR

- Exclusive or; if inputs are the same (0,0 or 1,1), function returns 0; if inputs are not the same (0,1 or 1,0), function returns 1
- Key chosen for cipher must have a length larger than the data; if not, it is vulnerable to frequency attacks

## Symmetric Encryption

- Known as single key or shared key
- One key is used to encrypt and decrypt the data
- Problems include key distribution (offline) and management
- Suitable for bulk encryption because of its speed
- Poor scalability because number of keys increases with network size
- Does nothing for nonrepudiation; only provides confidentiality

### Algorithms

- **DES** - block cipher; 56 bit key; quickly outdated and now considered not very secure
- **3DES** - block cipher; 168 bit key; up to 3 keys in a multiple-encryption method; more effective than DES but much slower
- **AES** (Advanced Encryption Standard) - block cipher; 128, 192 or 256 bit key; replaces DES; much faster than DES and 3DES
- **IDEA** (International Data Encryption Algorithm) - block cipher; 128 bit key; originally used in PGP 2.0; designed to replace DES; mainly used in Europe
- **Twofish** - block cipher; up to 256 bit key
- **Blowfish** - fast block cipher; replaced by AES; 64 bit block size; 32 to 448 bit key; considered public domain
- **RC** (Rivest Cipher) - versions from RC2 to RC6; block cipher; variable key length up to 2040 bits; RC6 (latest version) uses 128 bit blocks and 4 bit working registers; RC5 uses variable block sizes (32, 64 and 128 bit) and 2 bit working registers. RC4 is a stream cipher

## Asymmetric Encryption

- Uses two types of keys for encryption and decryption
- **Public Key** - generally used for encryption; can be sent to anyone
- **Private Key** - kept secret; used for decryption
- Comes down to what one key encrypts, the other decrypts
- The private key is used to digitally sign a message
- Provides confidentiality and nonrepudiation
- Solves problems with key distribution and scalability
- Only weakness is it's performance (slower than symmetric especially on bulk encryption) and processing power (it requires a longer key)

### Algorithms

- **Diffie-Hellman** 
- **Elliptic Curve Cryptosystem** (ECC) - uses points on elliptical curve along with logarithmic problems for encryption and signatures; uses less processing power; good for mobile devices
- **El Gamal** - not based on prime number factoring; uses solving of discrete logarithm problems for encryption and signatures
- **RSA** - achieves strong encryption through the use of two large prime numbers; factoring these create key sizes up to 4096 bits; modern de facto standard for encryption and digital signatures

#### Diffie-Hellman

- Developed as a key exchange protocol
- Used in SSL and IPSec
- If digital signatures are waived, vulnerable to MITM attacks
- Security increases with the size of the modulus used to generate the session key
- Group 14 protection fro 128 bit keys
- Group 15 protection for 192 bit keys

| Group | Size     |
| ----- | -------- |
| 1     | 768 bit  |
| 2     | 1024 bit |
| 5     | 1536 bit |
| 14    | 2048 bit |
| 15    | 3072 bit |
| 16    | 4096 bit |
| 17    | 6144 bit |
| 18    | 8192 bit |

## Hash Algorithms

- __One-way__ mathematical function that produces a fix-length string (hash) based on the arrangement of data bits in the input
- Verifies the integrity of data
- **Salt** - collection of random bits used as a key in addition to the hashing algorithm
- **Rainbow Tables** - contain precomputed hashes 

### Algorithms

- **MD5** (Message Digest algorithm) - produces 128 bit hash expressed as 32 digit hexadecimal number; has serious flaws; still used for file download verification; obsolete since 2010
- **SHA-1** - developed by NSA; 160 bit value output; serious flaws; replacement with SHA-2 after 2010
- **SHA-2** - four separate hash functions; produce outputs of 224, 256, 384 and 512 bits; not widely used
- **SHA-3** - uses sponge construction; data absorbed into the sponge (XOR) and squeezed out (state alternation)
- **RIPEMD-#** (RACE Integrity Primitives Evaluation Message Digest) - works through 80 stages, executing 5 blocks 16 times each; uses modulo 32 addition; # indicates bit length

### Attacks

- **DUHK Attack** (Don't Use Hard-Coded Keys) - allows attackers to access keys in certain VPN implementations; affects devices using ANSI X9.31 (random number generator) with a hard-coded seed key
- **Collision/Collision Attack** - occurs when two or more files create the same output; hacker tries to create a file with same hash value output as the original
- **Birthday Attack** - find 2 passwords with matching hashes; use the hash to gain access

### Tools

- HashCalc
- MD5 Calculator
- HashMyFiles
- HashDroid

## Steganography

- Practice of concealing a message inside text, audio, image or video so that only the sender and recipient know of its existence

### Ways to Identify

- __Text__ - character positions are key, blank spaces, text patterns or language anomalies
- __Image__ - file larger in size; some may have color palette faults
- __Audio & Video__ - require statistical analysis

### Methods

- **Least significant bit insertion** - changes least meaningful bit in every byte to represent data (for image: e.g. loss of sharpness)
- **Masking and filtering (grayscale images)** - like watermarking; modifying the luminescence of image parts
- **Algorithmic transformation** - hides in mathematical functions used in image compression

### Tools

- OmniHide Pro (video)
- Masker (video)
- DeepSound (audio)
- MP3Stego (audo)
- QuickStego
- gifshuffle
- SNOW
- Steganography Studio
- OpenStego

## PKI System

- Handles key generation, distribution and revocation; also allows for creation and dissemination of digital certificates
- **Public Key Infrastructure** (PKI) - structure designed to verify and authenticate the identity of individuals within data exchange
- **Registration Authority** (subordinate CA) - verifies user identity
- **Certificate Authority** - third party to the organization; creates and issues digital certificates; keeps track of all certificates and maintains a CRL
- **Certificate Revocation List** (CRL) - used to track which certificates have problems and which have been revoked
- **Validation Authority** - used to validate certificates via Online Certificate Status Protocol (OCSP)
- **Cross-Certification** - allows a CA to trust another CA in a different PKI; allows both CAs to validate certificates from either side
- **Trust Model** - how entities within an enterprise deal with keys, signatures and certificates
- Root CAs are removed from network access to protect the integrity of the system

### Trust Model Types

- **Single-authority system** - CA at the top; users trust each other based on the CA
- **Hierarchical trust system** - CA at the top (root CA); makes use of one or more RAs (subordinate CAs) underneath it to issue and manage certificates; most secure because certificates can be tracked back to the root to ensure authenticity
- **Web of trust** - multiple entities sign certificates for on another; user trust each other based on certificates they receive from other users

## Digital Certificates

- **Certificate** - electronic file that is used to verify a user's identity; provides nonrepudiation
- **X.509** - standard used for digital certificates
- **Self-Signed Certificates** - certificates that are not signed by a CA; generally not used for public; used for development purposes
- Some root CAs are automatically added to OSes; normally are reputable companies

### Contents of a Digital Certificate

- **Version** - identifies certificate format (most common version is 1)
- **Serial Number** - used to uniquely identify certificate
- **Subject** - who or what is being identified
- **Algorithm ID** (Signature Algorithm) - shows the algorithm that was used to create the certificate
- **Issuer** - shows the entity that verifies authenticity (the one who creates the certificates)
- **Valid From and Valid To** - dates certificate is good through
- **Key Usage** - what purpose the certificate serves
- **Subject's Public Key** - copy of the subject's public key
- **Optional Fields** - Issuer Unique Identifier, Subject Alternative Name, and Extensions

## Digital Signatures

- Hash a message and encrypt it with your **private** key; the recipient decrypts the hash with your **public** key
- **Digital Signature Algorithm** (DSA) - used in generation and verification of digital signatures per FIPS 186-2
- DSA is a Federal Information Processing Standard proposed by NIST (August 1991) for use in their Digital Signature Standard (DSS)

## Data at Rest (DAR)

- Data that is in a stored state and not currently accessible
- Usually protected by **full disk encryption** (FDE) with pre-boot authentication
- FDE can be software and hardware based; software-based FDE provides central management, making key management and recovery actions easier
- Can use network-based authentication (e.g. AD) or local authentication sources
- Example of FDE is Microsoft BitLocker and McAfee Endpoint Encryption
- FDE also gives protection against boot-n-root (bootable USB)
- Encrypting entire disk with pre-boot authentication VS individual volume, folder and file encryption

### Tools

- Microsofts BitLocker - FDE
- McAfee Endpoint Encryption - FDE
- Semantic Drive Encryption - FDE
- Gilisoft Full Disk Encryption - FDE
- Microsoft Encrypted File Systems (EFS) - folder/file
- VeraCrypt - folder/file
- AxCrypt - folder/file
- GNU Privacy Guard - folder/file

## Encrypted Communication

  - **Secure Shell** (SSH) - secured version of telnet; uses TCP port 22; relies on public key cryptography; SSH2 is successor and includes SFTP is more secure, efficient and portable
  - **Secure Sockets Layer** (SSL) - encrypts data at transport layer and above; uses RSA encryption and digital certificates; has a six-step process; largely has been replaced by TLS
  - **Transport Layer Security** (TLS) - uses RSA 1024 and 2048 bits; successor to SSL; TLS Handshake Protocol allows both client and server to authenticate to each other; TLS Record Protocol provides secured communication channel
  - **Internet Protocol Security** (IPSec) - network layer tunneling protocol; used in tunnel and transport modes; ESP encrypts each packet
  - **Pretty Good Privacy** (PGP) - used for signing, compression and encryption of emails, files and directories; follows the OpenPGP standard (RFC 4880) for encrypting and decrypting data; known as hybrid cryptosystem - features conventional and public key cryptography
  - **Secure/Multipurpose Internet Mail Extensions** (S/MIME) - standard for public key encryption and signing of MIME data; only difference between this and PGP is PGP can encrypt files and drives unlike S/MIME
  - **Internet Key Exchange** (IKE) - is the protocol used to set up a security association (SA) in the IPsec protocol

### SSL Connection Step

1. Client sends 'Hello' message
2. Server sends 'Hello' message with SSL version, Session ID and Certificate message
3. Sever sends 'Hello done' message
4. Client verifies the cert and sends the Client Key Exchange Message (with a secret key encrypted with the severs public key)
5. Clients sends a Finished message with a hash included
6. Server compares the hash against its computed hash of the exchange and sends a Finished message

### OpenSSL Tool

- `openssl s_server -port [port]` creates SSL/TLS server and listens on port `[port]`; default port is `4433`
- `openssl s_server -accept [host:port]` creates SSL/TLS server and listens on host `[host:port]`; default is `*:4433`
- `openssl s_client -connect [host:port]` connects a client to a specific host on port

### Heartbleed 

- Attack on OpenSSL heartbeat which verifies data was received correctly
- Vulnerability is that a single byte of data gets 64kb from the server
- This data is random; could include usernames, passwords, private keys, cookies; very easy to pull off
- `nmap -d --script ssl-heartbleed --script-args vulns.showall -sV [host]`
- Metasploit auxiliary module __openssl_heartbleed__ can be used for exploit
- Vulnerable versions include __Open SSL 1.0.1 and 1.0.1f__
- __CVE-2014-0160__

### FREAK (Factoring Attack on RSA-EXPORT Keys) 

- Man-in-the-middle attack that forces a downgrade of RSA key to a weaker length
- Attacker forces the use of weaker encryption key length, enabling successful brute-force attacks

### POODLE (Paddling Oracle On Downgraded Legacy Encryption)

- Downgrade attack that used the vulnerability that TLS downgrades to SSL if handshakes fail
- SSL 3.0 uses RC4, which is easy to crack
- SSL 3.0 has a design flaw; allows padding data at hte end of a block cipher to be changed; encryption cipher bceomes less secure each time its passedA
- __RC4 biases__ if same secret is sent over several sessions, more information will leak; only 256 SSL 3.0 requests needed to reveal 1 byte of encrypted messages
- __CVE-2014-3566__
- Also called **PoodleBleed**

#### Mitigation

- Disbable SSL 3.0
- Implement `TLS_FALLBACK_SCSV` if TLS 1.0 and above is not supported - fake cipher suite advertised in the CLient Hello message to start the SSL/TLS handshake)
- Implement __anti-POODLE__ record splitting - splits records into parts and none of them can be attacked

### DROWN (Decrypting RSA with Obsolete and Weakened eNcyption)

- Affects SSL and TLS services
- Allows attackers to break the encryption and steal sensitive data
- Uses flaws in SSLv2
- Not only web servers; can be IMAP and POP servers as well

#### Mitigation

- Turn off SSLv2
- Ensure private keys are not used anyware with server software that allows SSLv2 connections

## Cryptography Attacks

### Known plain-text attack

- Has both plain text and cipher-text
- Plain-text scanned for repeatable sequences which is compared to cipher text
- Needs time and effort to decipher the key

### Chosen plain-text attack

- Attacker encrypts multiple plain-text copies in order to gain the key

### Adaptive chosen plain-text attack

- Attacker makes a series of interactive queries choosing subsequent plaintexts based on the information from the previous encryptions
- Translation: Attacker sends bunches of cipher texts to be decrypted and the uses the results of the decryptions to select different, closley related cipher texts
- Idea is to glean more and more information about the full target cipher text and key

### Cipher-text-only attack

- Gains copies of several encrypted messages with the same algorithm
- Statistical analysis is then used to reveal eventually repeating code, which can be used to decode messages later

### Replay attack

- Usually performed within context of MITM attack
- Hacker repeats a portion of cryptographic exchange in hopes of fooling the system to setup a communications channel
- Doesn't know the actual data - just has to get timing right in copying and replaying the bit stream
- Session tokens are a countermeasure

### Chosen Cipher Attack

- Chooses a particular cipher-text message
- Attempts to discern the key through comparative analysis with multiple keys and a plain-text version
- RSA is particularly vulnerable to this

### Side-Channel Attack

- Monitors environmental factors such as power consumption, timing and delay on the cryptosystem

### Inference attack

- Derive information from the cipher-text without decoding it

### Tools

- Carnivore and Magic Lantern - used by law enforcement for cracking codes (more like a keylogger)
- L0phtcrack - used mainly against Windows SAM files (crack password hashes)
- John the Ripper - UNIX/Linux tool for the same purpose (crack password hashes)
- PGPcrack - designed to go after PGP-encrypted systems
- CrypTool
- Cryptobench
- Jipher

### Additional Information

- Keys should still change on a regular basis even though they may be "unhackable"
- Per U.S. government, an algorithm using at least a 256-bit key cannot be cracked
- The stronger encryption + longer the keys = the longer the attack will take to be successful
