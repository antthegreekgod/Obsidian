- **tags:** #IPMI #common-services 
- ------------
# Introduction
*Intelligent Platform Management Interface (IPMI)* offers a standardized approach for remote management and monitoring of computer systems, independent of the operating system or power state. This technology allows system administrators to manage systems remotely, even when they're off or unresponsive, and is especially useful for:
- Pre-OS boot configurations
- Power-off management
- Recovery from system failures
IPMI is capable of monitoring temperatures, voltages, fan speeds, and power supplies, alongside providing inventory information, reviewing hardware logs, and sending alerts via SNMP.
# Enumeration
IPMI communicates over **port 623 UDP**. Systems that use the IPMI protocol are called Baseboard Management Controllers (BMCs). BMCs are typically implemented as embedded ARM systems running Linux, and connected directly to the host's motherboard.
```bash
nmap -p623 -sU --script ipmi-version 10.10.11.19
```
## Password Retrieval

| Product         | Username      | Password                                                                  |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                                                    |
| Supermicro IPMI | AMIN          | ADMIN                                                                     |
| HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
If default credentials do not work to access a BMC, we can turn to a flaw in the RAKP protocol in IPMI 2.0. *During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password* to the client before authentication takes place. This can be leveraged to obtain the password hash for ANY valid user account on the BMC. To retrieve IPMI hashes, we can use the Metasploit [IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/) module.
```bash
# cracking captured HASH
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```