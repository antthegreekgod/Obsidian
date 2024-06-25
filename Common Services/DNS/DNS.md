- **tags:** #common-services  #DNS
---------------------
# Introduction
The [Domain Name System](https://www.cloudflare.com/learning/dns/what-is-dns/) (`DNS`) translates domain names (e.g., hackthebox.com) to the numerical IP addresses (e.g., 104.17.42.72). *DNS* is mostly `UDP/53`, but DNS will rely on `TCP/53` more heavily as time progresses.
# Perform DNS Record Queries
- **whois** is a query and response protocol that is used for querying databases for verified registration information of any domain or IP address.
```bash
whois instagram.com
whois 13.123.12.100
# Probably the most important information to note down are the NS
```
- **nslookup** yet another tool for querying the Domain Name System for DNS records
- **dig** is a flexible tool for interrogating *DNS name servers*.
A typical invocation of dig looks like:
```bash
dig @server name type
```
Where:
- *server*: is the name or *IP* address of the *name server* to query.
- *name*: is the name of the resource record that is to be looked up (domain)
- *type*: indicates what type of query is required — *ANY, A, MX, NS* etc.
Example:
![[dns.png]]
# Sub-Domain Enumeration
[Subbrute](https://github.com/TheRook/subbrute) allows us to use self-defined resolvers and perform pure DNS brute-forcing attacks during internal penetration tests on hosts that do not have Internet access. Another approach would be to write our own simple *bash* script:
```bash
#!/bin/bash

wordlist=$1
domain=$2
ns=$3
 
function ctrl_c(){
    echo -e "\nQuitting...\n"
    tput cnorm
    exit 1
}
 
trap ctrl_c INT
 
if [ $# -ne 3 ]; then
	echo -e "\nUsage: $0 wordlist domain ns\n"
    exit 1
fi

tput civis
for sub in $(cat $wordlist); do
    dig $sub.$domain @$ns | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt &
done; wait && tput cnorm
```
Or use built-in tools like *dnsenum*:
```bash
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```
## Passive Sub-Domain Enum
- https://crt.sh
- [https://subdomainfinder.c99.nl/](https://subdomainfinder.c99.nl/)
- https://www.virustotal.com
- 
# AXFR Attacks
The *AXFR* attack is carried out by sending a *zone transfer request from a spoofed DNS server to a legitimate DNS server*. This request is made using the DNS zone transfer protocol (AXFR), which is used by DNS servers to transfer DNS records from one server to another. Unless a DNS server is configured correctly (limiting which IPs can perform a DNS zone transfer), **anyone can ask a DNS server for a copy of its zone information since DNS zone transfers do not require any authentication**. A zone transfer will include information such as domain names, IP addresses, email servers and other sensitive information that can be used in future attacks.
To perform such attacks we will be using **dig** again:
![[axfr.png]]
# Domain/Sub-Domain Takeover
A subdomain takeover occurs when a subdomain points to another domain using the **CNAME record that does not currently exist**. When an attacker registers this nonexistent domain, the subdomain points to the domain registration by us. By making a single DNS change, we make ourselves the owner of that particular subdomain, and after that, we can manage the subdomain as we choose.
