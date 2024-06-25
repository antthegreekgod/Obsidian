- **tags:** #SNMP #common-services 
- ----------------
# Introduction
`Simple Network Management Protocol` ([SNMP](https://datatracker.ietf.org/doc/html/rfc1157)) was created to monitor network devices. In addition, this protocol can also be used to handle configuration tasks and change settings remotely. SNMP-enabled hardware includes routers, switches, servers, IoT devices, and many other devices that can also be queried and controlled using this standard protocol.
## Structure
**An OID is an object identifier value, typically an address used to identify a particular device and its status**. For example, you want to monitor a remote temperature sensor sitting on the roof of your building. But there are three different temperature sensors placed in different parts of the roof. How can you check the value of the sensor located on the eastern side of the roof? Using the unique OID associated with each device. In other words, each device has its own unique OID and using that you can track the performance and status of that particular device. **These OIDs are not random addresses, rather they are highly structured and follow a hierarchical tree pattern**, similar to the folder system in your computer. One difference is that all SNMP objects in the tree hierarchy are numbered.

*A MIB is a text file in which all queryable SNMP objects of a device are listed*. A MIB is a translator that helps a management station to understand the OID and through it, the status of the device. To avoid confusion, the manufacturer specifies the meaning of each value (OID) in the MIB file.
# Detection
The service runs on *UDP Port 161*:
```bash
nmap -p161 -sU --open -T5 -v -n 192.168.1.X
```
There are 3 versions of **SNMP**:
- *SNMPv1*
- *SNMPv2c*
- *SNMPv3*: Uses a better authentication form and the information travels encrypted
*SNMPv1 is still the most frequent*, **the authentication is based on a string (community string) that travels in plain-text** (all the information travels in plain text). Version 2 and 2c send the traffic in plain text also and uses a community string as authentication.
# Brute-Forcing Community String
Community strings can be seen as passwords that are used to determine whether the requested information can be viewed or not. If we do not know the community string, we can use **onesixtyone** and `SecLists` wordlists to identify these community strings.
```bash
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
```
A frequently used community string is **public**. Other frequent strings would be "private" and "manager".
# Thorough Scan
If you know a valid community string, you can access the data using *SNMPWalk* or *braa*:
```bash
# snmpwalk -v <version> -c <community string> <IP TARGET>
snmpwalk -v 1 -c public 10.129.203.14

# braa <community string>@<targetIP>:<OID to brute FORCE>
braa public@10.129.14.128:.1.3.6.*
```
**Handy OID's to FUZZ:**
```
1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 User Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports
```
So if we wanted to list the current system processes we could issue the following query:
```bash
snmpwalk -c public -v1 10.129.14.128 1.3.6.1.2.1.25.1.6.0
```
### External Resources
- [MIB and OID, what are they, and how do they work](https://www.netadmintools.com/snmp-mib-and-oids/)
- [Hacktricks, Pentesting SNMP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)