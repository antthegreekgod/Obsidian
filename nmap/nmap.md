- **tags:** #nmap #enumeration 
- --------------------
# most common switches

```bash
#------------- SCAN OPTIONS ------------
-Pn #skip host discovery scan (treat host as alive)
-p- #all pors
-sS/-sT/-sU #Stealth (S/S.A./RST)/ TCP (S/S.A./A/RST)/ UDP scan
-T #0-5 speed
-n #skip DNS resolution
--min-rate 5000
-sn #ping sweep, disables port enummeration
#------------- PROTECTION EVASION -------
-f #fragment packets
--mtu #set max transmission unit (multiple of 8)(the data being sent in the packet)
--source-port 53
--data-length 12 #adds the given number to the default packet data
-D #decoy (specify range of IP's)
#-------------- SCRIPTING ------------
-sC #nmap sends the default scripts
--script http-enum
--script="vuln and safe"
--script-help=mongodb-info
grep -oP "categories = \K{.*?}" -r /snap/nmap/3152/usr/share/nmap/scripts/ #to search by categories
```

**TIP:** to list all nmap scripts run `locate .nse` .
```bash
locate .nse | xargs grep "categories" | grep -oP '".*?"' | sort -u # list all categories
```

# nmap

`nmap`, short for Network Mapper, is a free and open-source tool used for network discovery and security auditing. It is widely utilized in cybersecurity to scan networks for open ports, running services, and system details.

## Host Discovery

By default `nmap` tries to check if the host is alive using `ARP-ping` requests, nonetheless we could instead use normal `ICMP` Echo Requests.

```bash
nmap 10.0.0.0/24 -sn -oA hosts #this will scan the whole network
nmap -sn -oA hosts_alive -iL hosts.lst #Only scan the IPs listed in the file
nmap -sn 10.0.0.18-24 -oA hosts
nmap -sn -PE 10.0.0.3 -oA hosts --packet-trace
nmap -sn -PE 10.0.0.3 -oA hosts --reason --disable-arp-ping
```

- `-PE` Performs the ping scan by using 'ICMP Echo requests' against the target.
- `-oA` Stores the results in all formats starting with the name 'host'.
- `-sn` Disables port sacnning.

## Host and Port Scanning

### TCP ports

By default when we run `nmap` as root it will use the `SYN` scan (`-sS`), which is the fastest way to analyse the state of a port.

There are 6 different port states:

- `Open` : Connection has been established, port is open
- `Closed` : Port closed, `RST` flag received.
- `Filtered` : No answer provided from the host, this may be due to the Firewall or an IPS.
- `Unfiltered` : Port is accessible but the state is unknown (`-sA` scan.)
- `Open|Filtered`
- `Closed|Unfiltered`

**Useful Switches:**

```bash
-sS #SYN scan
-sT #Connect scan 3-way handshake
-n #disables DNS resolution
-Pn #disables ICMP echo requests
--disable-arp-ping
--top-ports=10 #by defalt scans top 1000 ports
-F #top 100 ports
-p- #Scans all ports
-sV #Performs a service scan
--stats-every=5s #every 5s reports the sacn status
```

### UDP Ports

Since `UDP` is a stateless connection we will only be able to determine whether a port is open or not if they have been configured to do so. The `nmap` flag used to perform a UDP scan is `-sU` .

## Output Formats

The `nmap` results can be saved using three different outputs.

- `-oN` Nmap Format
- `-oG` Grepable Output
- `-oX` XML Output

With the XML output we can quickly create a visual report of the `nmap` results.

```bash
xsltproc target.xml -o target.html #convert the stored results from XML format to HTML
```

## Scripting

There are 14 different categories:
![[scripting.png]]


```bash
sudo nmap -sC 10.0.0.3
sudo nmap --script <cartegory> 10.0.0.3
sudo nmap --script <script_name> 10.0.0.3
```

### Common

```bash
banner.nse #banner grabbing
```

## Performance Tweaks

```bash
--max-rtt-timeout 100ms #Round-Trip-Time Timeout
--min-rate 300 #number of packets sent simultaneously per second
--max-retries 0 #Amount of retries after non-responsive ports
```

There are also 6 different timing templates, these go from 0-5 and are specified with the `-T` flag.

- `-T` 0 / `-T` paranoid
- `-T` 1 / `-T` seaky
- `-T` 2 / `-T` polite
- `-T` 3 / `-T` normal (default)
- `-T` 4 / `-T` aggressive
- `-T` 5 / `-T` insane

## Firewall IDS/IPS evasion

Most out coming connections will be analysed by a firewall and may be rejected or dropped depending on its configuration rules. We can try to bypass it, by directly sending `ACK` packets. Thus, the firewall might now allow our packets since it will look like our connection had already been successfully established. Finally, the target is alive, it will answer with the `RST` flag. The downside of this scanning method is that we won’t know whether the targeted ports are open or closed, we’ll just learn whether or not they respond to our packets.

The `nmap` flag to use such scanning method is `-sA` . The port scanning report will only determine if such ports are on `filtered` or `unfiltered` state.

Another way to confuse `IDS` mechanisms is the use of **************decoys**************. We can disguise our requests in the middle of fake traffic using the `-D` switch.

```bash
sudo nmap <ip> -sS -p445 --packet-trace -n -Pn --disable-arp-ping -D RND:5
```

We can also manually spoof our IP:

```bash
sudo nmap <ip> -sS -p445 -S <spoofing_ip> -e <iface>
```

Or we could send our requests from a trustworthy port.

```bash
sudo nmap <ip> -p445 -sS --source-port 53
```
# fast TCP port scan ideal for Pivoting
```bash
seq 1 65535 | xargs -P 500 -I {} proxychains nmap -sT -Pn -p{} --open -T5 -n -v <IP> -oG allPorts 2>&1 | grep "tcp open"
```