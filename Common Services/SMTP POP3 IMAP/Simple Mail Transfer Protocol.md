- **tags:** #SMTP #common-services #POP3 #IMAP
- -----------
# Introduction
A `mail server` (sometimes also referred to as an email server) is a server that handles and delivers email over a network, usually over the Internet. A mail server can receive emails from a client device and send them to other mail servers. A mail server can also deliver emails to a client device.
Protocols involved:
- **SMTP** (Protocol used for email delivery) `TCP PORT -> 25`
- **POP3** (`TCP PORT -> 110`) and **IMAP4** (`TCP PORT -> 143`) which allows the user to save messages
# Enumeration
We can use the `Mail eXchanger` (`MX`) *DNS record* to identify a mail server.
```bash
# Retrieving the MX DNS records.
host -t MX victim.com
dig @ns1.inlanefreight.htb inlanefreight.htb MX

# Retrieving the A DNS Record for the Mail Server found
host -t A mail1.inlanefreight.com
dig @ns1.inlanefreight.htb mail1.inlanefreight.htb A
```
**Used Ports**:

| Port    | Service           |
| ------- | ----------------- |
| TCP/25  | SMTP              |
| TCP/110 | POP3 Unencrypted  |
| TCP/143 | IMAP4 Unencrypted |
| TCP/465 | SMTP Encrypted    |
| TCP/587 | SMTP Encrypted    |
| TCP/993 | IMAP4 Encrypted   |
| TCP/995 | POP3 Encrypted    |
## User Enumeration On Custom MX
The *SMTP* server has different commands that can be used to enumerate valid usernames `VRFY`, `EXPN`, and `RCPT TO`.
- `VRFY`: instructs the receiving SMTP server to check the validity of a particular email username
- `EXPN`: is similar to `VRFY`, except that when used with a distribution list, it will list all users on that list (always check if "all" is regarded as a distribution list)
- `RCPT TO`: identifies the recipient of the email message
```shell
telnet 10.129.58.17 25

# The client greets the server and introduces itself using the HELO/EHLO command
HELO x

# start user enum via VRFY or EXPN commands
VRFY root

VRFY root@inlanefreight.htb

EXPN all

EXPN support-team

```
![[user_enum_smtp.png]]
To automate our enumeration process, we can use a tool named [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum).
![[enum_users.png]]
Some times we may be able to also enumerate valid users using the *POP3* protocol. For example, we can use the command `USER` followed by the username, and if the server responds `OK`. This means that the user exists on the server.
# Password Attacks
When we have a valid list of usernames, we can start our password spraying or brute-force attacks with tools like [[hydra]].
![[brute_smtp.png]]
# Interacting with Mail Services
## Listing MailBox
![[POP3.png]]
## Sending Mails Using Telnet
![[sending.png]]
![[recieved.png]]
# Interacting with Encrypted Mail Services
```bash
#POP3 Encrypted
openssl s_client -connect 10.129.14.128:995
#IMAP Encrypted
openssl s_client -connect 10.129.14.128:993
```
# SMTP Open Relay
An open relay is a Simple Transfer Mail Protocol (`SMTP`) server, which is improperly configured and allows an unauthenticated email relay. Messaging servers that are accidentally or intentionally configured as open relays allow mail from any source to be transparently re-routed through the open relay server. This behavior masks the source of the messages and makes it look like the mail originated from the open relay server. With the `nmap smtp-open-relay` script, we can identify if an SMTP port allows an open relay.
### Resource Labs
- Attacking Common Services Module from HTB