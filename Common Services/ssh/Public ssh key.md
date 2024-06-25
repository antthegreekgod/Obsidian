- **tags:** #ssh #common-services #configuration
-----------------------------------------------
# Key Based Authentication

## Generate key on Client

```bash
cd .ssh #move to the .ssh directory
ssh-keygen -t rsa -b 4096 #generate the public key
```

• `rsa` is an old algorithm based on the difficulty of factoring large numbers. A key size of at least 2048 bits is recommended for RSA; 4096 bits is better. RSA is getting old and significant advances are being made in factoring. Choosing a different algorithm may be advisable. It is quite possible the RSA algorithm will become practically breakable in the foreseeable future. All SSH clients support this algorithm.

**NOTE:** when running the last command it will ask you to name the file in which to save the key and to enter a passphrase

## Copy .pub file to server

```bash
scp file.pub user@hostname:~/ #transfer .pub file to server
```

Now it’s time to move to the server side to edit a few files

```bash
ssh user@hostname 
mkdir .ssh 
touch .ssh/authorized_keys
cat file.pub >> .ssh/authorized_keys
rm file.pub
sudo nano /etc/ssh/sshd_config #configure ssh daemon
```

## Modify ssh daemon config file

Change any necessary parameters to match the following:

- `PermitRootLogin no`
- `PubKeyAuthentication yes`
- `PasswordAuthentication no` add if missing
- Uncomment `AuthorizedKeysFile` line.

## Restart ssh daemon

```bash
sudo systemctl restart sshd
```

The setup is now completed, now you can go back to the client machine and ssh to the server using the public key authentication method. You may be asked to specify the location of your public key, in that case use the `-i` switch followed by the file-path.