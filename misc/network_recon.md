# Network Recon

Not a replacement for official docs but a rapid reference

### Ping Scan

```bash

nmap -sn -T4 -n -vvv -oA ping_hosts -iL range.txt
grep Up ping_hosts.gnmap | cut -d ' ' -f 2 > hosts.txt

#get ips as a result
```

* Wont work if ICMP ping requests are blocked
* advantage of using own custom script is that you can tune its parameters to suit your needs. Like changing the ping packet size
* one of such scripts is my tool: `ReconTools\ping_sweeper.py`

### SYN-scan

* make a half handshake
* was considered stealthy but its no more with NGFWs
* may also disclose the anonimity of user since it uses `sudo` under which some system information is include into raw sockets

`nmap -sS 10.11.11.3`

### TCP-scan

* slower than SYN
* bypasses some FW rules

`nmap -sT -p445 10.11.11.3`

Another possibility is nc

```bash
# sweep for 445 port
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445 ; done &> output.txt

# filter for non timed out conntection

grep -v 'timed out' output.txt
```

### UDP-scan

* finds UDP ports with some support of ICMP
* so if ICMP is blocked its gonna fail
* good practice is combine with TCP scan to have a full picture of target

`nmap -sTU 10.11.11.3`

### Banner grabing and service enumeration with scripts

* Provides a full and reliable source for info over tcp ports

`nmap -sVC -sT -A 10.11.11.3`

### Masscan

FAst scan over a large network is better to do with masscan.

`sudo masscan -p80 10.10.1.0/24 --rate=10000 -e tun0 --router-ip 10.10.0.1`

#### Find ports fast

masscan -p- --rate 10000 10.10.45.xx

-> adjust fullscan script  with that
