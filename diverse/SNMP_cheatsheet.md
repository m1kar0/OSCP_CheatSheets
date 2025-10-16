# SNP Pentesting Cheatsheet

### What is it

* SNMP contains Management Information Base (MIB) 
* It is realated to network management
* This tree contains endpoints with values that can be accessed and probed
* google for stuff like `1.3.6.1.2.1.25.1.6.0	System Processes`

### Manual

* scan UDP port 161

`sudo nmap -sU --open -p 161 10.10.1.1-254 -oG snmp.log`

### Onesixtyone

* enurmerate community strings

`onesixtyone -c community_list -i ip_list`

find some strings in `/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt`

* look for write permissions

`snmp-check -w -c secret_string ip_addr`

* refer to those references to get RCE if writable 

https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp

https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp/snmp-rce

* if not writable then just dump all snmp outputs and scroll through them

`snmpbulkwalk -c public -v2c 192.168.192.xxx .`
