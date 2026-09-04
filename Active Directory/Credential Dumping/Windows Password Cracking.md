**Windows password cracking** — turn the scrambled password data you collect during AD attacks back into the real, typed passwords. Across these attacks you pick up several formats — NT hashes (the stored form of a Windows password), Net-NTLM responses (challenge-response proofs captured off the wire), Kerberos tickets, and cached domain credentials — and none of them can be reversed directly. Instead you guess: you feed the hash plus a wordlist to `hashcat` or `john`, they scramble each candidate password the same way and compare, and a match reveals the plaintext. It all runs offline on your own machine, so there's no account lockout or noise on the target.

## Hashcat modes

The mode (`-m`) depends on where the hash came from.

| Hash / source | Example origin | hashcat `-m` |
| --- | --- | :---: |
| NTLM (NT hash) | NTDS.dit, SAM, LSASS | 1000 |
| LM | old SAM, LM part of a dump | 3000 |
| Net-NTLMv1 | Responder in `--lm` mode, [NTLMv1 downgrade](../Coercion/NTLMv1%20Authentication%20Downgrade.md) | 5500 |
| Net-NTLMv2 | Responder / ntlmrelayx capture | 5600 |
| Kerberos AS-REP (RC4) | [AS-REP Roasting](../Kerberos%20Attacks/ASREP%20Roasting.md) | 18200 |
| Kerberos TGS-REP (RC4) | [Kerberoasting](../Kerberos%20Attacks/Kerberoasting.md) | 13100 |
| Kerberos TGS-REP (AES128 / AES256) | Kerberoasting, AES SPN | 19600 / 19700 |
| Kerberos AS-REQ Pre-Auth (RC4) | kerbrute / pre-auth capture | 7500 |
| Domain Cached Credentials (DCC / MS-Cache) | LSA secrets | 1100 |
| Domain Cached Credentials 2 (DCC2 / MS-Cache v2) | LSA secrets, [Dump Registry](Dump%20Windows%20Registry%20%28SAM-LSA%29.md) | 2100 |

**Note:** AES Kerberos AS-REP variants use their own modes - run `hashcat --help | grep -i kerberos` on your build to confirm the exact number.

## Cracking

Wordlist + rules is the default first pass. `rockyou.txt` + `best64.rule` is the OSCP staple.

```bash

# Generic form
hashcat -m MODE -a 0 HASH_FILE /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

```

```bash

# NTLM
hashcat -m 1000 nt_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Net-NTLMv2 (from Responder / relay capture)
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Kerberoast (RC4)
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AS-REP roast (RC4)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# DCC2 / MS-Cache v2 (slow - keep the wordlist tight)
hashcat -m 2100 mscache2.txt /usr/share/wordlists/rockyou.txt

```

Show cracked results (reads the potfile):

```bash

hashcat -m MODE HASH_FILE --show

```

## John the Ripper

Handy when hashcat has no GPU available. Formats: `nt`, `netntlmv2`, `krb5asrep`, `krb5tgs`, `mscash2`.

```bash

john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt
john --show --format=krb5tgs kerberoast.txt

```

`kirbi2john`, `DumpNTLMInfo.py` and similar helpers convert captured tickets into a john-readable form.

## Cracking on Windows

When you crack on a Windows host, hashes pasted from a terminal often carry stray spaces/newlines. Flatten the file first:

```powershell

# Windows
Get-Content .\hashes.txt | ForEach-Object { $_.Trim() } | Set-Content .\hashes_clean.txt

```

```bash

# Linux equivalent
cat hashes.txt | tr -d '\n' | tr -d ' '

```

Save the cleaned file as ANSI (e.g. via Notepad++) to avoid BOM/encoding issues, then run `hashcat.exe` with `--force` if it complains about the OpenCL device.

## Notes

- **Net-NTLMv1** with a fixed server challenge (`1122334455667788`) is not cracked with hashcat - submit it to https://crack.sh/ for a near-instant NT hash. See [NTLMv1 Authentication Downgrade](../Coercion/NTLMv1%20Authentication%20Downgrade.md).
- A cracked **NT hash** rarely needs cracking at all - it can be used directly for pass-the-hash. See [Windows Remote Command Execution](../Lateral%20Movement/Windows%20Remote%20Command%20Execution.md).
- Keep a curated wordlist (company name, seasons, `Welcome1`, `Password1`, keyboard walks) - AD service accounts are the usual quick wins.

## References

- Hashcat - https://hashcat.net/hashcat/
- Hashcat example hashes (mode reference) - https://hashcat.net/wiki/doku.php?id=example_hashes
- John the Ripper (jumbo) - https://github.com/openwall/john
- Crack.sh (Net-NTLMv1) - https://crack.sh/
