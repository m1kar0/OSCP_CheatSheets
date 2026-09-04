**Golden Certificate** — the CA (Certificate Authority — the server that signs every certificate the domain trusts) holds a private key that vouches for all of them. If you steal that key, you can forge a valid login certificate for any account you like — a Domain Admin included — sign it yourself, and use it to authenticate. Because you are minting genuine certificates offline, this keeps working indefinitely, until the CA's own certificate is rotated. It is a powerful ADCS persistence trick (a.k.a. CA key theft / DPERSIST1).

```
admin on CA -> steal the CA private key
   -> forge a login cert for any account, signed with that key
   -> PKINIT with it -> TGT / NT hash as that account
```

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: admin on the CA server; extract the CA private key (`certipy ca -backup` / mimikatz `crypto::certificates /export`, DPAPI if non-exportable).
- Forge certs: `certipy forge -ca-pfx CA.pfx -upn administrator@domain.local`.
- Use the cert for PKINIT → TGT / NT hash - see [Pass the Cert](Pass%20the%20Cert.md).
- Detection + remediation (CA key rotation).

## References

- The Hacker Recipes - Certificate authority persistence - https://www.thehacker.recipes/ad/movement/adcs/certificate-templates
- SpecterOps - Certified Pre-Owned (DPERSIST1) - https://posts.specterops.io/certified-pre-owned-d95910965cd2
