**Golden Certificate** — with the Enterprise CA's private key you can forge client-authentication certificates for *any* principal, offline and indefinitely (until the CA cert is rotated). A powerful ADCS persistence primitive (a.k.a. CA key theft / DPERSIST1).

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: admin on the CA server; extract the CA private key (`certipy ca -backup` / mimikatz `crypto::certificates /export`, DPAPI if non-exportable).
- Forge certs: `certipy forge -ca-pfx CA.pfx -upn administrator@domain.local`.
- Use the cert for PKINIT → TGT / NT hash - see [Pass the Cert](Pass%20the%20Cert.md).
- Detection + remediation (CA key rotation).

## References

- The Hacker Recipes - Certificate authority persistence - https://www.thehacker.recipes/ad/movement/adcs/certificate-templates
- SpecterOps - Certified Pre-Owned (DPERSIST1) - https://posts.specterops.io/certified-pre-owned-d95910965cd2
