**NC Replication - ADCS Abuse** — Active Directory Certificate Services keeps its certificate templates and CA configuration in the Configuration NC (naming context — a partition of the directory that replicates to every DC in the forest). With admin / SYSTEM on a compromised child DC you write a deliberately weak certificate template into that partition; because the Configuration NC replicates forest-wide, the template shows up on the parent / root CA as well. You then enroll against it and run an ADCS ESC attack (one of the ESC1–ESC8 certificate-escalation techniques) to obtain a certificate for a privileged account, escalating from the child domain to the whole forest.

```
SYSTEM on child DC (DC02)
   -> write weak cert template into Configuration NC
   -> Config NC replicates forest-wide to the root CA
   -> enroll against template -> run ADCS ESC attack
   -> cert for a privileged account -> forest takeover
```

### Certify.exe

Coverting `.pem`

```powershell

# Fix formatting if needed
sed -i 's/\s\s\+/\n/g' cert.pem

# Convert to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

```