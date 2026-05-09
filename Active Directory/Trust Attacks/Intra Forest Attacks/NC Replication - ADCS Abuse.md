
1. Create vulnerable template on DC02 
2. Enroll it
3. perform ESC-X attack



### Certify.exe

Coverting `.pem`

```powershell

# Fix formatting if needed
sed -i 's/\s\s\+/\n/g' cert.pem

# Convert to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

```