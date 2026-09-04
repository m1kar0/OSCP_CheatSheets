**DPAPI abuse** — pull back the passwords Windows quietly saves for people (browser logins, RDP connections, scheduled tasks, Wi-Fi, credential vaults) by decrypting them the same way Windows itself does. The Data Protection API (DPAPI) locks each of those secrets with a per-user or per-machine key called a **masterkey**, and that masterkey is in turn unlocked by the user's password. So if you have the user's password or NT hash, run as local `SYSTEM`, or hold the **domain DPAPI backup key** (a master unlock key that every DC keeps a copy of), you can decrypt the saved secrets — and the backup key opens every user's masterkey across the whole domain.

## TODO

Placeholder - full write-up pending. Should cover:
- Local: mimikatz `dpapi::` / `sekurlsa::dpapi`; SharpDPAPI (`SharpDPAPI.exe triage`).
- Remote/automated: DonPAPI, `dpapi.py` (impacket) - `backupkeys`, `masterkey`, `credential`.
- Domain backup key: `dpapi.py backupkeys --export -t DOMAIN/USER:PASS@DC_IP` → decrypt any user's masterkeys offline.
- Where the loot lives (`%APPDATA%\Microsoft\Protect`, `Credentials`, browser Login Data).

## References

- The Hacker Recipes - DPAPI protected secrets - https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets
- DonPAPI - https://github.com/login-securite/DonPAPI
- SharpDPAPI - https://github.com/GhostPack/SharpDPAPI
