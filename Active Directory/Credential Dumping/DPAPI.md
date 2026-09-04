**DPAPI abuse** — the Windows Data Protection API encrypts saved credentials (browsers, RDP, scheduled tasks, Wi-Fi, vaults) under per-user/machine masterkeys. With a user's password/hash, local SYSTEM, or the **domain DPAPI backup key** (from a DC), those secrets can be decrypted - domain-wide with the backup key.

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
