**Snaffler** — crawls SMB shares across a Windows/AD environment to find credentials and other sensitive files ("candy") in the mountain of boring files.

## Setup

```bash

# Build from source
git clone https://github.com/SnaffCon/Snaffler.git
# Open Snaffler.sln and compile in Visual Studio
# Or grab a release binary
wget https://github.com/SnaffCon/Snaffler/releases/download/X.X.XX/Snaffler.exe

```

## Usage

```shell

# Against a specific path (skip share/computer discovery)
Snaffler.exe -s -o snaffler.log -v debug -i \\myhost.domain.local\share
# Against a specific computer
Snaffler.exe -s -o snaffler.log -v debug -n myhost.domain.local
# Against a domain with a custom ruleset (-p)
Snaffler.exe -s -o snaffler.log -v debug -d domain.local -c dc01.domain.local -p .\path\to\custom\rules
# Just list shares on target hosts (skip file enumeration)
Snaffler.exe -s -a -o snaffler.log -v debug -d domain.local -c dc01.domain.local
# Generate a default config file, then run with it
Snaffler.exe -z generate
Snaffler.exe -z snaff.toml
# From a non-domain-joined system
runas /netonly /user:DOMAIN\USER_NAME "Snaffler.exe -s -o snaffler.log -v debug -d domain.local -c dc01.domain.local"

```

## Rules

Snaffler ships default rules baked into the exe (`./Snaffler/SnaffRules/DefaultRules`); write your own and pass them with `-p`. The default rules do **not** look inside Office docs or PDFs (too slow, too much low-value noise) - build `UltraSnaffler.sln` for that.

## Caution

The Snaffler binary is often flagged by AV/EDR - rename the assembly / metadata or use a .NET packer. By default it is very noisy: with `ShareFinderEnabled` true it pulls every computer object and scans them for readable shares, which raises SMB recon alerts. For a stealthier run set `ShareFinderEnabled`, `ScanSysvol`, `ScanNetlogon` to false and target specific `ComputerTargets` / `PathTargets`.

## References

- Snaffler - https://github.com/SnaffCon/Snaffler
