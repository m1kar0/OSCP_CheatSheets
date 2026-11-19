# Review backlog

Findings from the vault review of 2026-11-16 that were **not** fixed in that round. Mechanical defects (broken commands, `cme` → `nxc`, dead links, fences) were fixed; everything here needs a decision or new content.

Line numbers are from the review and may have moved by a few lines.

---

## Commands that are still wrong or doubtful

| Where | Problem | Why it was left |
|---|---|---|
| `Active Directory/ACL Attacks/Shadow Credentials Attack Guide.md:136` | `certipy s4u -pfx …` | Certipy has no `s4u` subcommand (its commands are account, auth, ca, cert, find, forge, parse, relay, req, shadow, template). The step needs rewriting, probably as `certipy auth` followed by impacket `getST.py` |
| `Active Directory/ADCS Attacks/ADCS Configuration Issues (ESC1-8).md:16-24` | `certipy find … -old-bloodhound` / `-bloodhound`, and the note about "forked BloodHound" | Both flags are gone in Certipy v5 (`find` now has `-text`, `-stdout`, `-json`, `-csv`, `-output`). No drop-in replacement, so the paragraph needs rewriting. `-username` further down is still valid |
| `Active Directory/Reconnaissance/Pre-Windows 2000 Computers.md:51` | `nxc smb dc01.domain.local --kerberos` after exporting `KRB5CCNAME` | Probably wants `--use-kcache` as well. Not confirmed |
| `Active Directory/Known Exploits/EternalBlue (MS17-010).md:96` | `python2 eternalblue_exploit7.py` | The exploit is Python 2 only; needs a note or a maintained alternative |
| `Windows/Windows_PrivEsc_cheatsheet.md:932` | Heading "PrintSpoofer" sits over PrintNightmare (CVE-2021-1675) steps; the real PrintSpoofer part starts at :963 | Needs splitting into two sections, and the PrintNightmare half duplicates `Active Directory/Known Exploits/PrintNightmare.md` |
| `Windows/Windows_PrivEsc_cheatsheet.md:1201` | `run killav` (a Meterpreter command) inside a PowerShell block | Unclear what was intended |
| `Windows/Windows_PrivEsc_cheatsheet.md:100, 540` | `wmic` one-liners | `wmic` is off by default from Windows 11 24H2; add a `Get-CimInstance` form. The unquoted-path one-liner is also there twice |
| `Windows/Windows_PrivEsc_cheatsheet.md:381, 806-811, 1014, 1031` | Sherlock, `pth-winexe`, Watson | Deprecated tools; replace or mark as legacy |
| `Linux/linux_cheatsheet.md:201` | Cron example has six time fields under a five-field header; the whole explanation is prose inside a bash fence (180-204) | Intended schedule is ambiguous |
| `misc/mail_cheatsheet.md:78` | Points at `../eMail/vrfy.py`, which is not in the vault | Script missing |
| `misc/hashcracking_cheatsheet.md:91` | `hcxdumptool --active_beacon --enable_status` looks like the old 6.2 syntax; `misc/wifi_cheatsheet.md:112` uses the newer flags | Not confirmed |
| `Persistence/powershellEmpire_cheatsheet.md:76-77` | Sets IP `192.168.115.111`, the output below shows `192.168.119.158` | Cosmetic |
| `AWS/AWS Offensive Field Guide.md:81` | "Four tools cover 90%" above a six-row table | The text further down says "core four", so this may be intended |

## Stubs and empty notes

- `Active Directory/Trust Attacks/Cross Forest Attacks/Golden dMSA.md` (empty)
- `## TODO` placeholders, all under `Active Directory/` (11 notes): `ADCS Attacks/Golden Certificate.md`, `ADCS Attacks/UnPAC-the-hash.md`, `Credential Dumping/DPAPI.md`, `Credential Dumping/Dump LSASS.md`, `Kerberos Attacks/Timeroasting.md`, `MSSQL Attacks/Linked Server Abuse.md`, `Persistence/AdminSDHolder.md`, `Persistence/DCShadow.md`, `Persistence/DSRM Password.md`, `Persistence/Skeleton Key.md`, `Trust Attacks/Intra Forest Attacks/GPO Abuse.md`
- `Active Directory/Trust Attacks/Cross Forest Attacks/Cross-Forest Kerberoasting.md` (14 lines, no headings)
- `Active Directory/Active Directory cheatsheet.md:93` (`TBD`), `Windows/Windows_PrivEsc_cheatsheet.md:425` (`TBD`)
- `WEB/Web Vulns/Universal XSS.md` (one line)
- `Linux/Interesting PrivEsc Tasks.md` (asks the `tar *` wildcard question at :17 and never answers it)
- `misc/hw_hacking.md` (17 lines), `K8s/K8s_cheatsheet.md` (25 lines of admin `kubectl`, nothing offensive; `AWS/…:257-274` has more K8s attack content)
- Empty sections: `Persistence/pivoting_persistence_cheatsheet.md` "DNS tunneling"; `misc/DNS_cheatsheet.md:92, 117-121, 151`; `Android/Android Cheatsheet.md:60, 203, 234, 279`

## Missing topics

**Web** (outside the OSWE syllabus, so not written this round)

- Admin panel to shell: Tomcat manager WAR deploy, Jenkins script console, WebDAV `PUT`, phpMyAdmin, Werkzeug debug console
- Business logic flaws
- Deserialization deep dives for Java, PHP and Python, in the style of `Deserialization (.NET).md`
- Handlebars and older-Pug prototype pollution gadgets (documented, not tested)

**Active Directory**

- ADCS ESC9 to ESC16 (the existing note stops at ESC8)
- dMSA / BadSuccessor
- Pass-the-Hash, Overpass-the-Hash and Pass-the-Ticket as their own notes (now only in the cheatsheet at :549, :588)
- SCCM takeover and elevate paths (only NAA and distribution points are covered)
- Entra ID / hybrid: Entra Connect sync account, PRT
- NTLM reflection CVE-2025-33073
- Exchange paths (PrivExchange, Exchange Windows Permissions)
- MSSQL beyond linked servers: `xp_cmdshell`, impersonation, UNC path capture
- RODC attacks
- Protected Users as a precondition in the relay notes
- A decision flow: what to try with network access only, with a user, with local admin, with DA

**Linux privesc**: GTFOBins workflow, wildcard injection, NFS `no_root_squash`, docker and disk groups, systemd timers, capability exploitation (only listing at :77), choosing a kernel exploit, TTY upgrade, restricted-shell escapes beyond vim.

**Windows privesc**: `whoami /priv` as a first step, SeBackup / SeRestore / SeDebug abuse, GodPotato / SweetPotato / EfsPotato (the table stops at Rogue Potato), unattend files, SAM/SYSTEM backup locations, AlwaysInstallElevated registry query and msfvenom line, a UAC bypass that does not already need admin.

**General**

- Service enumeration by port (FTP, SSH, SMB, RDP, MySQL, Redis, NFS…). There is no port index anywhere
- Reverse shells, shell stabilisation and file transfer in both directions, with an msfvenom payload table
- Password attacks: hydra per service, hashcat mode table, cewl and rules, hash identification
- Pivoting: ligolo-ng, `netsh portproxy`, a double-pivot walkthrough

## Structure

- **Misfiled:** `Persistence/SNMP_cheatsheet.md` (service enumeration), `Persistence/Metasploit_CheatSheet.md` (intro note), `Persistence/pivoting_persistence_cheatsheet.md` (almost all pivoting), `Linux/x-compile-cheatsheet.md` (mostly Windows builds, repeated at `Windows/Windows_PrivEsc_cheatsheet.md:1110-1121`).
- **AD content inside the Windows cheatsheet:** GPO backdoor (:251), DPAPI (:436-467), ADCS/Certify (:972-1001), WMI/winrs/WinRM (:1042-1090), GPP (:1104).
- **The AD cheatsheet (1,109 lines) links to none of the deep-dive notes** and repeats several of them (delegation :1002, relay :1056, skeleton key :884). Either make it an index or split it.
- **Duplicates:** Kerberos relay to ADCS (`Relay Attacks/mitm6 relay/Kerberos to ESC-8 relay.md` and `Relay Attacks/Kerberos Relay/Kerberos Relay to ADCS.md`); unconstrained delegation (`Delegation Attacks/` and `Trust Attacks/Intra Forest Attacks/`); relay overviews (`_Intro to Relay Attacks.md` and `NTLM Relay/NTLM Relay.md`); `GPO Abuse.md` and `GPO Onsite Attack.md`; WiFi cracking in `misc/hashcracking_cheatsheet.md` and `misc/wifi_cheatsheet.md`; VBA macros in `misc/social_engineering.md` and `Phishing/Malicious Office Macros (VBA).md`.
- **Notes off the AD template:** `ACL Attacks/Shadow Credentials Attack Guide.md` (no References, inline example values), most of `Trust Attacks/` (no Discovery / Exploitation / References), `_Intro to Relay Attacks.md` (no References). Two hub notes are named `_ Name` with a space instead of `_Intro to …`.
- **File naming:** six conventions in use (`linux_cheatsheet`, `Metasploit_CheatSheet`, `powershellEmpire_cheatsheet`, `x-compile-cheatsheet`, `AWS Offensive Field Guide`, `hw_hacking`). Seven notes have no H1.
- **Links:** `WEB/` uses `[[wikilinks]]`, which do not render on GitHub; `Active Directory/` uses relative markdown links, which do. The in-file tables of contents use GitHub-style anchors, which Obsidian does not follow (use the Outline pane there).
- **`AWS/AWS Offensive Field Guide.md`:** no code fence has a language tag, and callout labels are flattened into body text (:19, :43).
- **`misc/hashcracking_cheatsheet.md:8-52`** is pasted from the crunch man page; a second H1 sits at :110.

## Housekeeping

- `WEB/Recon/web_attack_surface_recon.md` named a real domain as an example (now a placeholder). It is still in git history at commit `812cdca`.
- `WEB/Web Scripts/postgres-udf/udf_pg16_amd64.so` is a compiled binary for PostgreSQL 16 on x86-64. Rebuild from `udf.c` for any other version; the build command is in `PostgreSQL SQLi to RCE.md`.
