**DCShadow** — temporarily register a rogue/fake Domain Controller (mimikatz `lsadump::dcshadow`) and use directory replication to push arbitrary changes into AD (e.g. add SID History, alter `primaryGroupID`, plant ACLs) without touching a real DC's logs the usual way. Stealthy tampering/persistence (beyond OSCP).

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: Domain Admin (or equivalent replication + config-write rights).
- Two-session mimikatz flow: `lsadump::dcshadow /object:... /attribute:...` + `lsadump::dcshadow /push`.
- Example abuses (SIDHistory injection, ACL/SPN changes) and detection (rogue nTDSDSA/server object, replication from a non-DC).

## References

- The Hacker Recipes - DCShadow - https://www.thehacker.recipes/ad/persistence/dcshadow
