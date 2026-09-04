**DCShadow** — briefly turn your machine into a fake Domain Controller so you can push arbitrary changes straight into Active Directory through the channel DCs normally use to sync with each other. Domain Controllers trust one another via replication (the process that keeps every DC's copy of the directory identical); DCShadow (mimikatz `lsadump::dcshadow`) registers a rogue DC object, then sends your edits — add SID History, alter `primaryGroupID`, plant ACLs — as if they were a legitimate replication update. Because the change arrives as normal DC-to-DC traffic rather than an ordinary object write, it sidesteps the usual change logging, making it a stealthy tampering and persistence technique (beyond OSCP).

```
mimikatz: register rogue DC in AD configuration
you stage change -> trigger replication
real DC <- pulls your "update" from the rogue DC
=> edit lands in AD as normal replication traffic
```

## TODO

Placeholder - full write-up pending. Should cover:
- Prerequisite: Domain Admin (or equivalent replication + config-write rights).
- Two-session mimikatz flow: `lsadump::dcshadow /object:... /attribute:...` + `lsadump::dcshadow /push`.
- Example abuses (SIDHistory injection, ACL/SPN changes) and detection (rogue nTDSDSA/server object, replication from a non-DC).

## References

- The Hacker Recipes - DCShadow - https://www.thehacker.recipes/ad/persistence/dcshadow
