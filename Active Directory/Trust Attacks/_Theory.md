 Once you have compromised a domain within a large Corp you may need to continue compromising its other domains. Domains share Trusts between each other making such lateral movement possible:
 
## Active Directory Trust Relationships

**Intra-forest trusts** let domains inside the same forest share resources and authenticate users with each other.

**Cross-forest trusts** extend this communication between completely separate forests.

### Common Trust Types

- **Parent-Child Trust**  
  Automatically created when a new child domain is added to a forest. The parent and child domains trust each other bidirectionally.

- **Tree-Root Trust**  
  Automatically established between the root domains of different domain trees inside the same forest.

- **Shortcut (Cross-Link) Trust**  
  A manual trust between two child domains in different trees of the same forest. It reduces authentication hops and can be one-way or two-way.

- **External Trust**  
  A non-transitive trust between a domain in one forest and a domain in another forest. Used when no forest-wide trust exists.

- **Forest Trust**  
  A transitive trust created between the root domains of two separate forests. Allows users from one forest to access resources in the other.

- **Realm Trust**  
  Connects a Windows Active Directory domain to a non-Windows Kerberos realm (e.g., Linux/UNIX). Enables cross-platform resource access.

Parent-Child and Forest Trust are the most frequent.

