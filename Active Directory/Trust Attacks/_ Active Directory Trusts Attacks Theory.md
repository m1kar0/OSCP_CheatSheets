**Active Directory Trust Attacks** — a trust is a configured link between two domains that lets users of one domain authenticate and use resources in the other, and attackers ride those links to move from a domain they already own into a neighbouring one. Once you control one domain in a large org you rarely stop there: because domains are wired together with trusts, the tickets and credentials honoured on one side are accepted on the other, opening a path for lateral movement across the whole forest and sometimes into separate forests. Mechanically a trust stores a shared inter-realm key, so a Kerberos ticket issued by one domain's DC can be validated by the other domain's DC — which is exactly what the attacks below forge, escalate, or relay.

* The base: https://blog.harmj0y.net/redteaming/the-trustpocalypse/
 
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

