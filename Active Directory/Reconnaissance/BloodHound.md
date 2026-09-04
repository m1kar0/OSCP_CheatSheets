**BloodHound** — a tool that loads the AD data an ingestor collected into a graph database and then finds the shortest chains of abusable rights leading from an account you control to Domain Admin. It models users, groups, sessions, and ACLs (an ACL is an object's permission list) as nodes and edges, so instead of eyeballing thousands of objects you just ask "who can reach this target" and read the path off a graph. Collection is covered in [BloodHound Ingestors](BloodHound%20Ingestors.md).

## Getting started

1. Start `neo4j`:

```bash

sudo neo4j console  # console mode
sudo neo4j start    # daemon

```

2. Set a password: open `http://localhost:7474/browser/`, log in with the default `neo4j:neo4j`, and change it.

3. Start `bloodhound`:

```bash

bloodhound

```

Make sure the URL is `bolt://localhost:7687` and enter your `neo4j` credentials. If the screen is blank, press `Ctrl+R`.

## Import data

Two ways to import the ingestor output:
- Drag and drop the JSON/ZIP files into the GUI.
- Click **Upload Data** (top-right toolbar) and select the files.

The Upload Status window shows progress per file.

## Analyze the data

BloodHound ships with default queries (Analysis menu). Add more by editing `~/.config/bloodhound/customqueries.json` or importing community query sets (e.g. hausec's, Certipy's). Specific queries are covered per technique - see [Kerberoasting](../Kerberos%20Attacks/Kerberoasting.md), [ASREP Roasting](../Kerberos%20Attacks/ASREP%20Roasting.md).

## Clear the database

When done: Database Info menu > Clear Database > Refresh Database Stats.

## References

- BloodHound - https://github.com/BloodHoundAD/BloodHound
- BloodHound docs - https://bloodhound.readthedocs.io/en/latest/index.html
