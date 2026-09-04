**BloodHound** — after collecting Active Directory data (users, groups, sessions, ACLs) with an ingestor, BloodHound analyzes it and reveals privilege-escalation paths. Collection is covered in [BloodHound Ingestors](BloodHound%20Ingestors.md).

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
