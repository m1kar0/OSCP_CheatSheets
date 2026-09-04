**BloodHound and jq** — query the raw JSON that a BloodHound ingestor produces straight from the command line with `jq` (a small tool for filtering JSON), so you can answer quick questions without starting neo4j or the GUI. Each dump is just a `.data[]` array of objects, so you filter and print exactly the fields you want — enabled users, Kerberoastable accounts, stale computers, and so on. It is fast, scriptable, and easy to pipe into your other tools.

## Basics

```shell

sudo apt install jq

# Pretty-print
cat file.json | jq '.'
# List top-level keys/branches
cat file.json | jq '. | keys'
# Key values
cat file.json | jq '. | map_values(keys)'

```

## Diving into BloodHound files

```shell

# Select the data branch (drop meta)
cat bloodhound_users.json | jq '.data[]'
# Properties of each user
cat bloodhound_users.json | jq '.data[].Properties'
# Just the name
cat bloodhound_users.json | jq '.data[].Properties | .name'
# Name + description
cat bloodhound_users.json | jq '.data[].Properties | .name + ":" + .description'

```

## Adding logic

```shell

# Enabled users, print name
cat bloodhound_users.json | jq '.data[].Properties | select (.enabled == true) | .name'
# Enabled users with a non-null description
cat bloodhound_users.json | jq '.data[].Properties | select (.enabled == true and .description != null) | .name + ":" + .description'
# Enabled users, name + lastlogontimestamp (replicated across DCs, unlike lastlogon)
cat bloodhound_users.json | jq '.data[].Properties | select (.enabled == true) | .name + ":" + (.lastlogontimestamp | tostring)'
# Enabled users who never logged in (lastlogontimestamp == -1)
cat bloodhound_users.json | jq '.data[].Properties | select (.enabled == true and .lastlogontimestamp == -1) | .name'
# Kerberoastable enabled users
cat bloodhound_users.json | jq '.data[].Properties | select (.enabled == true and .serviceprincipalnames != []) | .name + ":" + .description'
# Operating systems of computers
cat bloodhound_computers.json | jq '.data[].Properties | select (.operatingsystem != null) | .name + ":" + .operatingsystem'
# Computers whose last logon was > 2 months ago (epoch value from epochconverter.com) - likely missing updates
cat bloodhound_computers.json | jq '.data[].Properties | select (.lastlogontimestamp < 1647422796) | .name + ":" + .operatingsystem'

```

**Tip:** Use `todate` instead of `tostring` for a human-readable timestamp. A `lastlogontimestamp` of `-1` means the account never logged in - a good password-spraying candidate (e.g. `Welcome2022`).

## References

- jq - https://stedolan.github.io/jq/
