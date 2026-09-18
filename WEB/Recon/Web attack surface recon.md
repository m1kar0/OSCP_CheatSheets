



```

passive names ──► AXFR ──► wildcard check ──► brute ──► permutations ──► resolve

│

delegation defects ◄── IP pivot ◄── takeover ◄──────┘

```

  

Wildcard detection comes *before* brute force, because on a wildcard zone an unfiltered brute
invents thousands of hosts. Permutations come *after* you have live names, because permuting
guesses multiplies guesses while permuting confirmed names mutates real naming conventions.

  

Only run the active stages (AXFR, brute force, resolution at volume, port scans) against targets
you are authorised to test. 

---

  

## Contents

  

- [Toolbox](#toolbox) · [Setup](#setup) · [Rules of engagement](#rules-of-engagement)

- [1. Passive names](#1-passive-names) · [2. Zone transfer](#2-zone-transfer-axfr) · [3. Wildcards](#3-wildcards--check-before-you-brute)

- [4. Brute force](#4-brute-force) · [5. Permutations](#5-permutations) · [6. Consolidate and resolve](#6-consolidate-and-resolve)

- [7. Delegation defects and DNS hijacking](#7-delegation-defects-and-dns-hijacking)

- [8. IP addresses](#8-ip-addresses-reverse-certificates-ranges-vhosts) · [9. Takeover](#9-subdomain-takeover) · [10. Web surface](#10-web-surface-and-ports)

- [11. Keep these outputs](#11-keep-these-outputs) · [Gotchas](#gotchas) · [What not to do](#what-not-to-do)

  

---

  

## Toolbox

  

| Job | Tool |

|---|---|

| passive subdomains | `subfinder`, `assetfinder`, `amass` |

| certificate transparency | `curl` + `crt.sh`, or `tlsx` |

| URL history | `gau`, `waybackurls`, `urlfinder`, `waymore` |

| crawling | `katana` |

| DNS resolution at volume | `puredns` (+`massdns`), `dnsx`, `shuffledns` |

| brute force | `puredns bruteforce`, `dnsx -w`, `shuffledns` |

| permutations | `alterx`, `gotator` |

| takeover | `dnsreaper`, `nuclei -tags takeover`, `dnstake` |

| IP pivot | `dnsx -ptr`, `tlsx`, `asnmap`, `mapcidr`, `cdncheck`, `hakip2host` |

| web probing | `httpx`, `naabu` |

| plumbing | `anew`, `unfurl`, `dsieve`, `jq` |

| attack-surface database | `bbrf` (CouchDB-backed) |

  

---

  

## Setup

  

Per target. Everything below assumes these variables and this working directory.



```bash

D=example.com # the apex you are testing

OUT=~/recon/$D

L=~/recon/lists

mkdir -p "$OUT" "$L" && cd "$OUT"

  

# resolver lists

curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \

-o "$L/resolvers.txt" # ~11k public resolvers

printf '1.1.1.1\n1.0.0.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n' > "$L/resolvers-trusted.txt"

  

R="$L/resolvers.txt" # public: fast first pass

RT="$L/resolvers-trusted.txt" # trusted: validate results, and every ad-hoc dig

W=/usr/share/seclists/Discovery/DNS

RPS=1000 # queries/sec against public resolvers

  

# a small permutation list, enough for most estates

printf 'dev\nstaging\nstage\ntest\nuat\nqa\nprod\nadmin\napi\ninternal\nold\nnew\nbackup\nvpn\nmail\n' \

> "$L/perms.txt"

```

  
**Two resolver lists, not one!**


```bash

dnsvalidator -tL "$R" -threads 200 -o "$L/resolvers-checked.txt"

```

  
| List | Size | Use when |

|---|---|---|

| `$W/subdomains-top1million-5000.txt` | 33 KB | quick pass, recursion into parents |

| `$W/subdomains-top1million-20000.txt` | 149 KB | sensible default |

| `$W/subdomains-top1million-110000.txt` | 1.1 MB | thorough single pass |

| `$W/bitquark-subdomains-top100000.txt` | 1.4 MB | different corpus — a complement, not a replacement |

| `$W/n0kovo_subdomains.txt` | 51 MB | when the estate *is* the engagement; hours |

  

---

  

## A database instead of flat files

  
[BBRF](https://github.com/honoki/bbrf-client) is that store: a CouchDB behind a small CLI.


### Backend, once

  

```bash

docker run -d --name bbrf-couchdb -p 5984:5984 \

-e COUCHDB_USER=bbrf -e COUCHDB_PASSWORD='<password>' couchdb:3

  

mkdir -p ~/.bbrf && cat > ~/.bbrf/config.json <<'JSON'

{

"username": "bbrf",

"password": "<password>",

"couchdb": "http://localhost:5984/bbrf",

"slack_token": "",

"discord_webhook": "",

"ignore_ssl_errors": true

}

JSON

```

  

The database itself needs its design documents (the views BBRF queries) created once — follow

[bbrf-server](https://github.com/honoki/bbrf-server), which also covers the hosted setup if you

would rather not run CouchDB yourself.

  

### Per target, once

  

```bash

bbrf new "$D" # create the program

bbrf use "$D" # make it active for subsequent commands

bbrf inscope add "$D" "*.$D" # scope: everything under the apex

bbrf outscope add "blog.$D" # anything explicitly excluded by the engagement

bbrf scope in # show what you just declared

```

  

The pattern is always the same: keep the flat file for the next command in the chain, and push the same data into the BBRF DB.

```bash

# → BBRF

cat passive.txt | bbrf domain add - -s passive --show-new

```

  

`-s <source>` is provenance and it is worth the keystrokes: six months later "who told me about
this host" is the difference between a defensible report and a guess. 

  

---


  

## 1. Passive names

  

Nothing here touches the target's infrastructure.

  

### 1.1 Aggregators

  

```bash

subfinder -d "$D" -all -silent | tee -a passive.txt | bbrf domain add - -s subfinder --show-new

assetfinder --subs-only "$D" | tee -a passive.txt | bbrf domain add - -s assetfinder --show-new

```

  
### 1.2 Certificates

  

```bash

curl -s --retry 3 --retry-delay 5 --max-time 60 "https://crt.sh/?q=%25.$D&output=json" \

| jq -r '.[].name_value' \

| sed 's/\*\.//g' | tr 'A-Z' 'a-z' | sed 's/\r$//' \

| tee -a passive.txt | bbrf domain add - -s crtsh --show-new

```

  

crt.sh is slow and rate-limits
  

### 1.3 URL history


Archived URLs and JavaScript mention hosts no DNS source lists. 
  

```bash

gau --subs "$D" | anew urls.txt

waybackurls "$D" | anew urls.txt

urlfinder -d "$D" -all -silent | anew urls.txt

waymore -i "$D" -mode U -oU waymore_urls.txt && cat waymore_urls.txt | anew urls.txt

  

unfurl -u domains < urls.txt | tee -a passive.txt | bbrf domain add - -s urlhistory --show-new

  

# → BBRF: the URLs themselves are worth keeping, not just their hostnames

cat urls.txt | bbrf url add - -s urlhistory --show-new

```

  

Tool-free fallback — useful when a tool is throttled or missing:

  

```bash

curl -sG --retry 3 --retry-delay 2 --max-time 120 "http://web.archive.org/cdx/search/cdx" \

--data-urlencode "url=*.$D/*" --data-urlencode "fl=original" \

--data-urlencode "collapse=urlkey" \

| unfurl -u domains | anew passive.txt

  

curl -s --max-time 30 "https://otx.alienvault.com/api/v1/indicators/domain/$D/passive_dns" \

| jq -r '.passive_dns[]?.hostname' | anew passive.txt

```

  

### 1.4 Crawl

  

```bash

# crawl the known web surface, JavaScript included

katana -u "https://$D" -jc -kf all -d 3 -fs fqdn -silent -o crawl.txt

unfurl -u domains < crawl.txt | tee -a passive.txt | bbrf domain add - -s katana --show-new

cat crawl.txt | bbrf url add - -s katana --show-new

  

# hosts referenced only in Content-Security-Policy headers

curl -sI "https://$D" | grep -i '^content-security-policy' \

| grep -oE '[a-z0-9.-]+\.[a-z]{2,}' | anew passive.txt

```

  
### 1.5 Passive DNS
  

```bash

# get a free key at virustotal.com and export it
  

vt "domains/$D/subdomains?limit=40" | jq -r '.data[].id' \

| tee -a passive.txt | bbrf domain add - -s virustotal --show-new

vt "domains/$D/resolutions?limit=40" | jq -r '.data[].attributes | "\(.ip_address)\t\(.date)"'

vt "ip_addresses/<IP>/resolutions?limit=40" | jq -r '.data[].attributes.host_name'

vt "domains/$D/historical_ssl_certificates?limit=10" \

| jq -r '.data[].attributes.extensions.subject_alternative_name[]?' | anew passive.txt

vt "domains/$D/historical_whois?limit=10" | jq -r '.data[].attributes.whois_map."Name Server"?'

```

  
---

  
## 2. Zone transfer (AXFR)

  

A successful transfer hands you the whole zone: every name, plus MX, TXT and SRV records and the internal naming scheme. 
  

```bash

dnsx -l passive.txt -ns -resp -silent -nc \
  | sed 's/[][]//g' \
  | awk '{
      zone=$1
      ns=$(NF)
      sub(/\.$/, "", zone)
      sub(/\.$/, "", ns)
      if (zone != "" && ns != "" && ns != "NS")
        print zone, ns
    }' \
  | sort -u > zone_ns.txt

wc -l < zone_ns.txt
: > axfr_hits.txt

while read -r zone ns; do
  [ -n "$zone" ] && [ -n "$ns" ] || continue
  if dig +time=3 +tries=1 +noall +answer AXFR "$zone." @"$ns" 2>/dev/null \
      | grep -qE '[[:space:]]IN[[:space:]]'; then
    safe_zone=${zone//\//_}
    safe_ns=${ns//\//_}
    echo "TRANSFERRED: $zone via $ns" | tee -a axfr_hits.txt
    dig +noall +answer AXFR "$zone." @"$ns" > "axfr_${safe_zone}_${safe_ns}.txt"
  fi
done < zone_ns.txt

```


Or just: 
  

```bash

dnsrecon -d "$D" -t axfr

dnsenum --noreverse "$D"

```

  


```bash

# → BBRF

grep -hoE '^[a-z0-9_.-]+' axfr_*.txt 2>/dev/null | sed 's/\.$//' | sort -u \

| tee -a passive.txt | bbrf domain add - -s axfr --show-new

```

  

---

  

## 3. Wildcards — check before you brute

  

If `*.$D` resolves, every random name "exists". Wildcards are frequently **per-subtree** and can be A-only, AAAA-only or CNAME-only, so probe several random labels at several depths.

  

```bash

for level in "$D" "dev.$D" "internal.$D" "staging.$D"; do

for i in 1 2 3; do echo "wc$(openssl rand -hex 6).$level"; done

done | dnsx -a -aaaa -cname -resp -silent -nc -r "$RT" </dev/null | tee wildcard_probe.txt

```



---

  

## 4. Brute force



```bash

puredns bruteforce "$W/subdomains-top1million-110000.txt" "$D" \

-r "$R" --resolvers-trusted "$RT" \

-l "$RPS" --rate-limit-trusted 400 \

--wildcard-tests 30 --wildcard-batch 1000000 \

--write-wildcards wildcards.txt -w brute.txt

```

  

- `brute.txt` — live names, wildcard noise removed

- `wildcards.txt` — the wildcard roots themselves, e.g. `*.dev.$D`

  

```bash

# → BBRF

cat brute.txt | bbrf domain add - -s bruteforce --show-new

```

  
  

```bash

dnsx -d "$D" -w "$W/subdomains-top1million-20000.txt" \

-wd "$D" -wt 5 -r "$RT" -t 100 -rl "$RPS" -silent -o brute_dnsx.txt

  

shuffledns -d "$D" -w "$W/subdomains-top1million-20000.txt" -r "$R" \

-mode bruteforce -o brute_shuffle.txt

```



### NOERROR sweep

  

A name can exist in the zone with no A record at all — invisible to a normal brute. Check for DNSSEC "black lies" first, or every random label answers NOERROR and the sweep is pure noise:

  

```bash

probe="zz$(openssl rand -hex 6).$D"

if echo "$probe" | dnsx -rc noerror -r "$RT" -silent | grep -q .; then

echo "black lies: the NOERROR sweep is useless on this zone"

else

dnsx -d "$D" -w "$W/subdomains-top1million-20000.txt" \

-rc noerror -r "$RT" -t 100 -rl "$RPS" -silent -o noerror.txt

fi

```

  

### Recursion - Go deeper

  

```bash

dsieve -f 3 < passive.txt | sort | uniq -c | sort -rn | head -20 | awk '{print $2}' > parents.txt

  

while read -r p; do subfinder -d "$p" -all -silent; done < parents.txt | anew passive.txt

while read -r p; do

puredns bruteforce "$W/subdomains-top1million-5000.txt" "$p" \

-r "$R" --resolvers-trusted "$RT" -l "$RPS" --wildcard-tests 30

done < parents.txt | anew brute_recursive.txt

```

  

---

  

## 5. Permutations

  

Run these **after** you have live names.

  

```bash

alterx -l live.txt -silent | anew perm_candidates.txt

  

# or, with an explicit word list

gotator -sub live.txt -perm "$L/perms.txt" -depth 1 -numbers 3 -mindup -silent \

| anew perm_candidates.txt

  

puredns resolve perm_candidates.txt \

-r "$R" --resolvers-trusted "$RT" -l "$RPS" \

--wildcard-tests 30 --write-wildcards wildcards_perm.txt -w perm.txt

  

# → BBRF

cat perm.txt | bbrf domain add - -s permutation --show-new

```

  

`-depth 2` and above grows the candidate list explosively — start at 1 and only go deeper if

depth 1 produced hits.

  

---

  

## 6. Consolidate and resolve

  

```bash

# one line per in-scope apex

printf 'example.com\nexample.net\n' > apexes.txt

  

in_scope() { # names on stdin -> in-scope names on stdout

awk 'NR==FNR{apex[$0];next}

{n=tolower($1); sub(/\.$/,"",n)

for (a in apex) if (n==a || n ~ ("\\." a "$")) { print n; next } }' apexes.txt -

}

  

cat passive.txt brute.txt brute_recursive.txt perm.txt noerror.txt 2>/dev/null \

| in_scope | anew all_names.txt

  

# final resolution: wildcard-filtered, trusted-validated

puredns resolve all_names.txt -r "$R" --resolvers-trusted "$RT" -l "$RPS" \

--wildcard-tests 30 --write-wildcards wildcards_final.txt -w live.txt

  

dnsx -l live.txt -a -aaaa -cname -resp -silent -nc -r "$RT" </dev/null -o resolved.txt

dnsx -l live.txt -a -resp-only -silent -r "$RT" </dev/null | sort -u > ips.txt

```
  

```bash

# → BBRF: resolving names, the addresses, and the links between them

cat live.txt | bbrf domain add - -s resolved --show-new

cat ips.txt | bbrf ip add - -s resolved --show-new

  

dnsx -l live.txt -a -resp -silent -nc -r "$RT" </dev/null \

| sed 's/\[//g; s/\]//g' | awk '$2=="A"{print $1":"$3}' | sort -u > domain_ip.txt

cat domain_ip.txt | bbrf domain update - -s dnsx

awk -F: '{print $2":"$1}' domain_ip.txt | bbrf ip update - -s dnsx

  

# the wildcard roots are worth recording as knowledge, not noise

cat wildcards_final.txt 2>/dev/null | bbrf domain add - -s wildcard --show-new --ignore-scope

```

  
Never run the raw, unfiltered list through `dnsx -recon` on a wildcard domain and call the result "extra IPs" — every fictional name answers.

  

---

  

## 7. Delegation defects and DNS hijacking

  

Subdomain takeover is about a dangling CNAMEs.
  

### 7.1 Lame delegation



```bash

dig +short NS "$D" @1.1.1.1 | sed 's/\.$//' | sort -u > ns.txt

while read -r ns; do

out=$(dig +norecurse +noall +comments SOA "$D" @"$ns" 2>/dev/null)

st=$(printf '%s\n' "$out" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)

aa=$(printf '%s\n' "$out" | grep -qE 'flags:[^;]* aa' && echo yes || echo NO)

printf '%-40s status=%-9s authoritative=%s\n' "$ns" "${st:-NOANSWER}" "$aa"

done < ns.txt

```

  

A healthy set is `status=NOERROR authoritative=yes` on every line. **Finding:** any `REFUSED`,

`SERVFAIL`, `NOANSWER`, or `NOERROR` with `authoritative=NO`.

  

### 7.2 A nameserver on a domain you can buy

  
The highest-impact check here. If an NS hostname sits under a domain that is unregistered, whoever registers it becomes authoritative for the zone.

  

```bash

awk -F. '{print $(NF-1)"."$NF}' ns.txt | sort -u | while read -r apex; do

w=$(whois "$apex" 2>/dev/null)

printf '%s' "$w" | grep -qiE 'no match|not found|no data found|no entries found|status:[[:space:]]*free' \

&& echo "UNREGISTERED -> $apex" || echo "registered -> $apex"

done

```

  

Every line prints, so a clean result reads `registered` on each apex rather than an empty screen.

  

### 7.3 Dangling CNAME and MX

  

```bash

dnsx -l live.txt -cname -resp-only -silent -r "$RT" </dev/null | sed 's/\.$//' | sort -u > cname_targets.txt

dnsx -l cname_targets.txt -rc nxdomain -silent -r "$RT" </dev/null | tee dangling_cname.txt

  

dig +short MX "$D" @1.1.1.1 | awk '{print $2}' | sed 's/\.$//' | sort -u > mx.txt

dnsx -l mx.txt -rc nxdomain -silent -r "$RT" </dev/null | tee dangling_mx.txt

  

printf 'cname targets: %s | dangling: %s\nmx targets: %s | dangling: %s\n' \

"$(wc -l < cname_targets.txt)" "$(wc -l < dangling_cname.txt)" \

"$(wc -l < mx.txt)" "$(wc -l < dangling_mx.txt)"

```

  

### 7.4 SPF include and DMARC rua

  

```bash

spf=$(dig +short TXT "$D" @1.1.1.1 | tr -d '"' | grep -i '^v=spf1' || true)

printf '%s\n' "$spf" | tr ' ' '\n' \

| grep -oiE '(include:|redirect=)[^ ]+' | sed 's/^[^:=]*[:=]//' | sort -u > spf_targets.txt

  

dmarc=$(dig +short TXT "_dmarc.$D" @1.1.1.1 | tr -d '"' || true)

printf '%s\n' "$dmarc" | grep -oiE '(rua|ruf)=mailto:[^;,]+' | sed 's/.*@//' | sort -u > dmarc_targets.txt

  

echo "spf targets : $(tr '\n' ' ' < spf_targets.txt)"

echo "dmarc targets: $(tr '\n' ' ' < dmarc_targets.txt)"

echo "dangling : $(cat spf_targets.txt dmarc_targets.txt | sort -u \

| dnsx -rc nxdomain -silent -r "$RT" </dev/null | tr '\n' ' ')"

```


  

```bash

git clone --depth 1 https://github.com/MattKeeley/Spoofy /opt/Spoofy \

&& python3 -m pip install -r /opt/Spoofy/requirements.txt

python3 /opt/Spoofy/spoofy.py -d "$D"

```

  

### 7.5 Parent versus child NS

  

```bash

tld=${D##*.}

tldns=$(dig +short NS "$tld." | head -1)

dig +noall +authority +answer NS "$D" @"$tldns" \

| awk '$4=="NS"{print tolower($5)}' | sed 's/\.$//' | sort -u > ns_parent.txt

dig +short NS "$D" @1.1.1.1 | tr 'A-Z' 'a-z' | sed 's/\.$//' | sort -u > ns_child.txt

diff ns_parent.txt ns_child.txt && echo "delegation consistent"

```

  

### 7.6 DNSSEC state

  

```bash

dig +short DS "$D" @1.1.1.1

dig +dnssec +noall +answer SOA "$D" @1.1.1.1 | grep RRSIG

delv @1.1.1.1 "$D" A 2>&1 | head -3

```

  
### 7.7 NSEC / NSEC3 zone walk
  

```bash

dnsrecon -d "$D" -t zonewalk

```

  


  

## 8. IP addresses: reverse, certificates, ranges, vhosts

  
  

```bash



cat ips.txt | cdncheck -silent -resp > cdn_tagged.txt

  

# reverse DNS

dnsx -l ips.txt -ptr -resp-only -silent -r "$RT" </dev/null | sort -u > ptr.txt

  

# names inside the TLS certificates those addresses serve

tlsx -l ips.txt -san -cn -ro -silent </dev/null | sort -u > tls_names.txt

  

# other names pointing at the same address

cat ips.txt | hakip2host | sort -u > ip2host.txt

  

# ASN space
asnmap -i "$(head -1 ips.txt)" -silent | mapcidr -silent > asn_cidrs.txt

  

# feed everything

cat ptr.txt tls_names.txt ip2host.txt | in_scope | anew all_names.txt

  

# → BBRF

cat ptr.txt tls_names.txt ip2host.txt | bbrf domain add - -s ippivot --show-new

awk '{print $1}' cdn_tagged.txt 2>/dev/null | bbrf ip update - -t cdn:true

cat asn_cidrs.txt | bbrf ip add - -s asnmap --show-new --ignore-scope

```

  

```bash

naabu -l ips.txt -tp 1000 -rate 500 -silent -o ports.txt

nmap -sV -iL ips.txt -oA nmap_estate

```

  

Virtual hosting hides names behind a single address: if you suspect it, use `ffuf` for vhost fuzzing in Host header.
  

---

  

## 9. Subdomain takeover

  

```bash

# 50+ SaaS signatures

docker run --rm -v "$PWD":/data punksecurity/dnsreaper \

file --filename /data/live.txt --out /data/takeover --out-format csv

  

# alternatives / second opinions

nuclei -l live.txt -tags takeover -severity info,low,medium,high,critical -silent -o tko.txt

dnstake -t live.txt -c 25 -s -o dnstake.txt

```

  


A candidate is not a finding. Answer four questions before writing one up:

  

1. Does the CNAME target NXDOMAIN, or does it resolve? `dig +noall +answer CNAME host @1.1.1.1`

2. Is the target's **apex registrable** ? That is a takeover with no SaaS involved.

3. Does the service return an unclaimed-resource fingerprint, or just a 404? A CNAME pointing at a live SaaS that answers 404 is **not** a takeover.

4. Could you claim it — and are you authorised to? Claiming changes state on a third-party service. Agree that first, and record the evidence you already have.

  

Evidence for the report: the `dig` output, the HTTP response, and the registration state of the target. 


---

  

## 10. Web surface and ports

  

```bash

httpx -l live.txt -sc -title -td -cdn -silent -o httpx.txt


httpx -l live.txt -silent -sc -cl -json \

| jq -r '"\(.url) \(.status_code) \(.content_length // 0)"' \

| bbrf url add - -s httpx --show-new

```

  

## 11. Keep these outputs

  

Keep the inputs *and* the evidence, separately. Inputs get regenerated; evidence gets cited.

  

```

$OUT/

passive.txt names from passive sources

brute.txt perm.txt names from active discovery

all_names.txt everything, in scope, deduplicated

live.txt names that actually resolve <- the deliverable

resolved.txt name -> A/AAAA/CNAME

ips.txt unique addresses

httpx.txt live web surface

wildcards*.txt wildcard roots (a finding, not noise)

axfr_*.txt zone dumps <- evidence

dangling_*.txt dangling CNAME/MX <- evidence

takeover.csv tko.txt dnstake.txt <- evidence

ns.txt ns_parent.txt ns_child.txt <- evidence for section 7

```

  

A one-line inventory for the report:

  

```bash

wc -l passive.txt all_names.txt live.txt ips.txt httpx.txt 2>/dev/null

```

  

### Querying the BBRF database


  

```bash

bbrf use "$D"

  

bbrf domains # everything in scope, ever

bbrf domains --view resolved # only names with an address attached

bbrf ips # every address

bbrf ips --filter-cdns # addresses worth scanning, CDN edges excluded

bbrf urls # the web surface

bbrf urls -d "sub.$D" # ...for one host

bbrf show "sub.$D" # the full document: sources, IPs, tags, first/last seen

bbrf tags takeover # everything you tagged as a takeover candidate

bbrf scope in # what the program considers in scope

```

  

Re-run the whole pipeline next month and every `--show-new` prints only the delta.


```bash

bbrf domains > domains_export.txt

bbrf ips > ips_export.txt

bbrf urls > urls_export.txt

```

  

---

  


## What not to do

  

- **Do not brute-force before checking for wildcards**, and do not report unfiltered wildcard

hits as live hosts.

- **Do not run permutations before you have live names.** Permuting guesses multiplies guesses.

- **Do not validate a public resolver list against itself.** A resolver that lies confirms its own

lie — check against known-good roots, or use the list as published.

- **Do not loop crt.sh per subdomain.** One wildcard query on the apex, with retries.

- **Do not mine certificate names on CDN addresses.** You will collect other organisations' names

and, if you act on them, test something you have no authorisation to touch.

- **Do not run takeover checks on the raw brute list.** Live names only.

- **Do not claim a takeover from a dangling CNAME alone.** See section 9.

- **Do not reference a file before the stage that writes it** — `live.txt` comes from section 6,

`ips.txt` from section 6, `httpx.txt` from section 10.

- **Do not point mass resolution at the target's own nameservers.** Use public resolvers for

volume; the target's servers are for authoritative answers and AXFR attempts only.

- **Do not confuse "passive" with "invisible".** Certificate transparency, passive DNS and archive

queries all disclose your interest to third parties. Get that agreed before you start.