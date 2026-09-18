# Web attack surface recon

```
passive → AXFR → wildcard check → brute → permutations → resolve
                                              │
                    IP pivot ← takeover ← live names
                         │
                 delegation defects
```


---

## Contents

- [Toolbox](#toolbox) · [Setup](#setup) · [BBRF](#bbrf)
- [1. Passive names](#1-passive-names) · [2. AXFR](#2-zone-transfer-axfr) · [3. Wildcards](#3-wildcards)
- [4. Brute force](#4-brute-force) · [5. Permutations](#5-permutations) · [6. Consolidate and resolve](#6-consolidate-and-resolve)
- [7. Delegation defects](#7-delegation-defects) · [8. IP pivot](#8-ip-pivot) · [9. Takeover](#9-subdomain-takeover)
- [10. Web surface](#10-web-surface) · [11. Outputs](#11-outputs) · [What not to do](#what-not-to-do)

---

## Toolbox

| Job | Tool |
|---|---|
| passive subdomains | `subfinder`, `assetfinder`, `amass` |
| certificate transparency | `curl` + `crt.sh` |
| URL history | `gau`, `waybackurls`, `urlfinder`, `waymore` |
| crawling | `katana` |
| DNS at volume | `puredns` (+ `massdns`), `dnsx`, `shuffledns` |
| brute | `puredns bruteforce`, `dnsx -w`, `shuffledns` |
| permutations | `alterx`, `gotator` |
| takeover | `dnsreaper`, `nuclei -tags takeover`, `dnstake` |
| IP pivot | `dnsx -ptr`, `tlsx`, `asnmap`, `mapcidr`, `cdncheck`, `hakip2host` |
| web / ports | `httpx`, `naabu` |
| plumbing | `anew`, `unfurl`, `dsieve`, `jq` |
| attack-surface DB | `bbrf` |

---

## Setup

Per target. Everything below assumes these variables and this working directory.

```bash
D=example.com                 # apex you are authorised to test
P=${D//./-}                   # BBRF program slug — never the FQDN (CouchDB id collision)
OUT=~/recon/$D
L=~/recon/lists
mkdir -p "$OUT" "$L" && cd "$OUT"

curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
  -o "$L/resolvers.txt"
printf '1.1.1.1\n1.0.0.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n' > "$L/resolvers-trusted.txt"

R="$L/resolvers.txt"          # public: fast first pass
RT="$L/resolvers-trusted.txt" # trusted: validate hits, and every ad-hoc dig
W=/usr/share/seclists/Discovery/DNS
RPS=1000                      # qps against public resolvers

printf 'dev\nstaging\nstage\ntest\nuat\nqa\nprod\nadmin\napi\ninternal\nold\nnew\nbackup\nvpn\nmail\n' \
  > "$L/perms.txt"
```

**Two resolver lists, not one.** Public resolvers lie; trusted resolvers (or a `dnsvalidator` pass) are what you cite.

```bash
dnsvalidator -tL "$R" -threads 200 -o "$L/resolvers-checked.txt"
```

If `1.1.1.1` / `8.8.8.8` time out from your network, `$RT` is dead and `dnsx -r "$RT"` returns nothing. Test with `dig +short "$D" @1.1.1.1` before you start.

| List | Size | Use when |
|---|---|---|
| `$W/subdomains-top1million-5000.txt` | 33 KB | quick pass, recursion into parents |
| `$W/subdomains-top1million-20000.txt` | 149 KB | sensible default |
| `$W/subdomains-top1million-110000.txt` | 1.1 MB | thorough single pass |
| `$W/bitquark-subdomains-top100000.txt` | 1.4 MB | different corpus — complement, not replacement |
| `$W/n0kovo_subdomains.txt` | 51 MB | when the estate *is* the engagement; hours |

`</dev/null>` on `dnsx -l file` is intentional (otherwise dnsx may hang on stdin). Do **not** put it on a piped `dnsx` — that discards the pipe.

---

## BBRF


```bash
bbrf new "$P"                 
bbrf use "$P"
bbrf inscope add "$D" "*.$D"
bbrf outscope add "blog.$D" 
bbrf scope in

# after any name list:
cat names.txt | bbrf domain add - -s <source> --show-new
# after any URL list:
cat urls.txt  | bbrf url add - -s <source> --show-new
```

---

## 1. Passive

### 1.1 Aggregators

```bash
subfinder -d "$D" -all -silent | tee -a passive.txt | bbrf domain add - -s subfinder --show-new
assetfinder --subs-only "$D"   | tee -a passive.txt | bbrf domain add - -s assetfinder --show-new
```

### 1.2 Certificates

crt.sh is slow and rate-limits. One wildcard query on the apex, with retries — do not loop it per subdomain.

```bash
curl -s --retry 3 --retry-delay 5 --max-time 60 "https://crt.sh/?q=%25.$D&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' | tr 'A-Z' 'a-z' | sed 's/\r$//' \
  | tee -a passive.txt | bbrf domain add - -s crtsh --show-new
```

### 1.3 URL history

Archived URLs and JavaScript mention hosts no DNS source lists.

```bash
gau --subs "$D"                    | anew urls.txt
waybackurls "$D"                   | anew urls.txt
urlfinder -d "$D" -all -silent     | anew urls.txt
waymore -i "$D" -mode U -oU waymore_urls.txt && cat waymore_urls.txt | anew urls.txt

unfurl -u domains < urls.txt | tee -a passive.txt | bbrf domain add - -s urlhistory --show-new
cat urls.txt | bbrf url add - -s urlhistory --show-new
```

Tool-free fallback when a tool is throttled or missing:

```bash
curl -sG --retry 3 --retry-delay 2 --max-time 120 "http://web.archive.org/cdx/search/cdx" \
  --data-urlencode "url=*.$D/*" --data-urlencode "fl=original" \
  --data-urlencode "collapse=urlkey" \
  | unfurl -u domains | anew passive.txt

# OTX is no longer anonymous — skip without a key
curl -s --max-time 30 -H "X-OTX-API-KEY: $OTX_API_KEY" \
  "https://otx.alienvault.com/api/v1/indicators/domain/$D/passive_dns" \
  | jq -r '.passive_dns[]?.hostname' | anew passive.txt
```

### 1.4 Crawl

```bash
katana -u "https://$D" -jc -kf all -d 3 -fs fqdn -silent -o crawl.txt
unfurl -u domains < crawl.txt | tee -a passive.txt | bbrf domain add - -s katana --show-new
cat crawl.txt | bbrf url add - -s katana --show-new

# hosts referenced only in CSP
curl -sI "https://$D" | grep -i '^content-security-policy' \
  | grep -oE '[a-z0-9.-]+\.[a-z]{2,}' | anew passive.txt
```

### 1.5 VirusTotal

`vt init` once. These are vt-cli subcommands, not API paths.

```bash
vt domain subdomains "$D" -n 40 -I -s \
  | tee -a passive.txt | bbrf domain add - -s virustotal --show-new
vt domain resolutions "$D" -n 40 --format json
vt domain historical_ssl_certificates "$D" -n 10 --format json \
  | jq -r '.. | .subject_alternative_name? // empty | .[]?' | anew passive.txt
```

---

## 2. Zone transfer (AXFR)

A successful transfer is the whole zone: every name, plus MX/TXT/SRV and the internal naming scheme.

dnsx 1.2+ prints one NS per line as `host [NS] [ns1.example.com]`.

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

grep -hoE '^[a-z0-9_.-]+' axfr_*.txt 2>/dev/null | sed 's/\.$//' | sort -u \
  | tee -a passive.txt | bbrf domain add - -s axfr --show-new
```

Shorter AXFR-only check:

```bash
dnsrecon -d "$D" -t axfr
```

`dnsenum --noreverse "$D"` is **not** AXFR-only — it still brute-forces its default wordlist after the transfer attempt.

---

## 3. Wildcards

If `*.$D` resolves, every random name "exists". Wildcards are often per-subtree and can be A-only, AAAA-only or CNAME-only, so probe several random labels at several depths.

```bash
for level in "$D" "dev.$D" "internal.$D" "staging.$D"; do
  for i in 1 2 3; do echo "wc$(openssl rand -hex 6).$level"; done
done | dnsx -a -aaaa -cname -resp -silent -nc -r "$RT" | tee wildcard_probe.txt
```

Any hit here means brute **must** go through puredns (or equivalent wildcard filtering). Do not feed an unfiltered brute into `dnsx -recon` and call the answers "extra IPs".

---

## 4. Brute force

```bash
puredns bruteforce "$W/subdomains-top1million-110000.txt" "$D" \
  -r "$R" --resolvers-trusted "$RT" \
  -l "$RPS" --rate-limit-trusted 400 \
  --wildcard-tests 30 --wildcard-batch 1000000 \
  --write-wildcards wildcards.txt -w brute.txt

cat brute.txt | bbrf domain add - -s bruteforce --show-new
```

- `brute.txt` — live names, wildcard noise removed
- `wildcards.txt` — the wildcard roots themselves, e.g. `*.dev.$D`

Alternatives (no wildcard filter on the dnsx line — only safe if §3 was clean):

```bash
dnsx -d "$D" -w "$W/subdomains-top1million-20000.txt" \
  -r "$RT" -t 100 -rl "$RPS" -silent -o brute_dnsx.txt </dev/null

shuffledns -d "$D" -w "$W/subdomains-top1million-20000.txt" -r "$R" \
  -mode bruteforce -o brute_shuffle.txt
```

`dnsx -wd` is a different mode (JSON only, other flags ignored). Do not mix it with `-o brute_dnsx.txt`.

### NOERROR sweep

A name can exist in the zone with no A record — invisible to a normal brute. Check for DNSSEC "black lies" first, or every random label answers NOERROR and the sweep is noise:

```bash
probe="zz$(openssl rand -hex 6).$D"
if echo "$probe" | dnsx -rc noerror -r "$RT" -silent | grep -q .; then
  echo "black lies: the NOERROR sweep is useless on this zone"
else
  dnsx -d "$D" -w "$W/subdomains-top1million-20000.txt" \
    -rc noerror -r "$RT" -t 100 -rl "$RPS" -silent -o noerror.txt
fi
```

### Recurse into parent labels

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

After you have live names (`brute.txt` from puredns). Do not permute `live.txt` — that file does not exist until §6.

```bash
cat brute.txt brute_recursive.txt 2>/dev/null | anew perm_seeds.txt

alterx -l perm_seeds.txt -silent | anew perm_candidates.txt

gotator -sub perm_seeds.txt -perm "$L/perms.txt" -depth 1 -numbers 3 -mindup -silent \
  | anew perm_candidates.txt

puredns resolve perm_candidates.txt \
  -r "$R" --resolvers-trusted "$RT" -l "$RPS" \
  --wildcard-tests 30 --write-wildcards wildcards_perm.txt -w perm.txt

cat perm.txt | bbrf domain add - -s permutation --show-new
```

`-depth 2` and above explodes. Start at 1.

---

## 6. Consolidate and resolve

```bash
printf '%s\n' "$D" > apexes.txt          # one apex per line if the engagement has several

in_scope() { # stdin → in-scope names
  awk 'NR==FNR{apex[$0];next}
  {n=tolower($1); sub(/\.$/,"",n)
  for (a in apex) if (n==a || n ~ ("\\." a "$")) { print n; next } }' apexes.txt -
}

cat passive.txt brute.txt brute_recursive.txt perm.txt noerror.txt 2>/dev/null \
  | in_scope | anew all_names.txt

puredns resolve all_names.txt -r "$R" --resolvers-trusted "$RT" -l "$RPS" \
  --wildcard-tests 30 --write-wildcards wildcards_final.txt -w live.txt

dnsx -l live.txt -a -aaaa -cname -resp -silent -nc -r "$RT" </dev/null -o resolved.txt
dnsx -l live.txt -a -resp-only -silent -r "$RT" </dev/null | sort -u > ips.txt
```

dnsx `-resp` on current versions is `host [A] [1.2.3.4]`. After stripping brackets, `$2=="A"` is the record type:

```bash
cat live.txt | bbrf domain add - -s resolved --show-new
cat ips.txt  | bbrf ip add - -s resolved --show-new

dnsx -l live.txt -a -resp -silent -nc -r "$RT" </dev/null \
  | sed 's/\[//g; s/\]//g' | awk '$2=="A"{print $1":"$3}' | sort -u > domain_ip.txt
cat domain_ip.txt | bbrf domain update - -s dnsx
awk -F: '{print $2":"$1}' domain_ip.txt | bbrf ip update - -s dnsx

cat wildcards_final.txt 2>/dev/null | bbrf domain add - -s wildcard --show-new --ignore-scope
```

---

## 7. Delegation defects

Takeover of a *name* is usually a dangling CNAME (§9). This section is the zone itself: lame NS, an NS hostname you can buy, parent/child disagreement, SPF/DMARC, DNSSEC.

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

Healthy: `status=NOERROR authoritative=yes` on every line. **Finding:** `REFUSED`, `SERVFAIL`, `NOANSWER`, or `NOERROR` with `authoritative=NO`.

### 7.2 A nameserver on a domain you can buy

Highest-impact check here. If an NS hostname sits under an unregistered domain, whoever registers it becomes authoritative for the zone.

The awk is two-label only (`ns1.kgeu.ru` → `kgeu.ru`). It is wrong for `co.uk` / `com.au`.

```bash
awk -F. '{print $(NF-1)"."$NF}' ns.txt | sort -u | while read -r apex; do
  w=$(whois "$apex" 2>/dev/null)
  printf '%s' "$w" | grep -qiE 'no match|not found|no data found|no entries found|status:[[:space:]]*free' \
    && echo "UNREGISTERED -> $apex" || echo "registered -> $apex"
done
```

Every line prints, so a clean result reads `registered` rather than an empty screen.

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
python3 /opt/Spoofy/spoofy.py -d "$D"    # or: spoofy -d "$D"
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

### 7.6 DNSSEC

```bash
dig +short DS "$D" @1.1.1.1
dig +dnssec +noall +answer SOA "$D" @1.1.1.1 | grep RRSIG
delv @1.1.1.1 "$D" A 2>&1 | head -3
```

Unsigned is `delv: unsigned answer`. DS empty + no RRSIG is the same finding, not a tool failure.

### 7.7 NSEC / NSEC3 zone walk

```bash
dnsrecon -d "$D" -t zonewalk
```

No-op on unsigned zones.

---

## 8. IP pivot

```bash
cat ips.txt | cdncheck -silent -resp > cdn_tagged.txt

dnsx -l ips.txt -ptr -resp-only -silent -r "$RT" </dev/null | sort -u > ptr.txt
tlsx -l ips.txt -san -cn -ro -silent </dev/null | sort -u > tls_names.txt
cat ips.txt | hakip2host | sort -u > ip2host.txt

# ASN of the first address, as a starting range — not the whole estate
asnmap -i "$(head -1 ips.txt)" -silent | mapcidr -silent > asn_cidrs.txt

cat ptr.txt tls_names.txt ip2host.txt | in_scope | anew all_names.txt

cat ptr.txt tls_names.txt ip2host.txt | bbrf domain add - -s ippivot --show-new
awk '{print $1}' cdn_tagged.txt 2>/dev/null | bbrf ip update - -t cdn:true
cat asn_cidrs.txt | bbrf ip add - -s asnmap --show-new --ignore-scope
```

Do not mine certificate names on CDN addresses — you will collect other organisations' names.

```bash
naabu -l ips.txt -tp 1000 -rate 500 -silent -o ports.txt
nmap -sV -iL ips.txt -oA nmap_estate
```

Virtual hosting hides names behind one address. If you suspect it, `ffuf` the Host header.

---

## 9. Subdomain takeover

Live names only. Not the raw brute list.

```bash
docker run --rm -v "$PWD":/data punksecurity/dnsreaper \
  file --filename /data/live.txt --out /data/takeover --out-format csv
# or, if dnsreaper is on PATH (file provider, one name per line):
# dnsreaper file --filename live.txt --out takeover --out-format csv

nuclei -l live.txt -tags takeover -severity info,low,medium,high,critical -silent -o tko.txt
dnstake -t live.txt -c 25 -s -o dnstake.txt
```

A candidate is not a finding. Before you write one up:

1. Does the CNAME target NXDOMAIN, or does it resolve? `dig +noall +answer CNAME host @1.1.1.1`
2. Is the target's **apex registrable**? That is a takeover with no SaaS involved.
3. Unclaimed-resource fingerprint, or just a 404? A CNAME at a live SaaS that answers 404 is **not** a takeover.
4. Could you claim it — and are you authorised to? Claiming changes state on a third-party service. Agree that first.

Evidence: the `dig` output, the HTTP response, and the registration state of the target.

---

## 10. Web surface

```bash
httpx -l live.txt -sc -title -td -cdn -silent -o httpx.txt

# BBRF accepts "url status content_length"
httpx -l live.txt -silent -sc -cl -json \
  | jq -r '"\(.url) \(.status_code) \(.content_length // 0)"' \
  | bbrf url add - -s httpx --show-new
```

---

## 11. Outputs

Keep the inputs *and* the evidence, separately. Inputs get regenerated; evidence gets cited.

```
$OUT/
passive.txt          names from passive sources
brute.txt perm.txt   names from active discovery
all_names.txt        everything, in scope, deduplicated
live.txt             names that actually resolve  ← the deliverable
resolved.txt         name → A/AAAA/CNAME
ips.txt              unique addresses
httpx.txt            live web surface
wildcards*.txt       wildcard roots (a finding, not noise)
axfr_*.txt           zone dumps                   ← evidence
dangling_*.txt       dangling CNAME/MX            ← evidence
takeover.csv tko.txt ← evidence
ns.txt ns_parent.txt ns_child.txt  ← evidence for §7
```

```bash
wc -l passive.txt all_names.txt live.txt ips.txt httpx.txt 2>/dev/null
```

### Query BBRF

```bash
bbrf use "$P"

bbrf domains
bbrf domains --resolved          # names with an address
bbrf ips
bbrf ips --filter-cdns
bbrf urls
bbrf urls -d "sub.$D"
bbrf show "sub.$D"
bbrf tags takeover
bbrf scope in
```

Re-run next month: `--show-new` is the delta.

```bash
bbrf domains > domains_export.txt
bbrf ips     > ips_export.txt
bbrf urls    > urls_export.txt
```

---

## What not to do

- **Do not brute before checking wildcards**, and do not report unfiltered wildcard hits as live hosts.
- **Do not permute guesses.** Permute confirmed names (`brute.txt`), then resolve.
- **Do not validate a public resolver list against itself.** A liar confirms its own lie.
- **Do not loop crt.sh per subdomain.** One wildcard query on the apex, with retries.
- **Do not mine certificate names on CDN addresses.**
- **Do not run takeover checks on the raw brute list.** Live names only.
- **Do not claim a takeover from a dangling CNAME alone.** See §9.
- **Do not name the BBRF program after the apex.** Use `$P`, not `$D`.
- **Do not put `</dev/null` on a piped dnsx.** That is how the wildcard probe goes blind. Keep it on `dnsx -l file`.
- **Do not point mass resolution at the target's own nameservers.** Public resolvers for volume; the target's servers for authoritative answers and AXFR only.
- **Do not confuse "passive" with "invisible".** CT, passive DNS and archives disclose interest to third parties.
- **Do not reference a file before the stage that writes it.** `brute.txt` is §4, `live.txt` / `ips.txt` are §6, `httpx.txt` is §10.

---

## Appendix: BBRF backend (once)

Skip if the DB is already up (this environment: `https://127.0.0.1:3443/bbrf`).

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

The database still needs its design documents — follow [bbrf-server](https://github.com/honoki/bbrf-server). Client: [bbrf-client](https://github.com/honoki/bbrf-client).
