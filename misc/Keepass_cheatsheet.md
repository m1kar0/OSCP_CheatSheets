# Hacking Keepass

References:
* https://www.thedutchhacker.com/how-to-crack-a-keepass-database-file/

## Cracking DB file

1. find `.kdbx` files
2. convert to john `keepass2john Database.kdbx > Keepasshash.txt`
3. crack with john `john --wordlist=/usr/share/wordlists/rockyou.txt Keepasshash.txt`

or use hashcat

1. remove DB name from already made `Keepasshash.txt`
2. `hashcat -m 13400 -a 0 --force Keepasshashforthecat.txt wordlist.txt -r best64.rule`

using masks and rules with hashcat helps https://hashcat.net/wiki/doku.php?id=mask_attack