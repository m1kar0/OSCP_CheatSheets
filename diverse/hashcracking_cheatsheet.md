# Hash cracking
Standard to be used is hashcat

## Generate wordlists

Use crunch for that:

```bash

Example 1
crunch 1 8
crunch will display a wordlist that starts at a and ends at zzzzzzzz

Example 2
crunch 1 6 abcdefg
crunch will display a wordlist using the character set abcdefg that starts at a and ends at gggggg

Example 3
crunch 1 6 abcdefg\
there is a space at the end of the character string.  In order for crunch to use the space you will need to escape it using  the  \  character.

Example 4
crunch 1 8 -f charset.lst mixalpha-numeric-all-space -o wordlist.txt
crunch will use the mixalpha-numeric-all-space character set from charset.lst and will write the wordlist to a file  named  wordlist.txt.   The
file will start with a and end with "        "

Example 5
crunch 8 8 -f charset.lst mixalpha-numeric-all-space -o wordlist.txt -t @@dog@@@ -s cbdogaaa
crunch should generate a 8 character wordlist using the mixalpha-number-all-space character set from charset.lst and will write the wordlist to
a file named wordlist.txt.  The file will start at cbdogaaa and end at "  dog   "

Example 6
crunch 2 3 -f charset.lst ualpha -s BB
crunch with start generating a wordlist at BB and end with ZZZ.  This is useful if you have to stop generating a wordlist in the middle.   Just
do  a tail wordlist.txt and set the -s parameter to the next word in the sequence.  Be sure to rename the original wordlist BEFORE you begin as
crunch will overwrite the existing wordlist.

Example 7
crunch 4 5 -p abc
The numbers aren't processed but are needed.
crunch will generate abc, acb, bac, bca, cab, cba.

Example 8
crunch 4 5 -p dog cat bird
The numbers aren't processed but are needed.
crunch will generate birdcatdog, birddogcat, catbirddog, catdogbird, dogbirdcat, dogcatbird.

Example 9
crunch 1 5 -o START -c 6000 -z bzip2
crunch will generate bzip2 compressed files with each file containing 6000 words.  The filenames of the compressed files  will  be  first_word-
last_word.txt.bz2


```

Pipe crunch to crack wifi

```bash

crunch 2 4 abcdefghijklmnopqrstuvwxyz | aircrack-ng /root/Mycapfile.cap -e MyESSID -w-

crunch 10 10 12345 --stdout | airolib-ng testdb -import passwd -

```


## Hashcat basic use

```
hashcat -O -a 0 -m 100 try.hash  /usr/share/wordlists/rockyou.txt

-O: swith optimized kernels to improve performance
-a: attack mode selection (o for straight)
-m: hash type (see help)
try.hash: file with list of hashes (best practice to reduce garbage on screen)
/usr/share/wordlists/rockyou.txt: use this for OSCP (find fresh rockyou on github)

```

## WiFi cracking

Manual origin: `https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2`

1. Stop all services that are accessing the WLAN device (e.g .: NetworManager and wpa_supplicant.service)
```
$ sudo systemctl stop NetworkManager.service
$ sudo systemctl stop wpa_supplicant.service
```
2. Capture handshake with hcxdumptool (send deauth to speed up)

`$ hcxdumptool -i interface -o dumpfile.pcapng --active_beacon --enable_status=15`

3. restart services

```
$ sudo systemctl start wpa_supplicant.service
$ sudo systemctl start NetworkManager.service
```
4. Convert the traffic to hash format 22000

`$ hcxpcapngtool -o hash.hc22000 -E wordlist dumpfile.pcapng`

for cap file (obtained from airgeddon) it's the same

`$ hcxpcapngtool -o hash.22000 --csv=AP.txt handshake-xx:xx:xx.cap  `

5. run hashcat

`hashcat -m 22000 hash.hc22000 wordlist.txt`
# How to crack Linux passwords


## john way

copy  /etc/passwd and /etc/shadow

then unshadow 

`unshadow passwd shadow passwds.txt`

launch john

`john --sordlist=/usr/share/rock.txt passwds.txt`