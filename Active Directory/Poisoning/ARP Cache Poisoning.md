**ARP cache poisoning** — ARP maps IP addresses (L3) to MAC addresses (L2). Few networks protect against spoofed ARP replies, so it is still an effective way to man-in-the-middle local traffic. Use it when everything else has failed.

## How it works

- Client: `192.168.0.100/24`. Gateway: `192.168.0.254/24`. Client wants to reach `8.8.8.8`.
- The client's only matching route is `0.0.0.0` via the gateway, so it must reach `192.168.0.254` at L2 and sends an ARP request for its MAC.
- An attacker on the segment answers those requests, handing its own MAC to both the client and the gateway - intercepting all traffic between them.

## Discovery

Nothing to discover - networks do not work without ARP.

## Exploitation

Several ways to run the MitM. See how to collect credentials from the intercepted traffic in [NTLM Credentials Gathering](NTLM%20Credentials%20Gathering.md).

### Method 1: Ettercap (GUI)

1. Start Ettercap, select the primary interface and Accept.
2. Scan for hosts (search button, top left).
3. Open the Host List (button next to it).
4. Select the gateway IP and add it to Target 1.
5. Select the client IP(s) and add them to Target 2.
6. Open the MITM menu (top right), click ARP Poisoning and OK.

To stop: click the stop button (top right); Ettercap should show "RE-ARPing the victims". To edit the target list, stop any running attack first, then Ettercap menu > Targets > Current targets.

### Method 2: bettercap

1. Start with `sudo bettercap`.
2. Scan the local network: `net.probe on`.
3. Start spoofing: `arp.spoof on`. Stop with `arp.spoof off`.

One-liner (scan 15s, then attack):

```bash

bettercap -eval 'net.probe on; sleep 15; net.probe off; arp.spoof on' -iface 'INTERFACE'

```

## Caution

**Warning:** One wrong move and you cause a Denial of Service on the segment.

Tips to limit impact:
- Use at least a Gigabit Ethernet adapter.
- Poison clients in batches of fewer than 20 IPs; tune to the network's behaviour.
- Don't forget to stop the attack. Once stopped, the network recovers within seconds.

## References

- Ettercap - https://www.ettercap-project.org/
- bettercap - https://www.bettercap.org/
