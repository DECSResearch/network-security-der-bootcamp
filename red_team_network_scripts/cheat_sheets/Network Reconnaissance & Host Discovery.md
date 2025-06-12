# Network Reconnaissance & Host Discovery Cheat Sheet

## 1. Communication Protocols

- **ARP (Address Resolution Protocol)**  
  - **Layer**: 2 (Data Link)  
  - **Purpose**: Map IPv4 ↔ MAC on local LAN; essential for local host discovery  
  - **Usage**: ARP requests/replies to learn active hosts  

- **ICMP (Internet Control Message Protocol)**  
  - **Layer**: 3 (Network)  
  - **Purpose**: Echo request/reply (ping); error & reachability messages  
  - **Usage**: Ping sweeps to test host availability  

- **TCP (Transmission Control Protocol)**  
  - **Layer**: 4 (Transport)  
  - **Purpose**: Reliable, connection-oriented sessions  
  - **Usage**: SYN scans to infer live hosts via open ports  

- **UDP (User Datagram Protocol)**  
  - **Layer**: 4 (Transport)  
  - **Purpose**: Connectionless, low-overhead datagrams  
  - **Usage**: UDP scans for services (DNS, SNMP) without handshake  

- **Modbus TCP**  
  - **Layer**: 7 (Application over TCP)  
  - **Port**: 502/TCP  
  - **Purpose**: Industrial control protocol for SCADA/DER devices  
  - **Usage**: Scan for hosts with port 502 open (e.g. `nmap -p502 --open`) and/or passively capture Modbus frames with Wireshark/tcpdump to fingerprint devices.  

## 2. Active Host Discovery

### Nmap Ping Sweep  
```bash
nmap -sn 192.168.1.0/24
````

* `-sn`: ping scan only (no port scan)
* Lists hosts that respond to ICMP/ECHO

### ARP Discovery (arp-scan)

```bash
sudo arp-scan --interface=eth0 192.168.1.0/24
```

* Sends ARP requests across the subnet
* Fast, reliable on switched LANs

### Netdiscover

```bash
sudo netdiscover -i eth0 -r 192.168.1.0/24
```

* `-i`: interface; `-r`: target range
* Passive by default; active ARP if `-r` is set


## 2. Passive Host Enumeration

### ARP Cache Lookup

```bash
arp -n
```

* Displays current IP ↔ MAC mappings without DNS

### MAC Vendor Lookup

```bash
arp -n | awk '{print $1, $3}' | xargs -n2 maclookup
```

* Maps MAC to vendor for device identification

