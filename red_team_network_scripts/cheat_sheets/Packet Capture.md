
**Why Use Filters?**

* **Reduce Noise:** Capture only the traffic you care about (e.g. ARP, HTTP, DNS), cutting down logfile size.
* **Improve Performance:** Offload filtering to kernel space, minimizing CPU and disk usage on busy hosts.
* **Focus Analysis:** Zero in on suspicious patterns (e.g. SYN floods, UDP floods) without wading through irrelevant packets.


**Basic BPF Syntax**

* **Protocol**: `arp`, `icmp`, `tcp`, `udp`
* **Port**: `port 80`, `tcp port 22`, `udp port 53`
* **Host/Network**: `host 192.168.1.10`, `net 192.168.1.0/24`
* **Logical Operators**:

  * AND: `and` (e.g. `tcp and port 80`)
  * OR: `or` (e.g. `icmp or tcp`)
  * NOT: `not` (e.g. `not arp`)


**Common Filter Examples**

* **ARP traffic only**:

  ```
  tcpdump -i eth0 arp
  ```
* **HTTP requests (TCP port 80)**:

  ```
  tcpdump -i eth0 tcp port 80
  ```
* **DNS queries (UDP port 53)**:

  ```
  tcpdump -i eth0 udp port 53
  ```
* **SYN packets (SYN flood indicator)**:

  ```
  tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'
  ```


**Pro Tips**

* Chain filters to narrow focus: e.g.,
  `'tcp and port 443 and src host 192.168.1.5'`
* Use `-c <count>` to stop after capturing a set number of packets.
* Write filtered output directly to a PCAP file (`-w`) for later Wireshark analysis.
