# network-security-der-bootcamp
Hands-on labs, cheat sheets, and scripts for the DER Edge Security Bootcamp, covering ARP spoofing &amp; MiTM, passive eavesdropping/packet capture, and DoS/DDoS simulation.

# Scripts

| Script | Classification | Description | Last Updated | Documentation |
|--------|---------------|-------------|--------------|---------------|
| [arp_spoof.py](red_team_network_scripts/impersonation/arp_spoof.py) | Impersonation | Bidirectional ARP cache poisoning tool | 2025-02-24 | [README](#arp-spoofing) |
| [brute_charset.py](red_team_network_scripts/flooding/bruteforce_char.py) | Flooding | Alphabet-based brute force (a-zA-Z0-9!@#) | 2025-02-19 | [README](#alphabet-based-brute-force) |
| [dict_attack.py](red_team_network_scripts/flooding/bruteforce_dict.py) | Flooding | Dictionary attack with Top 150k passwords | 2025-02-19 | [README](#ssh-dictionary-attack-tool) |
| [arp_blackout.py](red_team_network_scripts/impersonation/arp_blackout.py) | Impersonation | Advanced ARP cache poisoning | 2025-03-07| [README](#arp-blackout-attack-tool)|
| [FDIA.py](red_team_network_scripts/Injection/FDIA.py) | Injection | TCP/ModBus protocol data manipulation tool | 2025-03-10 | [README](#false-data-injection-attack) |
| [arp_eavesdrop.py](red_team_network_scripts/impersonation/arp_eavesdrop.py) | Impersonation | Passive network traffic sniffer | 2025-03-10 | [README](#arp-eavesdropping-attack) |
| [replay.py](red_team_network_scripts/Injection/replay.py) | Impersonation | ModBus frequency replay attack | 2025-03-21 | [README](#modbus-replay-attack) |
| [dos_icmp.py](red_team_network_scripts/flooding/dos_icmp.py) | Flooding | ICMP flood with IP spoofing and Rate Limiting| 2025-03-28 |  [README](#icmp-flood-attack) |
| [dos_tcp.py](red_team_network_scripts/flooding/dos_tcp.py) | Flooding | TCP flood with IP spoofing and Rate Limiting | 2025-03-28 | [README](#tcp-flood-attack) |
| [tcp_flag_injection.py](red_team_network_scripts/Injection/tcp_flag_injection.py) | Injection | TCP flag injection for non‑standard combinations | 2025-04-21 | [README](#tcp-flag-injection) |


## Classification Rationale

Based on standard network attack taxonomy:

- **Flooding**: Focuses on resource exhaustion through traffic/request overload  
- **Impersonation**: Utilizes identity deception and MITM techniques  
- **Injection**: Involves malicious data insertion or system interference



# Flooding

## Alphabet based brute force
A python based SSH credential brute-forcing using character combinations.

### Current Implementation
- CLI configuration via argparse for IP/user inputs
- Full printable ASCII character set (100 chars)
- Progressive length attempts (1-13 characters)
- Visual progress tracking with `tqdm`
- Automatic retry mechanism
- Network error recovery system
- 1-second SSH connection timeout
- 2-second retry delay on exceptions

### Usage
1. **Install dependencies**: `pip3 install paramiko tqdm`

2. **Execute brute force attack**: `python3 bruteforce.py <target_ip> <username>`

Example: `python3 bruteforce.py 192.168.1.45 admin`

Below is a clear, Markdown-formatted section for your README file that explains both monitoring the brute force progress and monitoring SSH connection attempts on the victim device.

---

3. **Monitor Progress**

When starting a brute force attack, you will see output similar to the following. This indicates that the attack has been initiated against the target IP (e.g., 192.168.1.45) with the specified username, and shows the progress of the attack:

```plaintext
[*] Starting brute force attack on 192.168.1.45 with username admin
Brute Force Progress: 0%|           | 0/100 [00:00<?, ?it/s]
```

---

4. **Monitor on Victim Device**

To capture only the initial SSH connection requests (i.e., SYN packets) on the victim device, use the following `tcpdump` command:

```bash
sudo tcpdump -i any -n 'tcp port 22 and tcp[13] == 2'
```

**Command Breakdown**

- **`-i any`**: Listen on all available interfaces.
- **`-n`**: Do not resolve hostnames or IP addresses.
- **`tcp port 22`**: Filter to capture only traffic destined for port 22 (SSH).
- **`tcp[13] == 2`**: Capture only packets where the 13th byte of the TCP header (the flags) is equal to 2, which corresponds to SYN packets with no ACK flag set. This ensures that you are only monitoring new connection requests and not ongoing SSH communications.

### Configuration Options
| Parameter | Default | Description |
|-----------|---------|-------------|
| `min_length` | 1 | Minimum password segments |
| `max_length` | 13 | Maximum password combinations |
| `timeout` | 1s | SSH connection timeout |
| `retry_delay` | 2s | Network error cooldown |

## Performance Notes
- Theoretical attempt count: 2.27e25 combinations (for 13 chars)
- Practical limitations:
- Network latency impacts speed
- SSH handshake overhead
- Lockout policies (not handled)
- Hardware limitations


### Troubleshooting
1. **Paramiko installation failures?**
- Update pip: `python3 -m pip install --upgrade pip`
- Install development tools: `sudo apt install python3-dev libffi-dev`

2. **Connection timeouts?**
- Verify target SSH port accessibility: `nc -zv <IP> 22`
- Ping device
- Check local firewall rules

3. **High failure rate?**
- Confirm username validity first
- Check target's failed attempt thresholds
- Consider narrowing character set in code

4. **Performance issues?**
- Remove progress bar (`tqdm`) for raw speed
- Increase timeout value in `ssh_connect()`


## SSH Dictionary Attack Tool

A multi-process Python script for performing high-speed dictionary attacks against SSH services using password lists.

### Current Implementation
- **Multi-core processing** using `multiprocessing.Pool`
- **Dictionary-based attacks** with configurable wordlists
- **Automatic retry system** for network errors
- **SSH connection recycling** (prevents resource exhaustion)
- **Progress visualization** with `tqdm` integration
- **Clean exit handling** via `finally` clause

### File Requirements
- `InsidePro.dic` password dictionary in working directory
- Custom wordlist support (modify `alnum` loading)

### Usage

1. **Install dependencies**: `pip3 install paramiko tqdm`

2. **Run attack** (4-core example):`python3  bruteforce_dict.py 192.168.1.25 admin`

3. **Monitor output**:
[*] Starting Dictionary attack on 192.168.1.25 with username admin
Brute Force Progress: 12%|██▏ | 1200/10000 [00:45<05:12, 26.21it/s]


### Configuration Options
| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 1s | SSH connection timeout |
| `retry_delay` | 2s | Network error cooldown |


**Flow Explanation**  
1. **Dictionary Loading**: Reads `InsidePro.dic` containing password candidates  
2. **List Generation**: Creates attack permutations from dictionary entries  
3. **Parallel Processing**: Distributes workload across all CPU cores  
4. **Connection Phase**: Each worker performs:  
   - SSH handshake with timeout  
   - Authentication attempt  
   - Error classification (retry vs discard)  
5. **Result Handling**: Successful finds terminate all workers immediately  


### Troubleshooting
**Dictionary Load Failures**  
➔ Verify `InsidePro.dic` exists in execution directory  
➔ Check file read permissions: `ls -l InsidePro.dic`

**Performance Issues**  
➔ Limit CPU cores: `with Pool(processes=2) as pool`  
➔ Disable progress bar: remove `tqdm` wrapper

**Connectivity Problems**  
nc -zvw3 <TARGET_IP> 22 # Verify SSH port accessibility
ping <TARGET_IP> # Check basic connectivity

text

### Operational Notes
1. **Wordlist Formatting**  
   Ensure dictionary file uses UNIX line endings (LF)  
   Remove empty lines: `sed -i '/^$/d' InsidePro.dic`

2. **Performance Tuning**  
   Optimal pool size = CPU cores - 1  
   For 8-core CPU: `Pool(processes=7)`


### Expected Performance
| CPU Cores | Passwords/Sec | 10k-wordlist Time |
|-----------|---------------|-------------------|
| 2         | 18-22         | ~9-11 mins        |
| 4         | 35-40         | ~4-5 mins         |
| 8         | 65-75         | ~2-3 mins         |  
*Based on 100Mbps network connection to target*

## ICMP Flood Attack

A high-performance ICMP flooding script designed to overwhelm a target system with large payload pings using raw socket injection. Built using Scapy and multiprocessing, this tool simulates a DoS (Denial of Service) scenario.

### Key Features

- **Raw ICMP packet crafting** with customizable payload size
- **IP spoofing** via randomized source IPs
- **Parallel flooding** using multiple processes
- **Adjustable rate limiting** for pacing packet transmission
- **Cross-platform compatibility** (Linux preferred for unrestricted payload sizes)

### Usage

```
sudo python3 dos_icmp.py
```

> **Note**: Requires root privileges for raw socket access.


### Default Configuration

| Parameter | Value | Description |
|----------|-------|-------------|
| `TARGET` | <AGX03> | Destination IP |
| `WORKERS` | 8 | Parallel processes |
| `PAYLOAD_SIZE` | 65495 bytes | Size of ICMP payload |
| `RATE_LIMIT` | 0.0000 sec | Delay between packets (0 = max speed) |

To modify behavior, edit the corresponding global variables at the top of the script.

### Packet Structure

Each packet is crafted as:

```
IP(dst=TARGET, src=RandIP()) /
ICMP(id=os.getpid(), seq=seq) /
Raw(load=os.urandom(PAYLOAD_SIZE))
```

- **Random IP source** to avoid detection / simulate real world attack
- **Raw payload** for maximizing packet size
- **Process PID as ID** to track process-level injections

### Theoretical Limits

| Component | Bytes |
|----------|--------|
| IPv4 Max Packet Size | 65535 |
| IP Header | 20 |
| ICMP Header | 8 |
| **Max Payload** | **65507** |

*Linux supports up to 65507 bytes, whereas some systems (e.g., Windows) cap this at 65500 bytes.*


### Troubleshooting

1. **Permission denied**
   - Run with `sudo`: raw sockets require elevated privileges

2. **Target not responding**
   - Check if target is alive (`ping TARGET`)
   - Ensure firewall isn’t blocking ICMP

3. **Low throughput**
   - Reduce `PAYLOAD_SIZE` or `WORKERS` to prevent local CPU bottleneck
   - Confirm NIC or OS is not rate limiting

4. **Script won’t stop**
   - Use `Ctrl+C` to terminate cleanly
   - Script automatically kills child processes on interrupt

---

### Operational Notes

- Tool is useful for **load testing**, **resilience simulation**, or demonstrating **rate limiting mechanisms**


## TCP Flood Attack

A high-volume TCP SYN flood tool built using Scapy and multiprocessing to simulate denial-of-service attacks. The script targets a specified IP with forged SYN packets containing large payloads, stressing the TCP handshake processing capability of the target.

### Key Features

- **TCP SYN packet crafting** with spoofed source IPs and randomized ports
- **Parallel flooding** using multiple worker processes
- **Large payload injection** using raw TCP segments
- **Configurable packet transmission rate**
- **Stateless attack**—no expectation of reply


### Usage

```
sudo python3 dos_tcp.py
```

> **Note**: Must be run with `sudo` to allow raw socket access via Scapy.


### Default Configuration

| Parameter | Value | Description |
|----------|-------|-------------|
| `TARGET` | 192.168.1.23 | Destination IP |
| `WORKERS` | 8 | Number of parallel processes |
| `PAYLOAD_SIZE` | 65495 bytes | TCP payload size |
| `RATE_LIMIT` | 0.0000 sec | Delay between sends (0 = maximum speed) |

To modify behavior, edit the global constants at the top of the script.


### Packet Structure

Each packet follows the structure:

```
IP(dst=TARGET, src=RandIP()) /
TCP(dport=80, sport=RandPort, flags="S") /
Raw(load=os.urandom(PAYLOAD_SIZE))
```

- **SYN flag** used to initiate TCP handshakes
- **Randomized source ports** to mimic distributed clients
- **Raw payloads** up to the theoretical TCP max size

### Theoretical Payload Limit

| Layer | Bytes |
|-------|--------|
| IPv4 Max Packet Size | 65535 |
| IP Header | 20 |
| TCP Header | 20 |
| **Max Payload** | **65495** |

> Large payloads in SYN packets are often dropped by stricter firewalls. Use smaller payloads if needed.


### Troubleshooting

1. **Permission errors**
   - Ensure script is run with `sudo` to access raw sockets

2. **Low impact on target**
   - Confirm target has open TCP port 80
   - Switch port from 80 to another exposed port
   - Reduce `PAYLOAD_SIZE` if target drops large SYNs

3. **Script does not terminate**
   - Use `Ctrl+C` to gracefully shut down all child processes

4. **No visible traffic**
   - Verify raw packets using Wireshark: `tcp.flags.syn == 1 and ip.src != YOUR_IP`


### Operational Notes

- Tool is effective against:
  - Devices lacking SYN flood protection
  - Load balancers without rate limiting
  - Simulating botnet-like behavior from a single host

****

# Impersonation
## ARP Spoofing

A Python-based ARP cache poisoning tool for demonstrating MITM (Man-in-the-Middle) attacks between two network devices.

### Current Implementation 
- CLI configuration with argparse for targets/interface
- Bidirectional ARP spoofing
- Configurable spoofing intervals
- Automatic ARP table restoration on exit (Ctrl+C)
- IP forwarding automation (enables/disables automatically)
- Iptables rule management for traffic forwarding
- Configurable network interface and target IPs


### Usage
1. **Start monitoring** (new terminal):
```sudo tcpdump -i eth0 -nnv "host 192.168.1.16 and host 192.168.1.23"```

2. **Run the ARP spoofer**:
```sudo python3 arp_spoof.py 192.168.1.16 192.168.1.23 -i eth0```

*Persistent spoofing* (resend every 5 seconds)
```sudo python3 arp_spoof.py 192.168.1.16 192.168.1.23 -i eth0 -r 5```


3. **Verify ARP table changes** on target devices:
On target_1 (192.168.1.16):
```arp -n | grep 192.168.1.23```

On target_2 (192.168.1.23):
```arp -n | grep 192.168.1.16```

### Automatic Management
The script now handles these automatically:
- Enables/disables IP forwarding (`net.ipv4.ip_forward`)
- Adds/removes iptables rules for ICMP/TCP forwarding
- NFqueue unbind


#### Command Options
| Option | Description |
|--------|-------------|
| `target1` | IP address of first target (required) |
| `target2` | IP address of second target (required) |
| `-i INTERFACE` | Network interface (default: eth0) |
| `-r SECONDS` | Resend ARP spoofs at interval (0=once, default:0) |

### Troubleshooting
1. **Permission errors?**
- Run with `sudo`
- Ensure no other ARP tools are running

2. **MAC discovery failures?**
- Ensure targets are on same VLAN
- Check physical connectivity

3. **Traffic not forwarding?**
- Confirm script output shows enabled IP forwarding
- Check iptables rules exist: `sudo iptables -L FORWARD -v`
- Verify target IPs are active (`ping` test)

4. **ARP tables not restoring?**
- Manually run restoration command: `arp -s TARGET_IP TARGET_MAC`

5. **Traffic stops forwarding after time?**  
→ Combine `-r 5` with persistent iptables rules:  
`sudo iptables-save > /etc/iptables/rules.v4`

 ### Advanced Use
For long sessions, consider creating a systemd service to maintain spoofing after disconnections. Add these iptables rules permanently with: `sudo iptables-save > /etc/iptables/rules.v4`

## ARP Blackout Attack Tool

A network disruption tool that performs ARP cache poisoning to isolate target devices from the local network. Built with Scapy for educational/penetration testing purposes.

### Key Features 

- **Network Discovery**  
  Auto-scans subnet to map active IP/MAC pairs
- **MAC Randomization & Unique MAC Detection**  
  Generates vendor-plausible spoofed addresses using common OUIs and ensures uniqueness by checking against the discovered devices.
- **Bidirectional Spoofing**  
  Poisons ARP caches of all network devices toward target.
- **Repeat Broadcast**  
  Continuously sends spoofed ARP packets at configurable intervals to maintain ARP cache poisoning.
- **Self-Healing Network**  
  Automatic ARP table restoration on exit (Ctrl+C)
- **Stealth Mode**  
  Randomized attack intervals and persistent spoofing

### Usage
1. **Install dependencies** (Scapy required):  
`pip3 install scapy`
2. **Run Attack**
   - Basic Attack:
     `sudo python3 arp_blackout.py 192.168.1.15`
   - Advanced Options:
     Custom interface and 15-second interval:
     `sudo python3 arp_blackout.py 192.168.1.25 -i wlan0 -t 15`
3. **Check target's ARP table changes**:  
`arp -n | grep 192`
4. **Monitor network traffic during attack**:
`sudo tcpdump -i eth0 arp -vv`

### Command Options
| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP address | *Required* |
| `-i INTERFACE` | Network interface | `eth0` |
| `-t SECONDS` | Spoofing interval | `10` |


### Technical Enhancements

**Unique MAC Detection**
-  Avoid generating a spoofed MAC address that's already present on the network.
  
**Repeat Broadcast**
- Ensure persistent ARP poisoning by re-sending spoofed ARP packets at regular intervals.

### Post-Attack Validation
1. Confirm target regains network connectivity
2. Verify original MAC addresses reappear in ARP tables

### Troubleshooting
**Common Issues**:
- `Target not found`: Ensure device is online (`ping -c 4 target_ip`)
- `Permission denied`: Run with `sudo` privileges
- `Spoofing ineffective`: Enable IP forwarding (`echo 1 > /proc/sys/net/ipv4/ip_forward`)

## ARP Eavesdropping Attack

A Python-based network traffic interceptor that combines ARP spoofing with packet capture capabilities. This tool allows for real-time MITM (Man-in-the-Middle) positioning to passively collect and save all traffic between two network endpoints for later analysis.

### Current Implementation

- **Bidirectional ARP Spoofing** to intercept traffic between two hosts
- **Concurrent Packet Capture** with multi-threaded operation
- **PCAP Export** for offline analysis with Wireshark or other tools
- **Automatic Network Configuration** of IP forwarding and iptables
- **Clean Network Restoration** upon exit
- **Flexible Timing Controls** for periodic ARP packet refreshes

### Usage
1. **Install dependencies** (Scapy required):  `pip3 install scapy`
2. **Basic usage**:`sudo python3 arp_eavesdrop.py 192.168.1.15 192.168.1.23`
3. **Custom interface and output file**:`sudo python3 arp_eavesdrop.py 192.168.1.15 192.168.1.23 -i wlan0 -o custom_capture.pcap`

4. **With recursive ARP spoofing every 5 seconds**:` sudo python3 arp_eavesdrop.py 192.168.1.15 192.168.1.23 -r 5`

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `target1` | First target IP address (required) | - |
| `target2` | Second target IP address (required) | - |
| `-i/--interface` | Network interface to use | eth0 |
| `-r/--recursive` | Seconds between ARP refreshes (0=once) | 0 |
| `-o/--output` | Output PCAP filename | captured_traffic.pcap |

### Technical Operation

1. **Network Preparation**:
   - Enables IP forwarding in Linux kernel
   - Configures iptables to allow forwarded traffic

2. **ARP Cache Poisoning**:
   - Sends crafted ARP packets to both targets
   - Convinces each target that the attacker's MAC is associated with the other target's IP
   - Optionally refreshes ARP cache periodically to maintain the attack

3. **Traffic Capture**:
   - Launches a separate thread for packet sniffing
   - Collects all packets passing through the attack machine
   - Stores packets in memory until termination
   - Writes collected packets to disk in PCAP format upon exit

4. **Restoration**:
   - Sends corrective ARP packets to restore normal network operation
   - Removes iptables rules
   - Disables IP forwarding

### Troubleshooting

1. **MAC Address Discovery Failure**
   - Ensure targets are online and responding to ARP
   - Check that the specified interface has network access
   - Try increasing ARP timeout with a code modification

2. **No Traffic Capture**
   - Verify ARP spoofing success with `arp -a` on targets
   - Ensure IP forwarding is enabled: `cat /proc/sys/net/ipv4/ip_forward`
   - Check iptables rules: `sudo iptables -L FORWARD -v`

3. **Permission Errors**
   - Run with sudo privileges
   - Check output file path permissions


Analysis of captured traffic can be performed with tools like Wireshark, Tshark, or NetworkMiner.


****
# Injection

## False Data Injection Attack

A Python-based FDIA (False Data Injection Attack) tool designed to intercept and modify TCP/ModBus protocol data packets in real-time. Built to demonstrate how attackers can manipulate critical measurement values in industrial systems while remaining undetected.

### Current Implementation

- **Multiple Modification Patterns** with 6 mathematical models:
  - Static (constant offset)
  - Dynamic (randomly selected function)
  - Gaussian distribution
  - Sigmoid function
  - Sinusoidal wave
  - Exponential curve
  - Pulse/step change
  - Polynomial (quadratic)
- **Packet Interception** via NetfilterQueue
- **Seamless Packet Modification** with automatic checksum recalculation
- **Automatic IPTables Management** for traffic redirection
- **Error Handling** with cleanup on exceptions
- **Debug Mode** for real-time attack monitoring
- **Requires ARP Spoofing** to be running in parallel (uses `arp_spoof.py`)

### Usage

1. **Install dependencies**:`pip3 install scapy netfilterqueue numpy`

2. **Start ARP spoofing in a separate terminal**:`sudo python3 arp_spoof.py 192.168.1.15 192.168.1.23 -i eth0 -r 5`

3. **Execute the FDIA attack**:`sudo python3 FDIA.py 192.168.1.15 -p 30502 -f gaussian`

4. **Monitor with debug mode**:`sudo python3 FDIA.py 192.168.1.15 -p 30502 -f dynamic -d`

5. **Check Kafka for frequency changes**:
   Monitor the Kafka stream to observe frequency value modifications in real-time.

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP address (required) | - |
| `-p/--port` | Target port number | 30502 |
| `-f/--frequency` | Modification pattern | static |
| `-d/--debug` | Enable debug output | False |

### Available Frequency Patterns

| Pattern | Description | Effect |
|---------|-------------|--------|
| `static` | Constant offset (+60.5Hz) | Fixed manipulation |
| `dynamic` | Randomly selected function | Unpredictable changes |
| `gaussian` | Bell curve distribution | Gradual rise and fall |
| `sigmoid` | S-shaped curve | Smooth transition |
| `sin` | Sine wave | Cyclical variation |
| `exponential` | Exponential decay | Rapid drop-off |
| `pulse` | Step function | Sudden jump |
| `polynomial` | Quadratic curve | Parabolic change |

### Troubleshooting

1. **NetfilterQueue Binding Errors**
   - Verify no other applications are using queue 1
   - Run: `sudo pkill -f NFQUEUE` to clear existing queue bindings
   - Install required dependencies:
     ```
     sudo apt-get install build-essential python3-dev libnetfilter-queue-dev libnfnetlink-dev
     sudo apt install libnfnetlink-dev libnetfilter-queue-dev
     pip3 install nfqp3
     pip3 install cython
     git clone https://github.com/oremanj/python-netfilterqueue
     cd python-netfilterqueue
     pip3 install .
     ```
   - (Optional) Use a Virtual Environment: If you hit permission issues or prefer isolation, create and activate a venv before installing:
    
       ```bash
       python3 -m venv .venv
       source .venv/bin/activate
       pip3 install scapy netfilterqueue numpy
       ```

2. **Queue Conflict**
   - If "Failed to create queue" error appears:
     ```
     sudo rm /run/xtables.lock  # Clear stale lock
     sudo pkill -f NFQUEUE      # Kill existing queue users
     ```

3. **Missing Traffic**
   - Confirm ARP spoofing is active and successful
   - Verify target IP and port are correct
   - Check iptables rules: `sudo iptables -L FORWARD -v`

4. **No Effect on Target**
   - Ensure target is using the expected protocol
   - Check if target validates input values
   - Try different frequency pattern with larger magnitude

### Operational Notes

1. **Attack flow**:
   - ARP spoofing redirects traffic through attacker
   - FDIA intercepts specific packets
   - Payload values modified according to pattern
   - Modified packets forwarded to destination

2. This attack specifically targets register 101 with frequency values, but can be modified for other industrial protocols and parameters.

3. Always restore network state after testing by properly terminating both the ARP spoofing and FDIA scripts with Ctrl+C.

## ModBus Replay Attack

A network manipulation tool for capturing and replaying industrial control system values through TCP/ModBus protocol. Enables security testing of industrial control systems by demonstrating real-time data injection vulnerabilities.

### Current Impementation
- **Dual Operation Modes**
  - **Capture Mode**: Record live frequency values to CSV
  - **Replay Mode**: Inject stored values into network traffic
-  Automatic iptables rule management
-  Packet modification with checksum recalculation
-  Debug mode for operation verification
-  Mechanisms for value range constraints (0-65535)

### Usage

1. **Install dependencies**:`pip3 install scapy netfilterqueue numpy`

2. **Start ARP spoofing in a separate terminal**:`sudo python3 arp_spoof.py 192.168.1.15 192.168.1.23 -i eth0 -r 5`

3. **Value Capture/Modification**
   
```sudo python3 replay_tool.py 192.168.1.100 -s -o freqlog.csv # Capture```

``` sudo python3 replay_tool.py 192.168.1.100 -a -r freqlog.csv # Replay```

### Operational Modes
| Mode | Description | Command Example |
|------|-------------|-----------------|
| Capture | Record frequency values | `sudo python3 replay_tool.py 192.168.1.100 -s -o freqlog.csv` |
| Replay | Inject stored values | `sudo python3 replay_tool.py 192.168.1.100 -a -r freqlog.csv` |

### Command Options
| Option | Description | Default |
|--------|-------------|---------|
| `-p/--port` | Target port | 30502 |
| `-s/--store` | Enable capture mode | False |
| `-o/--output` | Capture output file | captured_freq.csv |
| `-a/--attack` | Enable replay mode | False |
| `-r/--read` | Replay input file | captured_freq.csv |
| `-d/--debug` | Enable debug mode | False |

### Implementation Details
- Targets Modbus TCP register 101 (2-byte frequency values)
- Operates at network layer using NetfilterQueue (queue 1)
- Packet structure requirements:
  - Raw payload present
  - First register == 101
  - Payload length > 100 bytes
- Automatic cleanup of network rules on exit

### Troubleshooting

1. **NetfilterQueue Binding Errors**
   - Verify no other applications are using queue 1
   - Run: `sudo pkill -f NFQUEUE` to clear existing queue bindings
   - Install required dependencies:
     ```
     sudo apt-get install build-essential python3-dev libnetfilter-queue-dev libnfnetlink-dev
     sudo apt install libnfnetlink-dev libnetfilter-queue-dev
     pip3 install nfqp3
     pip3 install cython
     git clone https://github.com/oremanj/python-netfilterqueue
     cd python-netfilterqueue
     pip3 install .
     ```

2. **Queue Conflict**
   - If "Failed to create queue" error appears:
     ```
     sudo rm /run/xtables.lock  # Clear stale lock
     sudo pkill -f NFQUEUE      # Kill existing queue users
     ```

3. **Missing Traffic**
   - Confirm ARP spoofing is active and successful
   - Verify target IP and port are correct
   - Check iptables rules: `sudo iptables -L FORWARD -v`

4. **No Effect on Target**
   - Ensure target is using the expected protocol
   - Check if target validates input values
   - Try different frequency pattern with larger magnitude




## TCP Flag Injection

A network reconnaissance and evasion script that injects **non-standard TCP flag combinations** using Nmap’s raw packet crafting capabilities. This technique is commonly used in OS fingerprinting, IDS/IPS evasion, and low-and-slow scanning.

TCP flags (e.g., NULL or Xmas scans) are injected into the network to analyze how the target responds, which can reveal operating system details or firewall behavior.
Malformed packets may be used to confuse stateful packet inspectors or to disrupt established connections (for example, using a combination like FIN+RST to force unusual session termination).

Classification rational: The unusual TCP flag combinations —by their nature of being intentionally malformed or contradictory—are used as a form of packet injection. This injection is aimed at eliciting abnormal behaviors from the target’s network stack or security devices, rather than overwhelming them with traffic (flooding) or pretending to be someone else (impersonation).

### Key Features

- Accepts **integer flag values** (bitmask-based, e.g., 18 = SYN+ACK)
- Converts numeric flag value to **readable flag names**
- Supports **full-port scans** or single-port scans
- Generates and executes corresponding **Nmap scan with `--scanflags`**
- Provides optional **debug output** for visibility

### TCP Flag Codes

| Flag | Value |
|------|-------|
| FIN  | 1     |
| SYN  | 2     |
| RST  | 4     |
| PSH  | 8     |
| ACK  | 16    |
| URG  | 32    |

Example:  
To inject SYN+ACK, use value `18` (2 + 16)


### Usage

```
sudo python3 tcp_flag_injection.py <TARGET_IP> -f <FLAG_VALUE> [-p <PORT>] [-d]
```

#### Parameters

| Parameter | Description | Default |
|----------|-------------|---------|
| `<TARGET_IP>` | Target IP address | *Required* |
| `-f` / `--flag` | TCP flag value (0–63) | *Required* |
| `-p` / `--port` | Target port (or -1 for all ports) | `-1` |
| `-d` / `--debug` | Enable debug output | `False` |


### Examples

1. **Inject SYN flag (2) across all ports**:
```
sudo python3 tcp_flag_injection.py 192.168.1.45 -f 2
```

2. **Inject SYN+ACK (18) on port 22**:
```
sudo python3 tcp_flag_injection.py 192.168.1.45 -f 18 -p 22
```

3. **Full stealth scan with URG+PSH+FIN (41)**:
```
sudo python3 tcp_flag_injection.py 192.168.1.45 -f 41 -p 443 -d
```


### Troubleshooting

1. **"Invalid port value" error?**
   - Ensure port is between 0 and 65535 or set to `-1`.

2. **"Invalid flag value"?**
   - Use values between `0` and `63` (bitwise sum of flags above).

3. **No response in output?**
   - Confirm the target allows custom flag scans
   - Try adding `-Pn` to the command manually if host discovery fails

4. **Nmap permission issues?**
   - Always run with `sudo`, as raw socket operations require root